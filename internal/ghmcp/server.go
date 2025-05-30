package ghmcp

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/github/github-mcp-server/pkg/github"
	mcplog "github.com/github/github-mcp-server/pkg/log"
	"github.com/github/github-mcp-server/pkg/translations"
	gogithub "github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/shurcooL/githubv4"
	"github.com/sirupsen/logrus"
)

// AuthConfig represents authentication configuration
type AuthConfig struct {
	// Personal Access Token authentication
	Token string

	// GitHub App authentication
	AppID          string
	InstallationID string
	PrivateKeyPath string
	PrivateKeyPEM  string // Alternative to PrivateKeyPath - raw PEM content
}

type MCPServerConfig struct {
	// Version of the server
	Version string

	// GitHub Host to target for API requests (e.g. github.com or github.enterprise.com)
	Host string

	// Authentication configuration
	Auth AuthConfig

	// EnabledToolsets is a list of toolsets to enable
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#tool-configuration
	EnabledToolsets []string

	// Whether to enable dynamic toolsets
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#dynamic-tool-discovery
	DynamicToolsets bool

	// ReadOnly indicates if we should only offer read-only tools
	ReadOnly bool

	// Translator provides translated text for the server tooling
	Translator translations.TranslationHelperFunc
}

// authMethod represents the authentication method being used
type authMethod int

const (
	authToken authMethod = iota
	authGitHubApp
)

// getAuthMethod determines which authentication method to use based on the config
func (cfg *MCPServerConfig) getAuthMethod() (authMethod, error) {
	hasToken := cfg.Auth.Token != ""
	hasApp := cfg.Auth.AppID != "" && cfg.Auth.InstallationID != "" && 
		(cfg.Auth.PrivateKeyPath != "" || cfg.Auth.PrivateKeyPEM != "")

	if hasToken && hasApp {
		return 0, fmt.Errorf("cannot specify both token and GitHub App authentication")
	}

	if !hasToken && !hasApp {
		return 0, fmt.Errorf("must specify either token or GitHub App authentication")
	}

	if hasToken {
		return authToken, nil
	}

	return authGitHubApp, nil
}

// createGitHubAppTransport creates an authenticated transport for GitHub App
func (cfg *MCPServerConfig) createGitHubAppTransport() (http.RoundTripper, error) {
	appID, err := strconv.ParseInt(cfg.Auth.AppID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid app ID: %w", err)
	}

	installationID, err := strconv.ParseInt(cfg.Auth.InstallationID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid installation ID: %w", err)
	}

	var transport *ghinstallation.Transport

	if cfg.Auth.PrivateKeyPEM != "" {
		// Use PEM content directly
		transport, err = ghinstallation.New(
			http.DefaultTransport,
			appID,
			installationID,
			[]byte(cfg.Auth.PrivateKeyPEM),
		)
	} else {
		// Use private key file
		transport, err = ghinstallation.NewKeyFromFile(
			http.DefaultTransport,
			appID,
			installationID,
			cfg.Auth.PrivateKeyPath,
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub App transport: %w", err)
	}

	return transport, nil
}

func NewMCPServer(cfg MCPServerConfig) (*server.MCPServer, error) {
	apiHost, err := parseAPIHost(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse API host: %w", err)
	}

	authMethod, err := cfg.getAuthMethod()
	if err != nil {
		return nil, fmt.Errorf("authentication configuration error: %w", err)
	}

	// Create HTTP client based on authentication method
	var httpClient *http.Client
	var userAgent string

	switch authMethod {
	case authToken:
		// Use token-based authentication (existing behavior)
		httpClient = &http.Client{
			Transport: &bearerAuthTransport{
				transport: http.DefaultTransport,
				token:     cfg.Auth.Token,
			},
		}
		userAgent = fmt.Sprintf("github-mcp-server/%s", cfg.Version)

	case authGitHubApp:
		// Use GitHub App authentication
		transport, err := cfg.createGitHubAppTransport()
		if err != nil {
			return nil, err
		}

		httpClient = &http.Client{Transport: transport}
		userAgent = fmt.Sprintf("github-mcp-server/%s (GitHub App)", cfg.Version)
	}

	// Construct our REST client
	var restClient *gogithub.Client
	if authMethod == authToken {
		restClient = gogithub.NewClient(nil).WithAuthToken(cfg.Auth.Token)
	} else {
		restClient = gogithub.NewClient(httpClient)
	}
	
	restClient.UserAgent = userAgent
	restClient.BaseURL = apiHost.baseRESTURL
	restClient.UploadURL = apiHost.uploadURL

	// Construct our GraphQL client
	gqlHTTPClient := &http.Client{Transport: httpClient.Transport}
	gqlClient := githubv4.NewEnterpriseClient(apiHost.graphqlURL.String(), gqlHTTPClient)

	// When a client send an initialize request, update the user agent to include the client info.
	beforeInit := func(_ context.Context, _ any, message *mcp.InitializeRequest) {
		var newUserAgent string
		if authMethod == authGitHubApp {
			newUserAgent = fmt.Sprintf(
				"github-mcp-server/%s (%s/%s) (GitHub App)",
				cfg.Version,
				message.Params.ClientInfo.Name,
				message.Params.ClientInfo.Version,
			)
		} else {
			newUserAgent = fmt.Sprintf(
				"github-mcp-server/%s (%s/%s)",
				cfg.Version,
				message.Params.ClientInfo.Name,
				message.Params.ClientInfo.Version,
			)
		}

		restClient.UserAgent = newUserAgent

		gqlHTTPClient.Transport = &userAgentTransport{
			transport: gqlHTTPClient.Transport,
			agent:     newUserAgent,
		}
	}

	hooks := &server.Hooks{
		OnBeforeInitialize: []server.OnBeforeInitializeFunc{beforeInit},
	}

	ghServer := github.NewServer(cfg.Version, server.WithHooks(hooks))

	enabledToolsets := cfg.EnabledToolsets
	if cfg.DynamicToolsets {
		// filter "all" from the enabled toolsets
		enabledToolsets = make([]string, 0, len(cfg.EnabledToolsets))
		for _, toolset := range cfg.EnabledToolsets {
			if toolset != "all" {
				enabledToolsets = append(enabledToolsets, toolset)
			}
		}
	}

	getClient := func(_ context.Context) (*gogithub.Client, error) {
		return restClient, nil // closing over client
	}

	getGQLClient := func(_ context.Context) (*githubv4.Client, error) {
		return gqlClient, nil // closing over client
	}

	// Create default toolsets
	toolsets, err := github.InitToolsets(
		enabledToolsets,
		cfg.ReadOnly,
		getClient,
		getGQLClient,
		cfg.Translator,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize toolsets: %w", err)
	}

	context := github.InitContextToolset(getClient, cfg.Translator)
	github.RegisterResources(ghServer, getClient, cfg.Translator)

	// Register the tools with the server
	toolsets.RegisterTools(ghServer)
	context.RegisterTools(ghServer)

	if cfg.DynamicToolsets {
		dynamic := github.InitDynamicToolset(ghServer, toolsets, cfg.Translator)
		dynamic.RegisterTools(ghServer)
	}

	return ghServer, nil
}

type StdioServerConfig struct {
	// Version of the server
	Version string

	// GitHub Host to target for API requests (e.g. github.com or github.enterprise.com)
	Host string

	// Authentication configuration
	Auth AuthConfig

	// EnabledToolsets is a list of toolsets to enable
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#tool-configuration
	EnabledToolsets []string

	// Whether to enable dynamic toolsets
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#dynamic-tool-discovery
	DynamicToolsets bool

	// ReadOnly indicates if we should only register read-only tools
	ReadOnly bool

	// ExportTranslations indicates if we should export translations
	// See: https://github.com/github/github-mcp-server?tab=readme-ov-file#i18n--overriding-descriptions
	ExportTranslations bool

	// EnableCommandLogging indicates if we should log commands
	EnableCommandLogging bool

	// Path to the log file if not stderr
	LogFilePath string
}

// RunStdioServer is not concurrent safe.
func RunStdioServer(cfg StdioServerConfig) error {
	// Create app context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	t, dumpTranslations := translations.TranslationHelper()

	ghServer, err := NewMCPServer(MCPServerConfig{
		Version:         cfg.Version,
		Host:            cfg.Host,
		Auth:            cfg.Auth,
		EnabledToolsets: cfg.EnabledToolsets,
		DynamicToolsets: cfg.DynamicToolsets,
		ReadOnly:        cfg.ReadOnly,
		Translator:      t,
	})
	if err != nil {
		return fmt.Errorf("failed to create MCP server: %w", err)
	}

	stdioServer := server.NewStdioServer(ghServer)

	logrusLogger := logrus.New()
	if cfg.LogFilePath != "" {
		file, err := os.OpenFile(cfg.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}

		logrusLogger.SetLevel(logrus.DebugLevel)
		logrusLogger.SetOutput(file)
	}
	stdLogger := log.New(logrusLogger.Writer(), "stdioserver", 0)
	stdioServer.SetErrorLogger(stdLogger)

	if cfg.ExportTranslations {
		// Once server is initialized, all translations are loaded
		dumpTranslations()
	}

	// Start listening for messages
	errC := make(chan error, 1)
	go func() {
		in, out := io.Reader(os.Stdin), io.Writer(os.Stdout)

		if cfg.EnableCommandLogging {
			loggedIO := mcplog.NewIOLogger(in, out, logrusLogger)
			in, out = loggedIO, loggedIO
		}

		errC <- stdioServer.Listen(ctx, in, out)
	}()

	// Output github-mcp-server string
	_, _ = fmt.Fprintf(os.Stderr, "GitHub MCP Server running on stdio\n")

	// Wait for shutdown signal
	select {
	case <-ctx.Done():
		logrusLogger.Infof("shutting down server...")
	case err := <-errC:
		if err != nil {
			return fmt.Errorf("error running server: %w", err)
		}
	}

	return nil
}

type apiHost struct {
	baseRESTURL *url.URL
	graphqlURL  *url.URL
	uploadURL   *url.URL
}

func newDotcomHost() (apiHost, error) {
	baseRestURL, err := url.Parse("https://api.github.com/")
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse dotcom REST URL: %w", err)
	}

	gqlURL, err := url.Parse("https://api.github.com/graphql")
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse dotcom GraphQL URL: %w", err)
	}

	uploadURL, err := url.Parse("https://uploads.github.com")
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse dotcom Upload URL: %w", err)
	}

	return apiHost{
		baseRESTURL: baseRestURL,
		graphqlURL:  gqlURL,
		uploadURL:   uploadURL,
	}, nil
}

func newGHECHost(hostname string) (apiHost, error) {
	u, err := url.Parse(hostname)
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC URL: %w", err)
	}

	// Unsecured GHEC would be an error
	if u.Scheme == "http" {
		return apiHost{}, fmt.Errorf("GHEC URL must be HTTPS")
	}

	restURL, err := url.Parse(fmt.Sprintf("https://api.%s/", u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC REST URL: %w", err)
	}

	gqlURL, err := url.Parse(fmt.Sprintf("https://api.%s/graphql", u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC GraphQL URL: %w", err)
	}

	uploadURL, err := url.Parse(fmt.Sprintf("https://uploads.%s", u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHEC Upload URL: %w", err)
	}

	return apiHost{
		baseRESTURL: restURL,
		graphqlURL:  gqlURL,
		uploadURL:   uploadURL,
	}, nil
}

func newGHESHost(hostname string) (apiHost, error) {
	u, err := url.Parse(hostname)
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES URL: %w", err)
	}

	restURL, err := url.Parse(fmt.Sprintf("%s://%s/api/v3/", u.Scheme, u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES REST URL: %w", err)
	}

	gqlURL, err := url.Parse(fmt.Sprintf("%s://%s/api/graphql", u.Scheme, u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES GraphQL URL: %w", err)
	}

	uploadURL, err := url.Parse(fmt.Sprintf("%s://%s/api/uploads/", u.Scheme, u.Hostname()))
	if err != nil {
		return apiHost{}, fmt.Errorf("failed to parse GHES Upload URL: %w", err)
	}

	return apiHost{
		baseRESTURL: restURL,
		graphqlURL:  gqlURL,
		uploadURL:   uploadURL,
	}, nil
}

// Note that this does not handle ports yet, so development environments are out.
func parseAPIHost(s string) (apiHost, error) {
	if s == "" {
		return newDotcomHost()
	}

	u, err := url.Parse(s)
	if err != nil {
		return apiHost{}, fmt.Errorf("could not parse host as URL: %s", s)
	}

	if u.Scheme == "" {
		return apiHost{}, fmt.Errorf("host must have a scheme (http or https): %s", s)
	}

	if strings.HasSuffix(u.Hostname(), "github.com") {
		return newDotcomHost()
	}

	if strings.HasSuffix(u.Hostname(), "ghe.com") {
		return newGHECHost(s)
	}

	return newGHESHost(s)
}

type userAgentTransport struct {
	transport http.RoundTripper
	agent     string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", t.agent)
	return t.transport.RoundTrip(req)
}

type bearerAuthTransport struct {
	transport http.RoundTripper
	token     string
}

func (t *bearerAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}
