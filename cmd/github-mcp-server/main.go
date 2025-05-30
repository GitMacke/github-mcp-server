package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/github/github-mcp-server/internal/ghmcp"
	"github.com/github/github-mcp-server/pkg/github"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// These variables are set by the build process using ldflags.
var version = "version"
var commit = "commit"
var date = "date"

var (
	rootCmd = &cobra.Command{
		Use:     "server",
		Short:   "GitHub MCP Server",
		Long:    `A GitHub MCP server that handles various tools and resources.`,
		Version: fmt.Sprintf("Version: %s\nCommit: %s\nBuild Date: %s", version, commit, date),
	}

	stdioCmd = &cobra.Command{
		Use:   "stdio",
		Short: "Start stdio server",
		Long:  `Start a server that communicates via standard input/output streams using JSON-RPC messages.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Validate authentication configuration
			authConfig, err := buildAuthConfig()
			if err != nil {
				return err
			}

			// If you're wondering why we're not using viper.GetStringSlice("toolsets"),
			// it's because viper doesn't handle comma-separated values correctly for env
			// vars when using GetStringSlice.
			// https://github.com/spf13/viper/issues/380
			var enabledToolsets []string
			if err := viper.UnmarshalKey("toolsets", &enabledToolsets); err != nil {
				return fmt.Errorf("failed to unmarshal toolsets: %w", err)
			}

			stdioServerConfig := ghmcp.StdioServerConfig{
				Version:              version,
				Host:                 viper.GetString("host"),
				Auth:                 authConfig,
				EnabledToolsets:      enabledToolsets,
				DynamicToolsets:      viper.GetBool("dynamic_toolsets"),
				ReadOnly:             viper.GetBool("read-only"),
				ExportTranslations:   viper.GetBool("export-translations"),
				EnableCommandLogging: viper.GetBool("enable-command-logging"),
				LogFilePath:          viper.GetString("log-file"),
			}

			return ghmcp.RunStdioServer(stdioServerConfig)
		},
	}
)

// buildAuthConfig creates an AuthConfig based on environment variables and flags
func buildAuthConfig() (ghmcp.AuthConfig, error) {
	var authConfig ghmcp.AuthConfig

	// Check for Personal Access Token
	token := viper.GetString("personal_access_token")

	// Check for GitHub App credentials
	appID := viper.GetString("app_id")
	installationID := viper.GetString("installation_id")
	privateKeyPath := viper.GetString("private_key_path")
	privateKeyPEM := viper.GetString("private_key_pem")

	// Determine authentication method
	hasToken := token != ""
	hasApp := appID != "" && installationID != "" && (privateKeyPath != "" || privateKeyPEM != "")

	if !hasToken && !hasApp {
		return authConfig, errors.New("authentication required: set GITHUB_PERSONAL_ACCESS_TOKEN or GitHub App credentials (GITHUB_APP_ID, GITHUB_INSTALLATION_ID, and either GITHUB_PRIVATE_KEY_PATH or GITHUB_PRIVATE_KEY_PEM)")
	}

	if hasToken && hasApp {
		return authConfig, errors.New("cannot specify both personal access token and GitHub App authentication")
	}

	if hasToken {
		authConfig.Token = token
	} else {
		authConfig.AppID = appID
		authConfig.InstallationID = installationID
		authConfig.PrivateKeyPath = privateKeyPath
		authConfig.PrivateKeyPEM = privateKeyPEM
	}

	return authConfig, nil
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.SetVersionTemplate("{{.Short}}\n{{.Version}}\n")

	// Add global flags that will be shared by all commands
	rootCmd.PersistentFlags().StringSlice("toolsets", github.DefaultTools, "An optional comma separated list of groups of tools to allow, defaults to enabling all")
	rootCmd.PersistentFlags().Bool("dynamic-toolsets", false, "Enable dynamic toolsets")
	rootCmd.PersistentFlags().Bool("read-only", false, "Restrict the server to read-only operations")
	rootCmd.PersistentFlags().String("log-file", "", "Path to log file")
	rootCmd.PersistentFlags().Bool("enable-command-logging", false, "When enabled, the server will log all command requests and responses to the log file")
	rootCmd.PersistentFlags().Bool("export-translations", false, "Save translations to a JSON file")
	rootCmd.PersistentFlags().String("gh-host", "", "Specify the GitHub hostname (for GitHub Enterprise etc.)")

	// Add GitHub App authentication flags
	rootCmd.PersistentFlags().String("app-id", "", "GitHub App ID")
	rootCmd.PersistentFlags().String("installation-id", "", "GitHub App Installation ID")
	rootCmd.PersistentFlags().String("private-key-path", "", "Path to GitHub App private key file")
	rootCmd.PersistentFlags().String("private-key-pem", "", "GitHub App private key PEM content")

	// Bind flags to viper
	_ = viper.BindPFlag("toolsets", rootCmd.PersistentFlags().Lookup("toolsets"))
	_ = viper.BindPFlag("dynamic_toolsets", rootCmd.PersistentFlags().Lookup("dynamic-toolsets"))
	_ = viper.BindPFlag("read-only", rootCmd.PersistentFlags().Lookup("read-only"))
	_ = viper.BindPFlag("log-file", rootCmd.PersistentFlags().Lookup("log-file"))
	_ = viper.BindPFlag("enable-command-logging", rootCmd.PersistentFlags().Lookup("enable-command-logging"))
	_ = viper.BindPFlag("export-translations", rootCmd.PersistentFlags().Lookup("export-translations"))
	_ = viper.BindPFlag("host", rootCmd.PersistentFlags().Lookup("gh-host"))

	// Bind GitHub App flags to viper
	_ = viper.BindPFlag("app_id", rootCmd.PersistentFlags().Lookup("app-id"))
	_ = viper.BindPFlag("installation_id", rootCmd.PersistentFlags().Lookup("installation-id"))
	_ = viper.BindPFlag("private_key_path", rootCmd.PersistentFlags().Lookup("private-key-path"))
	_ = viper.BindPFlag("private_key_pem", rootCmd.PersistentFlags().Lookup("private-key-pem"))

	// Add subcommands
	rootCmd.AddCommand(stdioCmd)
}

func initConfig() {
	// Initialize Viper configuration
	viper.SetEnvPrefix("github")
	viper.AutomaticEnv()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
