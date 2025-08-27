// Package cmd provides the CLI interface using Cobra commands.
package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd is the base command for the CLI application.
var rootCmd = &cobra.Command{
	Use:     "bugscanx-go",
	Long:    "A bugscanner-go fork.",
	Example: "  bugscanx-go direct -f hosts.txt -o save.txt\n  bugscanx-go ping -f hosts.txt\n  bugscanx-go sni -f domains.txt\n  bugscanx-go proxy --proxy-cidr 192.168.1.0/24 --target example.com\n  bugscanx-go cdn-ssl --proxy-host proxy.txt --target sslsite.com",
}

// globalFlagThreads sets the number of concurrent threads for scanning.
var globalFlagThreads int

// Execute runs the root command and handles errors.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

// init sets up the root command with global flags and configuration.
func init() {
	// Configure global thread flag with default value of 64
	rootCmd.PersistentFlags().IntVarP(&globalFlagThreads, "threads", "t", 64, "total threads to use")

	// Disable default completion command to keep CLI clean
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Hide the default help command to provide custom help behavior
	rootCmd.SetHelpCommand(&cobra.Command{Use: "no-help", Hidden: true})
}
