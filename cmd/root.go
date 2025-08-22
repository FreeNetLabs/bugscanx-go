// Package cmd provides the command-line interface implementation for bugscanx-go.
//
// This package contains all CLI commands and their implementations using the Cobra
// command framework. It includes scanning commands for different network reconnaissance
// techniques such as direct scanning, proxy scanning, SNI enumeration, and more.
//
// The package follows the standard Cobra pattern with a root command that serves
// as the entry point and subcommands for specific scanning functionalities.
package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
// It serves as the main entry point for the bugscanx-go CLI application and
// provides global configuration options that are inherited by all subcommands.
var rootCmd = &cobra.Command{
	Use:     "bugscanx-go",
	Long:    "A bugscanner-go fork.",
	Example: "  bugscanx-go direct -f hosts.txt -o save.txt\n  bugscanx-go ping -f hosts.txt\n  bugscanx-go sni -f domains.txt\n  bugscanx-go proxy --proxy-cidr 192.168.1.0/24 --target example.com\n  bugscanx-go cdn-ssl --proxy-host proxy.txt --target sslsite.com",
}

// globalFlagThreads defines the number of concurrent threads/goroutines to use
// for scanning operations. This global flag is inherited by all subcommands
// and allows users to control the concurrency level based on their system
// resources and scanning requirements.
var globalFlagThreads int

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
//
// The function initializes and starts the Cobra command execution, handling
// any errors that might occur during command parsing or execution.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

// init initializes the root command configuration and sets up global flags.
// This function is automatically called when the package is imported and
// configures the CLI behavior including flag definitions and help system.
func init() {
	// Configure global thread flag with default value of 64
	rootCmd.PersistentFlags().IntVarP(&globalFlagThreads, "threads", "t", 64, "total threads to use")

	// Disable default completion command to keep CLI clean
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Hide the default help command to provide custom help behavior
	rootCmd.SetHelpCommand(&cobra.Command{Use: "no-help", Hidden: true})
}
