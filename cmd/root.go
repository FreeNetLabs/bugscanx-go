package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:  "bugscanx-go",
	Long: "A bugscanner-go fork.",
}

var (
	globalFlagThreads	    int
	globalFlagPrintInterval float64
)

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&globalFlagThreads, "threads", "t", 64, "total threads to use")
	rootCmd.PersistentFlags().Float64Var(&globalFlagPrintInterval, "print-interval", 1.0, "progress print interval in seconds")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
}
