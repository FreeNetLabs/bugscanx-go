package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "bugscanx-go",
	Long:    "A bugscanner-go fork.",
	Example: "  bugscanx-go direct -f hosts.txt -o save.txt\n  bugscanx-go ping -f hosts.txt\n  bugscanx-go sni -f domains.txt\n  bugscanx-go proxy --proxy-cidr 192.168.1.0/24 --target example.com\n  bugscanx-go cdn-ssl --proxy-host proxy.txt --target sslsite.com",
}

var globalFlagThreads int

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&globalFlagThreads, "threads", "t", 64, "total threads to use")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Use: "no-help", Hidden: true})
}
