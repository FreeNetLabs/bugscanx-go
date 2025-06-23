package cmd

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "bugscanx-go",
}

var globalFlagThreads int

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&globalFlagThreads, "threads", "t", 64, "total threads to use")
}

var (
	colorB1 = color.New(color.FgHiBlack)
	colorW1 = color.New(color.FgWhite, color.Bold)
	colorG1 = color.New(color.FgGreen, color.Bold)
	colorC1 = color.New(color.FgCyan, color.Bold)
	colorC2 = color.New(color.FgHiCyan)
	colorY1 = color.New(color.FgYellow, color.Bold)
	colorY2 = color.New(color.FgHiYellow)
	colorM1 = color.New(color.FgMagenta, color.Bold)
	colorM2 = color.New(color.FgHiMagenta)
	colorR1 = color.New(color.FgRed, color.Bold)
)

func PrintBanner() {
	colorC1.Print("\nWelcome to BugScanX-Go ")
	colorY1.Print("Made by Ayan Rajpoot ")
	colorM1.Print("Telegram Channel: BugScanX\n")
	println()
}