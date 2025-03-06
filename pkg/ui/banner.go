package ui

import (
	"github.com/fatih/color"
)

const ToolName = "Bugscanx-Go"


func PrintBanner() {
	color.New(color.FgHiCyan, color.Bold).Printf("\nWelcome to %s ", ToolName)
	color.New(color.FgHiYellow, color.Bold).Print("Made by Ayan Rajpoot ")
	color.New(color.FgHiMagenta, color.Bold).Print("Telegram Channel: Bugscanx\n")
}
