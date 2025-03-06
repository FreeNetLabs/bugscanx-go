package main

import (
	"github.com/Ayanrajpoot10/bugscanx-go/cmd"
	"github.com/Ayanrajpoot10/bugscanx-go/pkg/ui"
)

func main() {
	ui.PrintBanner()
	cmd.Execute()
}
