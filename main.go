package main

import (
	"os"

	"paigram/cmd/paigram/cmd"
)

func main() {
	// If no arguments provided, default to serve command
	if len(os.Args) == 1 {
		os.Args = append(os.Args, "serve")
	}
	cmd.Execute()
}
