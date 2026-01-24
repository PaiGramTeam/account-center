package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "paigram",
	Short: "Paigram - User Account Center for PaiGram Bot Series",
	Long: `Paigram is a centralized user account center for PaiGram bot series.
It provides user authentication, permission management, and RPC services
for bot applications with JWT authentication.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config/config.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// Config initialization will be handled by each command as needed
}
