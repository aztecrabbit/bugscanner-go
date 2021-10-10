package cmd

import (
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Subcommand for scanning",
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
