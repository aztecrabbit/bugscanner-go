package cmd

import (
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Subcommand for scanning",
}

var scanFlagThreads int

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.PersistentFlags().IntVarP(&scanFlagThreads, "threads", "t", 64, "total threads to use")
}
