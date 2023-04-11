package main

import (
	"github.com/datadog/managed-kubernetes-auditing-toolkit/cmd/managed-kubernetes-auditing-toolkit/eks"
	"github.com/spf13/cobra"
)

// BuildVersion is injected at compilation time
var BuildVersion = ""

var rootCmd = &cobra.Command{
	Use:                   "mkat",
	DisableFlagsInUseLine: true,
	SilenceUsage:          true,
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.AddCommand(eks.BuildEksSubcommand())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Display the current CLI version",
		Run: func(cmd *cobra.Command, args []string) {
			println(BuildVersion)
		},
	})
}

func main() {
	rootCmd.Execute()
}
