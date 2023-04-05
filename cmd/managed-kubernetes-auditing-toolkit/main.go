package main

import (
	"github.com/datadog/managed-k8s-auditing-toolkit/cmd/managed-kubernetes-auditing-toolkit/eks"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var rootCmd = &cobra.Command{
	Use:                   "mkat",
	DisableFlagsInUseLine: true,
}

func init() {
	rootCmd.AddCommand(eks.BuildEksSubcommand())
	rootCmd.AddCommand(&cobra.Command{
		Use: "autogen-docs",
		Run: func(cmd *cobra.Command, args []string) {
			doc.GenMarkdownTree(rootCmd, "./docs")
		},
	})
}

func main() {
	rootCmd.Execute()
}
