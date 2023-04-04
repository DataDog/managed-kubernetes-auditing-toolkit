package main

import (
	"github.com/datadog/managed-k8s-auditing-toolkit/cmd/managed-kubernetes-auditing-toolkit/eks"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:                   "mkat",
	DisableFlagsInUseLine: true,
}

func init() {
	rootCmd.AddCommand(eks.BuildEksSubcommand())
}

func main() {
	rootCmd.Execute()
}
