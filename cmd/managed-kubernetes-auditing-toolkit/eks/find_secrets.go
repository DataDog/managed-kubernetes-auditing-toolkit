package eks

import (
	"github.com/spf13/cobra"
	"os"
)

var availableSearchLocations = []string{
	"configmaps",
	"secrets",
	"pod-definitions",
	"deployments",
}

func buildEksFindSecretsCommand() *cobra.Command {
	eksFindSecretsCommand := &cobra.Command{
		Use:                   "find-secrets",
		Example:               "mkat eks find-secrets <eks-cluster-name>",
		DisableFlagsInUseLine: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Help()
				os.Exit(1)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return doFindSecretsCommand(args[0])
		},
	}

	return eksFindSecretsCommand
}

func doFindSecretsCommand(cluster string) error {
	println("Running")
	return nil
}
