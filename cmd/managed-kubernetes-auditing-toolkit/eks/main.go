package eks

import (
	"errors"
	"github.com/common-nighthawk/go-figure"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/utils"
	"github.com/spf13/cobra"
	"log"
)

func BuildEksSubcommand() *cobra.Command {
	eksCommand := &cobra.Command{
		Use:   "eks",
		Short: "Commands to audit your EKS cluster",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			figure.NewFigure("mkat", "", true).Print()
			println()
			if !utils.IsEKS() {
				return errors.New("you do not seem to be connected to an EKS cluster. Connect to an EKS cluster and try again")
			}
			clusterName := utils.GetEKSClusterName()
			if clusterName != "" {
				log.Println("Connected to EKS cluster " + clusterName)
			}
			return nil
		},
	}

	eksCommand.AddCommand(buildEksRoleRelationshipsCommand())
	eksCommand.AddCommand(buildEksFindSecretsCommand())
	eksCommand.AddCommand(buildTestImdsAccessCommand())

	return eksCommand
}
