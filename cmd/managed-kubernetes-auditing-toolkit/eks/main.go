package eks

import (
	"errors"
	"log"

	"github.com/common-nighthawk/go-figure"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/utils"
	"github.com/spf13/cobra"
)

var ignoreEksHostnameCheck bool

func BuildEksSubcommand() *cobra.Command {
	eksCommand := &cobra.Command{
		Use:   "eks",
		Short: "Commands to audit your EKS cluster",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			figure.NewFigure("mkat", "", true).Print()
			println()
			if !ignoreEksHostnameCheck && !utils.IsEKS() {
				return errors.New("you do not seem to be connected to an EKS cluster. Connect to an EKS cluster and try again")
			}
			clusterName := utils.GetEKSClusterName()
			if clusterName != "" {
				log.Println("Connected to EKS cluster " + clusterName)
			}
			return nil
		},
	}

	eksCommand.PersistentFlags().BoolVarP(&ignoreEksHostnameCheck, "skip-eks-hostname-check", "", false, "Don't check that the hostname of your current API server ends with .eks.amazonaws.com")
	eksCommand.AddCommand(buildEksRoleRelationshipsCommand())
	eksCommand.AddCommand(buildEksFindSecretsCommand())
	eksCommand.AddCommand(buildTestImdsAccessCommand())

	return eksCommand
}
