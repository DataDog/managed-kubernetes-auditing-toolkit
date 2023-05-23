package eks

import (
	"log"

	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/utils"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/pkg/managed-kubernetes-auditing-toolkit/eks/secrets"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

func buildEksFindSecretsCommand() *cobra.Command {
	eksFindSecretsCommand := &cobra.Command{
		Use:                   "find-secrets",
		Short:                 "Find hardcoded AWS secrets in your EKS cluster",
		Long:                  "find-secret will scan your EKS cluster for hardcoded AWS secrets in pod environment variables, configmaps and secrets",
		Example:               "mkat eks find-secrets",
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doFindSecretsCommand()
		},
	}

	return eksFindSecretsCommand
}

func doFindSecretsCommand() error {
	detector := secrets.SecretsDetector{K8sClient: utils.K8sClient(), AwsClient: utils.AWSClient()}
	secrets, err := detector.FindSecrets()
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		log.Println("No hardcoded AWS secrets found in your AWS cluster")
		return nil
	}

	t := table.NewWriter()
	t.AppendHeader(table.Row{"Namespace", "Type", "Name", "Value"})
	secretColor := color.New(color.BgRed, color.FgWhite, color.Bold)
	for _, secret := range secrets {
		t.AppendRow(table.Row{secret.Namespace, secret.Type, secret.Name, secretColor.Sprintf(secret.Value)})
	}

	println(t.Render())
	return nil
}
