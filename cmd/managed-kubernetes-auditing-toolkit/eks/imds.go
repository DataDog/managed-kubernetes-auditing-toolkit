package eks

import (
	"log"

	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/utils"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/pkg/managed-kubernetes-auditing-toolkit/eks/imds"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func buildTestImdsAccessCommand() *cobra.Command {
	eksFindSecretsCommand := &cobra.Command{
		Use:                   "test-imds-access",
		Example:               "mkat eks test-imds-access",
		Short:                 "Test if your EKS cluster allows pod access to the IMDS",
		Long:                  "test-imds-access will check if your EKS cluster allows pods to access the IMDS by running a pod and executing a curl command hitting the IMDS",
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return doTestImdsAccessCommand()
		},
	}

	return eksFindSecretsCommand
}

func doTestImdsAccessCommand() error {
	tester := imds.ImdsTester{K8sClient: utils.K8sClient(), Namespace: "default"}
	result, err := tester.TestImdsAccessible()
	if err != nil {
		return err
	}
	if result.IsImdsAccessible {
		warningColor := color.New(color.BgRed, color.FgWhite, color.Bold)
		log.Println(warningColor.Sprint("IMDS is accessible") + " and allows any pod to retrieve credentials for the AWS role " + result.NodeRoleName)
	} else {
		log.Println("IMDS is not accessible in your cluster")
	}
	return nil
}
