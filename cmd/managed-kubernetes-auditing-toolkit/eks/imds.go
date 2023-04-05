package eks

import (
	"github.com/datadog/managed-k8s-auditing-toolkit/internal/utils"
	"github.com/datadog/managed-k8s-auditing-toolkit/pkg/managed-kubernetes-auditing-toolkit/eks/imds"
	"github.com/spf13/cobra"
)

func buildTestImdsAccessCommand() *cobra.Command {
	eksFindSecretsCommand := &cobra.Command{
		Use:                   "test-imds-access",
		Example:               "mkat eks test-imds-access",
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
		println("IMDS is accessible and allows any pod to retrieve credentials for the AWS role " + result.NodeRoleName)
	} else {
		println("IMDS is not accessible in your cluster")
	}
	return nil
}
