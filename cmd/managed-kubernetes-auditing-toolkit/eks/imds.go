package eks

import (
	"log"
	"sync"

	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/utils"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/pkg/managed-kubernetes-auditing-toolkit/eks/imds"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var successColor = color.New(color.BgBlack, color.FgGreen, color.Bold)
var warningColor = color.New(color.BgRed, color.FgWhite, color.Bold)

func buildTestImdsAccessCommand() *cobra.Command {
	eksFindSecretsCommand := &cobra.Command{
		Use:                   "test-imds-access",
		Example:               "mkat eks test-imds-access",
		Short:                 "Test if your EKS cluster allows pod access to the IMDS",
		Long:                  "test-imds-access will check if your EKS cluster allows pods to access the IMDS by running a pod and executing a curl command hitting the IMDS",
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			doTestImdsAccessCommand()
		},
	}

	return eksFindSecretsCommand
}

func doTestImdsAccessCommand() {
	tester := imds.ImdsTester{K8sClient: utils.K8sClient(), Namespace: "default"}
	log.Println("Testing if IMDSv1 and IMDSv2 are accessible from pods by creating a pod that attempts to access it")

	// We run the test for IMDSv1 and IMDSv2 in parallel
	var wg sync.WaitGroup
	wg.Add(2)
	go doTestImdsAccess(IMDSv1, &tester, &wg)
	go doTestImdsAccess(IMDSv2, &tester, &wg)
	wg.Wait()
}

type ImdsVersion string

const (
	IMDSv1 ImdsVersion = "IMDSv1"
	IMDSv2 ImdsVersion = "IMDSv2"
)

func doTestImdsAccess(imdsVersion ImdsVersion, tester *imds.ImdsTester, wg *sync.WaitGroup) {
	var result *imds.ImdsTestResult
	var err error

	defer wg.Done()

	switch imdsVersion {
	case IMDSv1:
		result, err = tester.TestImdsV1Accessible()
	case IMDSv2:
		result, err = tester.TestImdsV2Accessible()
	default:
		panic("invalid IMDS version")
	}

	if err != nil {
		log.Printf("Unable to determine if %s is accessible in your cluster: %s\n", imdsVersion, err.Error())
		return
	}

	if result.IsImdsAccessible {
		log.Printf("%s: %s\n", warningColor.Sprintf("%s is accessible", imdsVersion), result.ResultDescription)
	} else {
		description := ""
		if result.ResultDescription != "" {
			description = ": " + result.ResultDescription
		}
		log.Printf("%s %s%s\n",
			successColor.Sprintf("%s is not accessible", imdsVersion),
			"to pods in your cluster",
			description,
		)
	}
}
