package eks

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/datadog/managed-k8s-auditing-toolkit/internal/utils"
	"github.com/datadog/managed-k8s-auditing-toolkit/pkg/managed-kubernetes-auditing-toolkit/eks"
	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"golang.org/x/term"
	"log"
	"os"
	"strings"
)

// Command-line arguments
var outputFormat string
var outputFile string

// Output formats
const (
	CsvOutputFormat  string = "csv"
	TextOutputFormat string = "text"
	DotOutputFormat  string = "dot"
)

var availableOutputFormats = []string{CsvOutputFormat, TextOutputFormat, DotOutputFormat}

const DefaultOutputFormat = TextOutputFormat

func buildEksRoleRelationshipsCommand() *cobra.Command {
	eksRoleRelationshipsCommand := &cobra.Command{
		Use:                   "find-role-relationships",
		Example:               "mkat eks find-role-relationships <eks-cluster-name>",
		DisableFlagsInUseLine: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				cmd.Help()
				os.Exit(1)
			}
			if !slices.Contains(availableOutputFormats, outputFormat) {
				return fmt.Errorf("invalid output format %s", outputFormat)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return doFindRoleRelationshipsCommand(args[0])
		},
	}

	eksRoleRelationshipsCommand.Flags().StringVarP(&outputFormat, "output-format", "f", DefaultOutputFormat, "Output format. Supported formats: "+strings.Join(availableOutputFormats, ", "))
	eksRoleRelationshipsCommand.Flags().StringVarP(&outputFile, "output-file", "o", "", "Output file. If not specified, output will be printed to stdout.")
	return eksRoleRelationshipsCommand
}

// Actual logic implementing the "find-role-relationships" command
func doFindRoleRelationshipsCommand(targetCluster string) error {
	resolver := eks.EKSClusterRolesResolver{K8sClient: utils.K8sClient(), AwsClient: utils.AWSClient()}
	cluster, err := resolver.ResolveClusterRoles(targetCluster)
	if err != nil {
		log.Fatalf("unable to analyze cluster role relationships: %v", err)
	}

	output, err := getOutput(cluster)
	if err != nil {
		return err
	}
	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(output), 0644)
	} else {
		print(output)
	}

	return nil
}

func getOutput(cluster *eks.EKSCluster) (string, error) {
	switch outputFormat {
	case TextOutputFormat:
		return getTextOutput(cluster)
	case DotOutputFormat:
		return getDotOutput(cluster)
	case CsvOutputFormat:
		return getCsvOutput(cluster)
	default:
		return "", fmt.Errorf("unsupported output format %s", outputFormat)
	}
}

func getTextOutput(cluster *eks.EKSCluster) (string, error) {
	t := table.NewWriter()
	if term.IsTerminal(0) {
		width, _, err := term.GetSize(0)
		if err == nil {
			t.SetAllowedRowLength(width)
		}
	}
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true, VAlign: text.VAlignMiddle},
		{Number: 2, AutoMerge: true, VAlign: text.VAlignMiddle},
	})
	t.AppendHeader(table.Row{"Namespace", "Service Account", "Pod", "Assumable Role ARN"})
	for namespace, pods := range cluster.PodsByNamespace {
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			for _, role := range pod.ServiceAccount.AssumableRoles {
				t.AppendRow([]interface{}{namespace, pod.ServiceAccount.Name, pod.Name, role.Arn})
			}
		}
		t.AppendSeparator()
	}

	return t.Render(), nil
}

func getDotOutput(cluster *eks.EKSCluster) (string, error) {
	g := graph.New(graph.StringHash, graph.Directed(), graph.Acyclic())

	for namespace, pods := range cluster.PodsByNamespace {
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			podLabel := fmt.Sprintf("Pod %s/%s", namespace, pod.Name)

			g.AddVertex(podLabel,
				graph.VertexAttribute("shape", "box"),
				graph.VertexAttribute("rank", "same"),
			)
		}
	}

	for namespace, pods := range cluster.PodsByNamespace {
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			podLabel := fmt.Sprintf("Pod %s/%s", namespace, pod.Name)
			for _, role := range pod.ServiceAccount.AssumableRoles {
				parsedArn, _ := arn.Parse(role.Arn)
				roleLabel := fmt.Sprintf("IAM Role %s", parsedArn.Resource)

				g.AddVertex(
					roleLabel,
					graph.VertexAttribute("style", "filled"),
					graph.VertexAttribute("shape", "box"),
					graph.VertexAttribute("fillcolor", "#BFEFFF"),
					graph.VertexAttribute("rank", "max"),
				)

				g.AddEdge(
					podLabel, roleLabel,
					graph.EdgeAttribute("label", "can assume"),
				)
			}
		}
	}

	sb := new(strings.Builder)
	if err := draw.DOT(g, sb); err != nil {
		return "", err
	}

	return sb.String(), nil
}

func getCsvOutput(cluster *eks.EKSCluster) (string, error) {
	sb := new(strings.Builder)
	sb.WriteString("namespace,pod,service_account,role_arn")
	for namespace, pods := range cluster.PodsByNamespace {
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			for _, role := range pod.ServiceAccount.AssumableRoles {
				sb.WriteString(fmt.Sprintf(
					"%s,%s,%s,%s",
					namespace,
					pod.Name,
					pod.ServiceAccount.Name,
					role.Arn,
				))
				sb.WriteRune('\n')
			}
		}
	}

	return sb.String(), nil
}
