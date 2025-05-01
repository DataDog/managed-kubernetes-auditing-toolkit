package eks

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/awalterschulze/gographviz"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/internal/utils"
	"github.com/datadog/managed-kubernetes-auditing-toolkit/pkg/managed-kubernetes-auditing-toolkit/eks/role_relationships"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
	"golang.org/x/term"
)

// Command-line arguments
var outputFormat string
var outputFile string
var eksClusterName string
var showFullRoleArns bool

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
		Example:               "mkat eks find-role-relationships",
		Short:                 "Find relationships between your EKS service accounts and IAM roles",
		Long:                  "Analyzes your EKS cluster and finds all service accounts that can assume AWS roles, based on their trust policies ",
		DisableFlagsInUseLine: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if !slices.Contains(availableOutputFormats, outputFormat) {
				return fmt.Errorf("invalid output format %s", outputFormat)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cluster := utils.GetEKSClusterName()
			if cluster == "" {
				// If we cannot determine the EKS cluster name automatically, give the user a chance to specify it on the CLI
				cluster = eksClusterName
			}
			if cluster == "" {
				return errors.New("unable to determine your current EKS cluster name. Try specifying it explicitely with the --eks-cluster-name flag")
			}
			return doFindRoleRelationshipsCommand(cluster)
		},
	}

	eksRoleRelationshipsCommand.Flags().StringVarP(&outputFormat, "output-format", "f", DefaultOutputFormat, "Output format. Supported formats: "+strings.Join(availableOutputFormats, ", "))
	eksRoleRelationshipsCommand.Flags().StringVarP(&outputFile, "output-file", "o", "", "Output file. If not specified, output will be printed to stdout.")
	eksRoleRelationshipsCommand.Flags().StringVarP(&eksClusterName, "eks-cluster-name", "", "", "When the EKS cluster name cannot be automatically detected from your KubeConfig, specify this argument to pass the EKS cluster name of your current kubectl context")
	eksRoleRelationshipsCommand.Flags().BoolVarP(&showFullRoleArns, "show-full-role-arns", "", false, "Show full ARNs of roles instead of just the role name")
	return eksRoleRelationshipsCommand
}

// Actual logic implementing the "find-role-relationships" command
func doFindRoleRelationshipsCommand(targetCluster string) error {
	resolver := role_relationships.EKSCluster{
		K8sClient: utils.K8sClient(),
		AwsClient: utils.AWSClient(),
		Name:      targetCluster,
	}
	err := resolver.AnalyzeRoleRelationships()
	if err != nil {
		log.Fatalf("unable to analyze cluster role relationships: %v", err)
	}

	output, err := getOutput(&resolver)
	if err != nil {
		return err
	}
	if outputFile != "" {
		log.Println("Writing " + strings.ToUpper(outputFormat) + " output to " + outputFile)
		return os.WriteFile(outputFile, []byte(output), 0644)
	}

	print(output)
	return nil
}

func getOutput(resolver *role_relationships.EKSCluster) (string, error) {
	switch outputFormat {
	case TextOutputFormat:
		return getTextOutput(resolver)
	case DotOutputFormat:
		return getDotOutput(resolver)
	case CsvOutputFormat:
		return getCsvOutput(resolver)
	default:
		return "", fmt.Errorf("unsupported output format %s", outputFormat)
	}
}

func getTextOutput(resolver *role_relationships.EKSCluster) (string, error) {
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
		{Number: 3, AutoMerge: true, VAlign: text.VAlignMiddle},
	})
	t.AppendHeader(table.Row{"Namespace", "Service Account", "Pod", "Assumable Role", "Mechanism"})
	var found = false
	for namespace, pods := range resolver.PodsByNamespace {
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			for _, role := range pod.ServiceAccount.AssumableRoles {
				t.AppendRow([]interface{}{namespace, pod.ServiceAccount.Name, pod.Name, getRoleDisplayName(role.IAMRole), role.Reason})
				found = true
			}
		}
		t.AppendSeparator()
	}
	if !found {
		return "No service accounts found that can assume AWS roles", nil
	}
	return t.Render(), nil
}

type Vertex struct {
	ID    int
	Label string
}

func (v *Vertex) GetID() int {
	return v.ID
}

func getDotOutput(resolver *role_relationships.EKSCluster) (string, error) {
	graphAst, _ := gographviz.ParseString(`digraph G { }`)
	graphViz := gographviz.NewGraph()
	gographviz.Analyse(graphAst, graphViz)
	graphViz.AddAttr("G", "rankdir", "LR")
	graphViz.AddAttr("G", "splines", "polyline")
	graphViz.AddAttr("G", "ranksep", "1.2")
	graphViz.AddAttr("G", "nodesep", "0.8")
	graphViz.AddAttr("G", "outputorder", "edgesfirst")
	graphViz.AddAttr("G", "overlap", "false")
	graphViz.AddAttr("G", "newrank", "true")

	for namespace, pods := range resolver.PodsByNamespace {
		subgraph := fmt.Sprintf(` "cluster_%s" `, namespace)
		graphViz.AddSubGraph("G", subgraph, map[string]string{
			"rank":  "same",
			"label": fmt.Sprintf(`"%s"`, namespace),
			"color": "lightgrey",
			"style": "rounded",
		})
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			podLabel := fmt.Sprintf(` "Pod %s" `, pod.Name)
			graphViz.AddNode(subgraph, podLabel, map[string]string{
				"fontname":  "Helvetica",
				"shape":     "box",
				"style":     "filled",
				"fillcolor": "lightgrey",
				"fontsize":  "12",
			})
			for _, role := range pod.ServiceAccount.AssumableRoles {
				roleLabel := fmt.Sprintf(`"IAM role %s"`, getRoleName(role.IAMRole))
				graphViz.AddNode("G", roleLabel, map[string]string{
					"fontname":  "Helvetica",
					"shape":     "box",
					"style":     "filled",
					"fillcolor": `"#BFEFFF"`,
					"fontsize":  "12",
				})
				graphViz.AddEdge(podLabel, roleLabel, true, map[string]string{
					"fontname": "Helvetica",
					"color":    "black",
					"penwidth": "1",
					"fontsize": "10",
					"weight":   "2.0",
				})
			}
		}
	}

	return graphViz.String(), nil
}

func getCsvOutput(resolver *role_relationships.EKSCluster) (string, error) {
	sb := new(strings.Builder)
	sb.WriteString("namespace,pod,service_account,role_arn,reason")
	for namespace, pods := range resolver.PodsByNamespace {
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			for _, role := range pod.ServiceAccount.AssumableRoles {
				sb.WriteString(fmt.Sprintf(
					"%s,%s,%s,%s,%s",
					namespace,
					pod.Name,
					pod.ServiceAccount.Name,
					getRoleDisplayName(role.IAMRole),
					role.Reason,
				))
				sb.WriteRune('\n')
			}
		}
	}

	return sb.String(), nil
}

func getRoleDisplayName(role *role_relationships.IAMRole) string {
	if showFullRoleArns {
		return role.Arn
	}
	return getRoleName(role)
}

func getRoleName(role *role_relationships.IAMRole) string {
	parsedArn, _ := arn.Parse(role.Arn)
	return strings.TrimPrefix(parsedArn.Resource, "role/")
}
