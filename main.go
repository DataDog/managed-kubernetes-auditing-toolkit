package main

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	"os"
	"path/filepath"
)

/**
 * We'll have to make a decision: do we want to show _effective_ permissions, or _how_ a specific workload is getting permissions?
 */
func main() {
	targetCluster := os.Args[1]
	resolver := EKSClusterRolesResolver{k8sClient: K8sClient(), awsClient: AWSClient()}
	cluster, err := resolver.ResolveClusterRoles(targetCluster)
	if err != nil {
		panic(err)
	}

	for namespace, pods := range cluster.PodsByNamespace {
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			println("Pod " + namespace + "/" + pod.Name + " using service account " + pod.ServiceAccount.Name + " can assume role " + pod.ServiceAccount.AssumableRoles[0].Arn)
		}
	}

	g := graph.New(graph.StringHash, graph.Directed(), graph.Acyclic())
	for namespace, pods := range cluster.PodsByNamespace {
		for _, pod := range pods {
			if pod.ServiceAccount == nil || len(pod.ServiceAccount.AssumableRoles) == 0 {
				continue
			}
			role := pod.ServiceAccount.AssumableRoles[0]
			parsedArn, _ := arn.Parse(role.Arn)
			roleLabel := fmt.Sprintf("IAM Role %s", parsedArn.Resource)
			serviceAccountLabel := fmt.Sprintf("Service account %s/%s", namespace, pod.ServiceAccount.Name)
			podLabel := fmt.Sprintf("Pod %s/%s", namespace, pod.Name)

			g.AddVertex(
				roleLabel,
				graph.VertexAttribute("style", "filled"),
				graph.VertexAttribute("shape", "box"),
				graph.VertexAttribute("fillcolor", "#BFEFFF"),
			)
			g.AddVertex(serviceAccountLabel,
				graph.VertexAttribute("shape", "box"),
			)
			g.AddVertex(podLabel,
				graph.VertexAttribute("shape", "box"),
			)
			g.AddEdge(
				podLabel, serviceAccountLabel,
				//graph.EdgeAttribute("label", "runs under"),
				//graph.EdgeAttribute("rank", "same"),
			)
			g.AddEdge(
				serviceAccountLabel, roleLabel,
				graph.EdgeAttribute("label", "can assume"),
			)
		}
	}

	file, _ := os.Create("/tmp/mygraph.gv")
	_ = draw.DOT(g, file)

}

func roleCanBeAssumedByServiceAccount(role IAMRole, serviceAccount *K8sServiceAccount, cluster *EKSCluster) bool {
	var policy map[string]interface{}
	err := json.Unmarshal([]byte(role.TrustPolicy), &policy)
	if err != nil {
		panic(err)
	}

	issuerId := cluster.IssuerURL[len("https://"):]
	for _, rawStatement := range policy["Statement"].([]interface{}) {
		statement := rawStatement.(map[string]interface{})
		if statement["Effect"] != "Allow" {
			continue
		}

		rawCondition, hasCondition := statement["Condition"]
		if !hasCondition {
			return true
		}

		condition := rawCondition.(map[string]interface{})
		//TODO: use stringlike
		if stringEquals, ok := condition["StringEquals"]; ok {
			subjectCondition := stringEquals.(map[string]interface{})[issuerId+":sub"]
			if subjectCondition == nil {
				continue
			}
			effectiveSubject := "system:serviceaccount:" + serviceAccount.Namespace + ":" + serviceAccount.Name
			if match, err := filepath.Match(subjectCondition.(string), effectiveSubject); match && err == nil {
				return true
			}
		}
	}
	return false
}
