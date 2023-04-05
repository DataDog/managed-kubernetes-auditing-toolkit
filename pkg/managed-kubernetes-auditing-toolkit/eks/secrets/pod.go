package secrets

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
)

func findSecretsInSinglePodDefinition(pod *v1.Pod) []*SecretInfo {
	var secrets []*SecretInfo
	for _, container := range pod.Spec.Containers {
		var accessKeyInfo *SecretInfo
		var secretKeyInfo *SecretInfo

		for _, env := range container.Env {
			foundCredentials := FindAwsCredentialsInUnstructuredString(env.Value)
			if foundCredentials.AccessKey != "" {
				accessKeyInfo = &SecretInfo{
					Namespace: pod.Namespace,
					Name:      fmt.Sprintf("%s (environment variable %s)", pod.Name, env.Name),
					Type:      "Pod",
					Value:     foundCredentials.AccessKey,
				}
			}
			if foundCredentials.SecretKey != "" {
				secretKeyInfo = &SecretInfo{
					Namespace: pod.Namespace,
					Name:      fmt.Sprintf("%s (environment variable %s)", pod.Name, env.Name),
					Type:      "Pod",
					Value:     foundCredentials.SecretKey,
				}
			}
			if accessKeyInfo != nil && secretKeyInfo != nil {
				secrets = append(secrets, accessKeyInfo, secretKeyInfo)
				// start searching for a new set of credentials
				accessKeyInfo = nil
				secretKeyInfo = nil
			}
		}
	}
	return secrets
}
