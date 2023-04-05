package secrets

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
)

func findSecretsInSingleConfigMap(configMap *v1.ConfigMap) []*SecretInfo {
	var secrets []*SecretInfo
	var accessKeyInfo *SecretInfo
	var secretKeyInfo *SecretInfo
	for key, value := range configMap.Data {
		configMapSecrets := FindAwsCredentialsInUnstructuredString(value)
		if configMapSecrets.AccessKey != "" {
			accessKeyInfo = &SecretInfo{
				Namespace: configMap.Namespace,
				Name:      fmt.Sprintf("%s (key %s)", configMap.Name, key),
				Type:      "ConfigMap",
				Value:     configMapSecrets.AccessKey,
			}
		}
		if configMapSecrets.SecretKey != "" {
			secretKeyInfo = &SecretInfo{
				Namespace: configMap.Namespace,
				Name:      fmt.Sprintf("%s (key %s)", configMap.Name, key),
				Type:      "ConfigMap",
				Value:     configMapSecrets.SecretKey,
			}
		}
		if accessKeyInfo != nil && secretKeyInfo != nil {
			secrets = append(secrets, accessKeyInfo, secretKeyInfo)
			// start searching for a new set of credentials
			accessKeyInfo = nil
			secretKeyInfo = nil
		}
	}
	return secrets
}
