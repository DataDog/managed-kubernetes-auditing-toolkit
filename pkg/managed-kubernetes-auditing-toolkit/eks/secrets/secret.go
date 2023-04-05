package secrets

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
)

func findSecretsInSingleSecret(secret *v1.Secret) []*SecretInfo {
	// TODO: The code is very similar to ConfigMaps, we should probably refactor it
	var secrets []*SecretInfo
	var accessKeyInfo *SecretInfo
	var secretKeyInfo *SecretInfo

	for key, value := range secret.Data {
		foundCredentials := FindAwsCredentialsInUnstructuredString(string(value))
		if foundCredentials.AccessKey != "" {
			accessKeyInfo = &SecretInfo{
				Namespace: secret.Namespace,
				Name:      fmt.Sprintf("%s (key %s)", secret.Name, key),
				Type:      "Secret",
				Value:     foundCredentials.AccessKey,
			}
		}
		if foundCredentials.SecretKey != "" {
			secretKeyInfo = &SecretInfo{
				Namespace: secret.Namespace,
				Name:      fmt.Sprintf("%s (key %s)", secret.Name, key),
				Type:      "Secret",
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
	return secrets
}
