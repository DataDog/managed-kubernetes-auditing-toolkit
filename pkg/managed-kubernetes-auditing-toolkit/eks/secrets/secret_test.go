package secrets

import (
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	"testing"
)

func TestDetectsSecretsInK8sSecrets(t *testing.T) {
	scenarios := []struct {
		Name             string
		K8sSecret        *v1.Secret
		ShouldFindSecret bool
		MatchedSecrets   []string
	}{
		{
			Name:             "no secrets",
			K8sSecret:        &v1.Secret{Data: map[string][]byte{"foo": []byte("bar")}},
			ShouldFindSecret: false,
		},
		{
			Name: "something that looks like an AWS secret key but is within a longer string",
			K8sSecret: &v1.Secret{Data: map[string][]byte{
				"access_key": []byte("AKIAZ3MSJV4WWNKWW5FG"),
				"foo":        []byte("XXXHP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XFXXX"),
			}},
			ShouldFindSecret: false,
		},
		{
			Name: "only something that looks like an AWS secret key but without an access key",
			K8sSecret: &v1.Secret{Data: map[string][]byte{
				"foo": []byte("HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF"),
			}},
			ShouldFindSecret: false,
		},
		{
			Name: "only something that looks like an AWS access key but without a secret key",
			K8sSecret: &v1.Secret{Data: map[string][]byte{
				"foo": []byte("AKIAZ3MSJV4WWNKWW5FG"),
			}},
			ShouldFindSecret: false,
		},
		{
			Name: "an access key and a secret key",
			K8sSecret: &v1.Secret{Data: map[string][]byte{
				"access_key": []byte("AKIAZ3MSJV4WWNKWW5FG"),
				"secret_key": []byte("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"),
			}},
			ShouldFindSecret: true,
			MatchedSecrets: []string{
				"AKIAZ3MSJV4WWNKWW5FG",
				"HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF",
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := findSecretsInSingleSecret(scenario.K8sSecret)
			if scenario.ShouldFindSecret && len(result) == 0 {
				t.Errorf("expected to find secrets, but found none")
			}
			if !scenario.ShouldFindSecret && len(result) > 0 {
				t.Errorf("expected to find no secrets, but found %d", len(result))
			}
			if len(scenario.MatchedSecrets) == 0 {
				return // nothing to check further
			}
			var allFoundSecrets []string
			for _, secret := range result {
				allFoundSecrets = append(allFoundSecrets, secret.Value)
			}
			assert.ElementsMatch(t, allFoundSecrets, scenario.MatchedSecrets)
		})
	}
}
