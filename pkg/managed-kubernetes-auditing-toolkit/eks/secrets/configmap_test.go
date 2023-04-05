package secrets

import (
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	"testing"
)

func TestDetectsSecretsInConfigMaps(t *testing.T) {
	scenarios := []struct {
		Name             string
		ConfigMap        *v1.ConfigMap
		ShouldFindSecret bool
		MatchedSecrets   []string
	}{
		{
			Name:             "no secrets",
			ConfigMap:        &v1.ConfigMap{Data: map[string]string{"foo": "bar"}},
			ShouldFindSecret: false,
		},
		{
			Name: "something that looks like an AWS secret key but is within a longer string",
			ConfigMap: &v1.ConfigMap{Data: map[string]string{
				"access_key": "AKIAZ3MSJV4WWNKWW5FG",
				"foo":        "XXXHP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XFXXX",
			}},
			ShouldFindSecret: false,
		},
		{
			Name: "only something that looks like an AWS secret key but without an access key",
			ConfigMap: &v1.ConfigMap{Data: map[string]string{
				"foo": "HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF",
			}},
			ShouldFindSecret: false,
		},
		{
			Name: "only something that looks like an AWS access key but without a secret key",
			ConfigMap: &v1.ConfigMap{Data: map[string]string{
				"foo": "AKIAZ3MSJV4WWNKWW5FG",
			}},
			ShouldFindSecret: false,
		},
		{
			Name: "an access key and a secret key",
			ConfigMap: &v1.ConfigMap{Data: map[string]string{
				"access_key": "AKIAZ3MSJV4WWNKWW5FG",
				"secret_key": "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",
			}},
			ShouldFindSecret: true,
			MatchedSecrets: []string{
				"AKIAZ3MSJV4WWNKWW5FG",
				"HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF",
			},
		},
		{
			Name: "2 access keys and secret keys",
			ConfigMap: &v1.ConfigMap{Data: map[string]string{
				"access_key1": "AKIAZ3MSJV4WWNKWW5FG",
				"secret_key1": "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",
				"access_key2": "AKIAZ3MSJV4WWNKWW5FH",
				"secret_key2": "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",
			}},
			ShouldFindSecret: true,
			MatchedSecrets: []string{
				"AKIAZ3MSJV4WWNKWW5FG",
				"HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF",
				"AKIAZ3MSJV4WWNKWW5FH",
				"HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XG",
			},
		},
		{
			Name: "an access key and a secret key in config-like string",
			ConfigMap: &v1.ConfigMap{Data: map[string]string{
				"my_config": `
access_key = AKIAZ3MSJV4WWNKWW5FG
secret_key = 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
`,
			}},
			ShouldFindSecret: true,
			MatchedSecrets: []string{
				"AKIAZ3MSJV4WWNKWW5FG",
				"HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF",
			},
		},
		{
			Name: "an access key and a secret key in JSON string",
			ConfigMap: &v1.ConfigMap{Data: map[string]string{
				"my_config": `
{
	"myapp": {
		"access_key": "AKIAZ3MSJV4WWNKWW5FG",
		"secret_key": "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"
	}
}
`,
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
			result := findSecretsInSingleConfigMap(scenario.ConfigMap)
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
