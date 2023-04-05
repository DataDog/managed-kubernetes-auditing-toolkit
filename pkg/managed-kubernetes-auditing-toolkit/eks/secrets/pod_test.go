package secrets

import (
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	"testing"
)

func makeContainerEnv(env map[string]string) []v1.EnvVar {
	var containerEnv = make([]v1.EnvVar, 0, len(env))
	for key, value := range env {
		containerEnv = append(containerEnv, v1.EnvVar{Name: key, Value: value})
	}
	return containerEnv
}

func podWithEnvironmentVariables(env map[string]string) *v1.Pod {
	return &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{Env: makeContainerEnv(env)}}}}
}

func podWithEnvironmentVariablesInInitContainer(env map[string]string) *v1.Pod {
	return &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{{Name: "foo"}}, InitContainers: []v1.Container{{Name: "bar", Env: makeContainerEnv(env)}}}}
}

func TestDetectsSecretsInPods(t *testing.T) {
	scenarios := []struct {
		Name             string
		Pod              *v1.Pod
		ShouldFindSecret bool
		MatchedSecrets   []string
	}{
		{
			Name:             "no environment variables",
			Pod:              podWithEnvironmentVariables(map[string]string{}),
			ShouldFindSecret: false,
		},
		{
			Name:             "no secrets",
			Pod:              podWithEnvironmentVariables(map[string]string{"foo": "bar"}),
			ShouldFindSecret: false,
		},
		{
			Name: "something that looks like an AWS secret key but is within a longer string",
			Pod: podWithEnvironmentVariables(map[string]string{
				"my_id":     "AKIAZ3MSJV4WWNKWW5FG",
				"my_string": "XXXHP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XFXXX",
			}),
			ShouldFindSecret: false,
		},
		{
			Name: "only something that looks like an AWS secret key but without an access key",
			Pod: podWithEnvironmentVariables(map[string]string{
				"foo": "HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF",
			}),
			ShouldFindSecret: false,
		},
		{
			Name: "only something that looks like an AWS access key but without an secret key",
			Pod: podWithEnvironmentVariables(map[string]string{
				"foo": "AKIAZ3MSJV4WWNKWW5FG",
			}),
			ShouldFindSecret: false,
		},
		{
			Name: "an access key and a secret key",
			Pod: podWithEnvironmentVariables(map[string]string{
				"access": "AKIAZ3MSJV4WWNKWW5FG",
				"secret": "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",
			}),
			ShouldFindSecret: true,
			MatchedSecrets: []string{
				"AKIAZ3MSJV4WWNKWW5FG",
				"HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF",
			},
		},
		{
			Name: "two containers with pieces of credentials should not match",
			Pod: &v1.Pod{Spec: v1.PodSpec{Containers: []v1.Container{
				{Env: makeContainerEnv(map[string]string{"access": "AKIAZ3MSJV4WWNKWW5FG"})},
				{Env: makeContainerEnv(map[string]string{"secret": "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"})},
			}}},
			ShouldFindSecret: false,
		},
		{
			Name: "an access key and a secret key in an init container",
			Pod: podWithEnvironmentVariablesInInitContainer(map[string]string{
				"access": "AKIAZ3MSJV4WWNKWW5FG",
				"secret": "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",
			}),
			ShouldFindSecret: true,
			MatchedSecrets: []string{
				"AKIAZ3MSJV4WWNKWW5FG",
				"HP8lBRs8X50F/0nCAXqEPQ95+jlG/0pLdlNui2XF",
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := findSecretsInSinglePodDefinition(scenario.Pod)
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
