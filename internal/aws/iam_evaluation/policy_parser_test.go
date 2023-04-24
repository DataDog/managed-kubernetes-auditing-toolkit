package iam_evaluation

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func getTestPolicyFile(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename), "test_policies", name+".json")
	// read file and return contents
	btes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(btes)
}

func TestPolicyParser(t *testing.T) {
	scenarios := []struct {
		Name         string
		PolicyFile   string
		ExpectError  bool
		ExpectPolicy Policy
	}{
		{
			Name:       "foo",
			PolicyFile: "foo",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			policy, err := ParseRoleTrustPolicy(getTestPolicyFile(scenario.PolicyFile))
			if (err == nil) != scenario.ExpectError {
				t.Errorf("expected error: %v, got: %v", scenario.ExpectError, err)
			}
			// verify if policy deepequals expected
			if !reflect.DeepEqual(*policy, scenario.ExpectPolicy) {
				t.Errorf("expected policy: %v, got: %v", scenario.ExpectPolicy, policy)
			}
		})
	}
}
