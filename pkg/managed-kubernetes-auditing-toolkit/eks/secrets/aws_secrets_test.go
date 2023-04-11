package secrets

import "testing"

func TestDetectsAWSAccessKeys(t *testing.T) {
	scenarios := []struct {
		Name        string
		Value       string
		ShouldMatch bool
	}{
		{"should not match a non-AWS access key", "foobar", false},
		{"should match an AWS access key", "AKIAZ3MSJV4WYJDU2ZDX", true},
		{"should match an AWS access key after tokenization", "foo = AKIAZ3MSJV4WYJDU2ZDX", true},
		{"should match an AWS access key after tokenization (json)", `{"foo": "AKIAZ3MSJV4WYJDU2ZDX"}`, true},
		{"should match an AWS access key after tokenization (yaml)", `foo:\n\tbar: AKIAZ3MSJV4WYJDU2ZDX`, true},
		{"should not match something that looks like an AWS access key that's buried in something else", `HELLOAKIAZ3MSJV4WYJDU2ZDXWORLD`, false},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := matchAwsAccessKey(scenario.Value)
			if result == nil && scenario.ShouldMatch {
				t.Errorf("Expected to match AWS access key, but didn't")
			} else if result != nil && !scenario.ShouldMatch {
				t.Errorf("Expected to not match AWS access key, but did")
			}
			// Otherwise, all good
		})
	}
}

func TestDetectsAWSSecretKeys(t *testing.T) {
	scenarios := []struct {
		Name        string
		Value       string
		ShouldMatch bool
	}{
		{"should not match a non-AWS secret key", "foobar", false},
		{"should match an AWS access key", "E7TZzdyO/HQPgp97EzWicL5FsXBHiFEka9HbtK+S", true},
		{"should match an AWS access key after tokenization", "foo = E7TZzdyO/HQPgp97EzWicL5FsXBHiFEka9HbtK+S", true},
		{"should match an AWS access key after tokenization (json)", `{"foo": "E7TZzdyO/HQPgp97EzWicL5FsXBHiFEka9HbtK+S"}`, true},
		{"should match an AWS access key after tokenization (yaml)", `foo:\n\tbar: E7TZzdyO/HQPgp97EzWicL5FsXBHiFEka9HbtK+S`, true},
		{"should not match something that looks like an AWS access key that's buried in something else", `HELLOE7TZzdyO/HQPgp97EzWicL5FsXBHiFEka9HbtK+SWORLD`, false},
		{"should not match something that looks like an AWS access key but is actually a SHA1 or similar hash", `B3E37C058E373AF3B1CA2C7C5BAE8051595EE985`, false},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			result := matchAwsSecretKey(scenario.Value)
			if result == nil && scenario.ShouldMatch {
				t.Errorf("Expected to match AWS access key, but didn't")
			} else if result != nil && !scenario.ShouldMatch {
				t.Errorf("Expected to not match AWS access key, but did")
			}
			// Otherwise, all good
		})
	}
}
