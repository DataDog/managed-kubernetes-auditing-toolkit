package secrets

import "regexp"

type AwsSecretScanningResult struct {
	AccessKey string
	SecretKey string
}

var (
	AwsAccessKeyPattern = regexp.MustCompile("^AKIA[0-9A-Z]{16}$")
	AwsSecretKeyPattern = regexp.MustCompile("^[A-Za-z0-9/+=]{40}$")
	HashPattern         = regexp.MustCompile("^[0-9a-fA-F]{40}$")
)

func FindAwsCredentialsInUnstructuredString(input string) *AwsSecretScanningResult {
	var result = &AwsSecretScanningResult{}

	accessKey := matchAwsAccessKey(input)
	if accessKey != nil {
		result.AccessKey = *accessKey
	}

	secretKey := matchAwsSecretKey(input)
	if secretKey != nil {
		result.SecretKey = *secretKey
	}
	return result
}

func match(regex *regexp.Regexp, input string) *string {
	tokens := regexp.MustCompile("(?s)\\s*[^a-zA-Z0-9./+)_-]+\\s*").Split(input, -1)
	for _, token := range tokens {
		if token == "" {
			continue
		}
		test := regex.FindStringIndex(token)
		if test != nil {
			matchedValue := token[test[0]:test[1]]
			return &matchedValue
		}
	}
	return nil
}
func matchAwsAccessKey(value string) *string {
	return match(AwsAccessKeyPattern, value)
}

func matchAwsSecretKey(value string) *string {
	result := match(AwsSecretKeyPattern, value)
	if result != nil && !HashPattern.MatchString(value) {
		return result
	}
	return nil
}
