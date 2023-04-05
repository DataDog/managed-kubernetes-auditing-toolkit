package secrets

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"log"
	"strconv"
)

type SecretsDetector struct {
	AwsClient *aws.Config
	K8sClient *kubernetes.Clientset
	Namespace string // empty for all namespaces
}

type SecretInfo struct {
	Namespace string
	Type      string
	Name      string
	Value     string
}

func (m *SecretsDetector) FindSecrets() ([]*SecretInfo, error) {
	var secrets []*SecretInfo

	log.Println("Searching for AWS secrets in ConfigMaps...")
	configMapCredentials, err := m.findCredentialsInConfigMaps()
	if err != nil {
		return nil, err
	}
	secrets = append(secrets, configMapCredentials...)

	log.Println("Searching for AWS secrets in Secrets...")
	secretCredentials, err := m.findCredentialsInSecrets()
	if err != nil {
		return nil, err
	}
	secrets = append(secrets, secretCredentials...)

	log.Println("Searching for AWS secrets in Pod definitions...")
	podCredentials, err := m.findCredentialsInPodDefinitions()
	if err != nil {
		return nil, err
	}
	secrets = append(secrets, podCredentials...)

	return secrets, nil
}

func (m *SecretsDetector) findCredentialsInConfigMaps() ([]*SecretInfo, error) {
	configMaps, err := m.K8sClient.CoreV1().ConfigMaps(m.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list ConfigMaps: %v", err)
	}
	var secrets []*SecretInfo
	log.Println("Analyzing " + strconv.Itoa(len(configMaps.Items)) + " ConfigMaps...")
	for _, configMap := range configMaps.Items {
		configMapSecrets := findSecretsInSingleConfigMap(&configMap)
		secrets = append(secrets, configMapSecrets...)
	}
	return secrets, nil
}

func (m *SecretsDetector) findCredentialsInSecrets() ([]*SecretInfo, error) {
	k8sSecrets, err := m.K8sClient.CoreV1().Secrets(m.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list Secrets: %v", err)
	}
	var secrets []*SecretInfo
	log.Println("Analyzing " + strconv.Itoa(len(k8sSecrets.Items)) + " Secrets...")
	for _, k8sSecret := range k8sSecrets.Items {
		configMapSecrets := findSecretsInSingleSecret(&k8sSecret)
		secrets = append(secrets, configMapSecrets...)
	}
	return secrets, nil
}

func (m *SecretsDetector) findCredentialsInPodDefinitions() ([]*SecretInfo, error) {
	pods, err := m.K8sClient.CoreV1().Pods(m.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to list Pods: %v", err)
	}
	var secrets []*SecretInfo
	log.Println("Analyzing " + strconv.Itoa(len(pods.Items)) + " Pod definitions...")
	for _, pod := range pods.Items {
		podSecrets := findSecretsInSinglePodDefinition(&pod)
		secrets = append(secrets, podSecrets...)
	}
	return secrets, nil
}
