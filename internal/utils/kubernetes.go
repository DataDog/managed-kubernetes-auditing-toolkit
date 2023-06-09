package utils

import (
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func getKubeConfigPath() string {
	// if KUBECONFIG is set, use it
	if kubeConfigEnvPath := os.Getenv("KUBECONFIG"); kubeConfigEnvPath != "" {
		return kubeConfigEnvPath
	}

	// Otherwise, use $HOME/.kube/config if it exists
	if kubeConfigFilePath := filepath.Join(homedir.HomeDir(), ".kube/config"); FileExists(kubeConfigFilePath) {
		return kubeConfigFilePath
	}

	// Otherwise, return an empty string
	// This will cause `clientcmd.BuildConfigFromFlags` called in `GetClient` will try to use
	// in-cluster auth
	// c.f. https://pkg.go.dev/k8s.io/client-go/tools/clientcmd#BuildConfigFromFlags
	return ""
}

func getConfig() *rest.Config {
	config, err := clientcmd.BuildConfigFromFlags("", getKubeConfigPath())
	if err != nil {
		log.Fatalf("unable to build kube config: %v", err)
	}
	return config
}

func K8sClient() *kubernetes.Clientset {
	k8sClient, err := kubernetes.NewForConfig(getConfig())
	if err != nil {
		log.Fatalf("unable to create kube client: %v", err)
	}
	return k8sClient
}

// IsEKS determines if the cluster in the current context does appear to be an EKS cluster
func IsEKS() bool {
	parsedUrl, err := url.Parse(getConfig().Host)
	if err != nil {
		return false
	}
	return strings.HasSuffix(parsedUrl.Host, ".eks.amazonaws.com")
}

func GetEKSClusterName() string {
	// Most of (if not all) the time, the KubeConfig file generated by "aws eks update-kubeconfig" will have an
	// ExecProvider section that runs "aws eks get-token <...> --cluster-name foo"
	// We parse it and extract the cluster name from there

	execProvider := getConfig().ExecProvider
	if execProvider == nil || execProvider.Command != "aws" {
		return ""
	}
	for i, arg := range execProvider.Args {
		if arg == "--cluster-name" && i+1 < len(execProvider.Args) {
			return execProvider.Args[i+1]
		}
	}
	return ""
}
