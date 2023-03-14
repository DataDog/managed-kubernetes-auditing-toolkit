package main

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"log"
	"os"
	"path/filepath"
)

func K8sClient() *kubernetes.Clientset {
	config, err := clientcmd.BuildConfigFromFlags("", GetKubeConfigPath())
	if err != nil {
		log.Fatalf("unable to build kube config: %v", err)
	}
	k8sClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("unable to create kube client: %v", err)
	}
	return k8sClient
}

// unexported function with the main logic
func GetKubeConfigPath() string {
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
