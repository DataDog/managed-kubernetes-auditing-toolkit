package imds

import (
	"bytes"
	"context"
	"fmt"
	"io"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	typedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type ImdsTester struct {
	K8sClient *kubernetes.Clientset
	Namespace string
}

type ImdsTestResult struct {
	IsImdsAccessible bool
	NodeRoleName     string
}

const ImdsTesterPodName = "mkat-imds-tester"

func (m *ImdsTester) TestImdsAccessible() (*ImdsTestResult, error) {
	podDefinition := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: ImdsTesterPodName, Namespace: m.Namespace},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name:    ImdsTesterPodName,
				Image:   "curlimages/curl:8.00.1",
				Command: []string{"sh", "-c", "(curl --silent --show-error --connect-timeout 2 169.254.169.254/latest/meta-data/iam/security-credentials/ || true)"},
			}},
			RestartPolicy: v1.RestartPolicyNever, // don't restart the pod once the command has been executed
		},
	}
	podsClient := m.K8sClient.CoreV1().Pods(m.Namespace)

	log.Println("Testing if IMDS is accessible to pods by creating a pod that attempts to access it")
	_, err := podsClient.Create(context.Background(), podDefinition, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to create IMDS tester pod: %v", err)
	}
	m.handleCtrlC()
	defer removePod(podsClient, ImdsTesterPodName)

	err = wait.PollImmediate(1*time.Second, 120*time.Second, func() (bool, error) {
		return podHasSuccessfullyCompleted(podsClient, ImdsTesterPodName)
	})

	if err != nil {
		return nil, fmt.Errorf("unable to wait for IMDS tester pod to complete: %v", err)
	}

	// Retrieve command output
	podLogs, err := getPodLogs(podsClient, ImdsTesterPodName)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve logs from IMDS tester pod: %v", err)
	}
	if strings.Contains(podLogs, "Failed to connect") {
		return &ImdsTestResult{IsImdsAccessible: false}, nil
	} else {
		return &ImdsTestResult{IsImdsAccessible: true, NodeRoleName: podLogs}, nil
	}
}

func (m *ImdsTester) handleCtrlC() {
	// If the user interactively cancels the test, clean up the pod
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		println("Received SIGINT, cleaning up IMDS tester pod")
		removePod(m.K8sClient.CoreV1().Pods(m.Namespace), ImdsTesterPodName)
		os.Exit(1)
	}()
}

func podHasSuccessfullyCompleted(podsClient typedv1.PodInterface, podName string) (bool, error) {
	pod, err := podsClient.Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	if pod.Status.Phase == v1.PodSucceeded {
		return true, nil
	} else if pod.Status.Phase != v1.PodPending && pod.Status.Phase != v1.PodRunning {
		return false, fmt.Errorf("pod %s errored and is in status %s", podName, pod.Status.Phase)
	}

	return false, nil
}

func getPodLogs(podsClient typedv1.PodInterface, podName string) (string, error) {
	podLogsRequest := podsClient.GetLogs(ImdsTesterPodName, &v1.PodLogOptions{})
	podLogs, err := podLogsRequest.Stream(context.Background())
	if err != nil {
		return "", fmt.Errorf("unable to get logs for pod %s: %v", podName, err)
	}
	defer podLogs.Close()
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)
	if err != nil {
		return "", fmt.Errorf("unable to copy logs for pod %s: %v", podName, err)
	}
	return buf.String(), nil
}

func removePod(podsClient typedv1.PodInterface, podName string) {
	var gracePeriod int64 = 0
	_ = podsClient.Delete(context.Background(), podName, metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
	})
}
