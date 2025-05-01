package imds

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	typedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type ImdsTester struct {
	K8sClient *kubernetes.Clientset
	Namespace string
}

type ImdsTestResult struct {
	IsImdsAccessible  bool
	ResultDescription string
}

const ImdsTesterV1PodName = "mkat-imds-tester"
const ImdsTesterV2PodName = "mkat-imds-v2-tester"

func (m *ImdsTester) TestImdsV1Accessible() (*ImdsTestResult, error) {
	commandToRun := []string{
		"sh",
		"-c",
		"(curl --silent --show-error --connect-timeout 2 169.254.169.254/latest/meta-data/iam/security-credentials/ || true)",
	}
	podLogs, err := m.runCommandInPodAndGetLogs(ImdsTesterV1PodName, commandToRun)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve logs from IMDS tester pod: %v", err)
	}

	// Case 1: no network connection (e.g. NetworkPolicy in place)
	if strings.Contains(podLogs, "Failed to connect") {
		return &ImdsTestResult{
			IsImdsAccessible:  false,
			ResultDescription: "unable to establish a network connection to the IMDS",
		}, nil
	}

	// Case 2: IMDSv2 enforced, IMDSv1 is accessible at the network level but returns a 401 error
	if strings.TrimSpace(podLogs) == "" {
		return &ImdsTestResult{
			IsImdsAccessible:  false,
			ResultDescription: "able to establish a network connection to the IMDS, but no credentials were returned",
		}, nil
	}

	// Case 3: IMDSv1 is accessible and returns credentials
	return &ImdsTestResult{
		IsImdsAccessible:  true,
		ResultDescription: fmt.Sprintf("any pod can retrieve credentials for the AWS role %s", podLogs),
	}, nil
}

func (m *ImdsTester) TestImdsV2Accessible() (*ImdsTestResult, error) {
	commandToRun := []string{
		"sh",
		"-c",
		// We use "--max-time" because when the IMDS max-response-hop is set to 1, the TCP connection succeeds initially but hangs indefinitely when calling /latest/api/token
		`TOKEN=$(curl --show-error --max-time 2 --silent -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
		(curl --silent --show-error --max-time 2 -H "X-aws-ec2-metadata-token: $TOKEN" 169.254.169.254/latest/meta-data/iam/security-credentials/ || true)`,
	}
	podLogs, err := m.runCommandInPodAndGetLogs(ImdsTesterV2PodName, commandToRun)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve logs from IMDS tester pod: %v", err)
	}

	// Case 1: no network connection (e.g. NetworkPolicy in place)
	if strings.Contains(podLogs, "Failed to connect") || strings.Contains(podLogs, "timed out") {
		return &ImdsTestResult{
			IsImdsAccessible:  false,
			ResultDescription: "unable to establish a network connection to the IMDS",
		}, nil
	}

	// Case 3: IMDSv2 is accessible and returns credentials
	return &ImdsTestResult{
		IsImdsAccessible:  true,
		ResultDescription: fmt.Sprintf("any pod can retrieve credentials for the AWS role %s", podLogs),
	}, nil
}

func (m *ImdsTester) runCommandInPodAndGetLogs(podName string, command []string) (string, error) {
	podsClient := m.K8sClient.CoreV1().Pods(m.Namespace)
	podDefinition := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: m.Namespace},
		Spec: v1.PodSpec{
			Containers: []v1.Container{{
				Name:    podName,
				Image:   "curlimages/curl:8.00.1",
				Command: command,
				Resources: v1.ResourceRequirements{
					Requests: v1.ResourceList{
						v1.ResourceCPU:    resource.MustParse("500m"),
						v1.ResourceMemory: resource.MustParse("128Mi"),
					},
					Limits: v1.ResourceList{
						v1.ResourceCPU:    resource.MustParse("500m"),
						v1.ResourceMemory: resource.MustParse("256Mi"),
					},
				},
			}},
			RestartPolicy: v1.RestartPolicyNever, // don't restart the pod once the command has been executed
		},
	}
	_, err := podsClient.Create(context.Background(), podDefinition, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to create IMDS tester pod: %v", err)
	}
	m.handleCtrlC()
	defer removePod(podsClient, podName)

	err = wait.PollImmediate(1*time.Second, 120*time.Second, func() (bool, error) {
		return podHasSuccessfullyCompleted(podsClient, podName)
	})

	if err != nil {
		return "", fmt.Errorf("unable to wait for IMDS tester pod to complete: %v", err)
	}

	// Retrieve command output
	podLogs, err := getPodLogs(podsClient, podName)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve logs from IMDS tester pod: %v", err)
	}

	return podLogs, nil
}

func (m *ImdsTester) handleCtrlC() {
	// If the user interactively cancels the test, clean up the pod
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		println("Received SIGINT, cleaning up IMDS tester pods")
		podsClient := m.K8sClient.CoreV1().Pods(m.Namespace)
		removePod(podsClient, ImdsTesterV1PodName)
		removePod(podsClient, ImdsTesterV2PodName)
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
	podLogsRequest := podsClient.GetLogs(podName, &v1.PodLogOptions{})
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
