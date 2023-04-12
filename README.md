# Managed Kubernetes Auditing Toolkit (MKAT)

[![Tests](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/actions/workflows/test.yml) [![go static 
analysis](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/actions/workflows/static-analysis.yml) 


MKAT is an all-in-one auditing toolkit for identifying common security issues within managed Kubernetes environments. It is focused on AWS EKS at the moment, and will be extended to other managed Kubernetes environments in the future.

Features:
- [Identify trust relationships between K8s service accounts and AWS IAM roles](#identify-trust-relationships-between-k8s-service-accounts-and-aws-iam-roles)
- [Find hardcoded AWS credentials in K8s resources](#find-hardcoded-aws-credentials-in-k8s-resources)
- [Test if pods can access the AWS Instance Metadata Service (IMDS)](#test-if-pods-can-access-the-aws-instance-metadata-service-imds=

## Installation

```bash
brew tap datadog/managed-kubernetes-auditing-toolkit https://github.com/datadog/managed-kubernetes-auditing-toolkit
brew install datadog/managed-kubernetes-auditing-toolkit/managed-kubernetes-auditing-toolkit
```

... or use a [pre-compiled binary](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/releases).

Then, make sure you are authenticated against your cluster, and to AWS. MKAT uses your current AWS and kubectl authentication contexts.

```bash
aws eks update-kubeconfig --name <cluster-name>
```

## Features

### Identify trust relationships between K8s service accounts and AWS IAM roles

[IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) is 
a popular mechanism to allow pods to assume AWS IAM roles, by exchanging a Kubernetes service account token for AWS credentials through the AWS STS API (`AssumeRoleWithWebIdentity`).

MKAT can identify the trust relationships between K8s service accounts and AWS IAM roles, and display them in a table or as a graph. 
It works by looking both at the trust policy of the IAM roles, and at the service accounts that are associated with the pods running in the cluster.

```bash
$ mkat eks find-role-role-relationships
              _              _
  _ __ ___   | | __   __ _  | |_
 | '_ ` _ \  | |/ /  / _` | | __|
 | | | | | | |   <  | (_| | | |_
 |_| |_| |_| |_|\_\  \__,_|  \__|

2023/04/12 00:25:15 Connected to EKS cluster mkat-cluster
2023/04/12 00:25:15 Retrieving cluster OIDC issuer
2023/04/12 00:25:16 Listing roles in the AWS account
2023/04/12 00:25:18 Listing K8s service accounts in all namespaces
2023/04/12 00:25:19 Analyzing the trust policy of 5 IAM roles that have the cluster's OIDC provider in their trust policy
+-----------+----------------------+-------------------+-------------------------------------------------------+
| NAMESPACE | SERVICE ACCOUNT      | POD               | ASSUMABLE ROLE ARN                                    |
+-----------+----------------------+-------------------+-------------------------------------------------------+
| default   | apigw-sa             | apigw             | arn:aws:iam::677301038893:role/apigw-role             |
|           |                      |                   | arn:aws:iam::677301038893:role/s3-reader              |
|           | inventory-service-sa | inventory-service | arn:aws:iam::677301038893:role/inventory-service-role |
|           |                      |                   | arn:aws:iam::677301038893:role/s3-reader              |
|           | kafka-proxy-sa       | kafka-proxy       | arn:aws:iam::677301038893:role/kafka-proxy-role       |
|           | rate-limiter-sa      | rate-limiter      | arn:aws:iam::677301038893:role/rate-limiter-role      |
+-----------+----------------------+-------------------+-------------------------------------------------------+
```

It can also generate a `dot` output for graphic visualization:
 
```bash
$ mkat eks find-role-role-relationships --output-format dot --output-file roles.dot
$ dot -Tpng -O roles.dot
$ open roles.dot.png
```

![Mapping trust relationships](./examples/irsa.png)

### Find hardcoded AWS credentials in K8s resources

MKAT can identify hardcoded AWS credentials in K8s resources such as Pods, ConfigMaps, and Secrets. 
It has a low false positive rate, and only alerts you if it finds both an AWS access key ID and a secret access key in the same Kubernetes resource.
It's also able to work with unstructured data, i.e. if you have a ConfigMap with an embedded JSON or YAML document that contains AWS credentials.

```bash
$ mkat eks find-secrets
              _              _
  _ __ ___   | | __   __ _  | |_
 | '_ ` _ \  | |/ /  / _` | | __|
 | | | | | | |   <  | (_| | | |_
 |_| |_| |_| |_|\_\  \__,_|  \__|

2023/04/12 00:33:24 Connected to EKS cluster mkat-cluster
2023/04/12 00:33:24 Searching for AWS secrets in ConfigMaps...
2023/04/12 00:33:25 Analyzing 10 ConfigMaps...
2023/04/12 00:33:25 Searching for AWS secrets in Secrets...
2023/04/12 00:33:25 Analyzing 45 Secrets...
2023/04/12 00:33:25 Searching for AWS secrets in Pod definitions...
2023/04/12 00:33:25 Analyzing 8 Pod definitions...
+-----------+--------+-----------------------------------------+------------------------------------------+
| NAMESPACE | TYPE   | NAME                                    | VALUE                                    |
+-----------+--------+-----------------------------------------+------------------------------------------+
| default   | Secret | kafka-proxy-aws (key aws_access_key_id) | AKIAZ3MSJV4WWNKWW5FG                     |
| default   | Secret | kafka-proxy-aws (key aws_secret_key)    | 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 |
+-----------+--------+-----------------------------------------+------------------------------------------+
```

### Test if pods can access the AWS Instance Metadata Service (IMDS)

Pods accessing the EKS nodes Instance Metadata Service is a [common and dangerous attack vector](https://blog.christophetd.fr/privilege-escalation-in-aws-elastic-kubernetes-service-eks-by-compromising-the-instance-role-of-worker-nodes/) 
that can be used to escalate privileges. MKAT can test if pods can access the IMDS. It tests it by creating a temporary pod that tries to access the IMDS, and then deletes it.

```bash
$ mkat eks test-imds-access
              _              _
  _ __ ___   | | __   __ _  | |_
 | '_ ` _ \  | |/ /  / _` | | __|
 | | | | | | |   <  | (_| | | |_
 |_| |_| |_| |_|\_\  \__,_|  \__|

2023/04/12 00:35:10 Connected to EKS cluster mkat-cluster
2023/04/12 00:35:10 Testing if IMDS is accessible to pods by creating a pod that attempts to access it
2023/04/12 00:35:15 IMDS is accessible and allows any pod to retrieve credentials for the AWS role eksctl-mkat-cluster-nodegroup-ng-NodeInstanceRole-AXWUFF35602Z
```

## How does MKAT compare to other tools?

| **Tool** | **Description** |
|:---:|:---:|
| [kube-bench](https://github.com/aquasecurity/kube-bench) |  kube-bench is a general-purpose auditing tool for Kubernetes cluster, checking for compliance against the CIS benchmarks |
| [kubiscan](https://github.com/cyberark/KubiScan) | kubiscan focuses on identifying dangerous in-cluster RBAC permissions |
| [peirates](https://github.com/inguardians/peirates) |   peirates is a generic Kubernetes penetration testing tool. Although it has a `get-aws-token` command that retrieve node credentials from the IMDS, it is not specific to managed K8s environments. |
| [botb](https://github.com/brompwnie/botb) | botb is a generic Kubernetes penetration testing tool. It also has a command to retrieve node credentials from the IMDS, but it is not specific to managed K8s environments. |
| [rbac-police](https://github.com/PaloAltoNetworks/rbac-police) | rbac-police focuses on identifying in-cluster RBAC relationships. |
| [kdigger](https://github.com/quarkslab/kdigger) | kdigger is a general-purpose context discovery tool for Kubernetes penetration testing. It does not attempt to be specific to managed K8s environments. |
| [kubeletmein](https://github.com/4ARMED/kubeletmein) | kubeletmein _is_ specific to managed K8s environments. It's an utility to generate a kubeconfig file using the node's IAM credentials, to then use it in a compromised pod. |
| [hardeneks](https://github.com/aws-samples/hardeneks) | hardeneks _is_ specific to managed K8s environments, but only for EKS. It identifies issues and lack of best practices inside of the cluster, and does not focus on cluster to cloud pivots. |

## Roadmap

We currently plan to:
* Add a feature to identify EKS pods that are exposed through an AWS load balancer, through the [aws-load-balancer-controller](https://github.com/kubernetes-sigs/aws-load-balancer-controller)
* Add support for GCP GKE
* Allow scanning for additional types of cloud credentials
* Enhance the IAM role trust policy evaluation logic to take into account additional edge cases
