# Managed Kubernetes Auditing Toolkit (MKAT)

[![Tests](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/actions/workflows/test.yml/badge.svg)](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/actions/workflows/test.yml) [![go static 
analysis](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/actions/workflows/static-analysis.yml) 


MKAT is an all-in-one auditing toolkit for identifying common security issues within managed Kubernetes environments. It is focused on Amazon EKS at the moment, and will be extended to other managed Kubernetes environments in the future.

Features:
- 🔎 [Identify trust relationships between K8s service accounts and AWS IAM roles](#identify-trust-relationships-between-k8s-service-accounts-and-aws-iam-roles) - supports both IAM Roles for Service Accounts (IRSA), and [Pod Identity](https://aws.amazon.com/blogs/aws/amazon-eks-pod-identity-simplifies-iam-permissions-for-applications-on-amazon-eks-clusters/), [released] on November 26th 2023.
- 🔑 [Find hardcoded AWS credentials in K8s resources](#find-hardcoded-aws-credentials-in-k8s-resources).
- 💀 [Test if pods can access the AWS Instance Metadata Service (IMDS)](#test-if-pods-can-access-the-aws-instance-metadata-service-imds).

## Installation

```bash
brew tap datadog/mkat https://github.com/datadog/managed-kubernetes-auditing-toolkit
brew install datadog/mkat/managed-kubernetes-auditing-toolkit
mkat version
```

... or use a [pre-compiled binary](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/releases).

Then, make sure you are authenticated against your cluster, and to AWS. MKAT uses your current AWS and kubectl authentication contexts.

```bash
aws eks update-kubeconfig --name <cluster-name>
```

## Features

### Identify trust relationships between K8s service accounts and AWS IAM roles

MKAT can identify the trust relationships between K8s service accounts and AWS IAM roles, and display them in a table or as a graph. It currently supports:

- **[IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)**, a popular mechanism to allow pods to assume AWS IAM roles by exchanging a Kubernetes service account token for AWS credentials through the AWS STS API (`AssumeRoleWithWebIdentity`).

- **[EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)**, another newer mechanism that works in a similar way, but is easier to set up.

MKAT works by analyzing both the IAM roles in the AWS account, and the K8s service accounts in the cluster, and then matching them together based on these two mechanisms.

```bash
$ mkat eks find-role-relationships
 _ __ ___   | | __   __ _  | |_
 | '_ ` _ \  | |/ /  / _` | | __|
 | | | | | | |   <  | (_| | | |_
 |_| |_| |_| |_|\_\  \__,_|  \__|

2023/11/28 21:05:59 Connected to EKS cluster mkat-cluster
2023/11/28 21:05:59 Retrieving cluster information
2023/11/28 21:06:00 Listing K8s service accounts in all namespaces
2023/11/28 21:06:02 Listing roles in the AWS account
2023/11/28 21:06:03 Found 286 IAM roles in the AWS account
2023/11/28 21:06:03 Analyzing IAM Roles For Service Accounts (IRSA) configuration
2023/11/28 21:06:03 Analyzing Pod Identity configuration of your cluster
2023/11/28 21:06:04 Analyzing namespace microservices which has 1 Pod Identity associations
2023/11/28 21:06:04 Adding assumable role arn:aws:iam::677301038893:role/webserver-role to pod rate-limiter-1 in namespace microservices
+------------------+---------------------------+-----------------------------------+-----------------------------+--------------------------------+
| NAMESPACE        | SERVICE ACCOUNT           | POD                               | ASSUMABLE ROLE              | MECHANISM                      |
+------------------+---------------------------+-----------------------------------+-----------------------------+--------------------------------+
| microservices    | inventory-service-sa      | inventory-service                 | inventory-service-role      | IAM Roles for Service Accounts |
|                  |                           |                                   | s3-backup-role              | IAM Roles for Service Accounts |
|                  | rate-limiter-sa           | rate-limiter-1                    | rate-limiter-role           | IAM Roles for Service Accounts |
|                  |                           |                                   | webserver-role              | Pod Identity                   |
|                  |                           | rate-limiter-2                    | rate-limiter-role           | IAM Roles for Service Accounts |
|                  |                           |                                   | webserver-role              | Pod Identity                   |
+------------------+---------------------------+-----------------------------------+-----------------------------+--------------------------------+
| default          | vulnerable-application-sa | vulnerable-application            | vulnerable-application-role | IAM Roles for Service Accounts |
|                  | webserver-sa              | webserver                         | webserver-role              | IAM Roles for Service Accounts |
+------------------+---------------------------+-----------------------------------+-----------------------------+--------------------------------+
| external-secrets | external-secrets-sa       | external-secrets-66cfb84c9b-kldt9 | ExternalSecretsRole         | IAM Roles for Service Accounts |
+------------------+---------------------------+-----------------------------------+-----------------------------+--------------------------------+
```

It can also generate a `dot` output for graphic visualization:
 
```bash
$ mkat eks find-role-relationships --output-format dot --output-file roles.dot
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
that can be used to escalate privileges. MKAT can test if pods can access the IMDS, both through IMDSv1 and IMDSv2. 

It tests this by creating two temporary pods (one for IMDSv1, one for IMDSv2) that try to access the IMDS, and are then deleted.

```bash
$ mkat eks test-imds-access
              _              _
  _ __ ___   | | __   __ _  | |_
 | '_ ` _ \  | |/ /  / _` | | __|
 | | | | | | |   <  | (_| | | |_
 |_| |_| |_| |_|\_\  \__,_|  \__|

2023/07/11 21:56:19 Connected to EKS cluster mkat-cluster
2023/07/11 21:56:19 Testing if IMDSv1 and IMDSv2 are accessible from pods by creating a pod that attempts to access it
2023/07/11 21:56:23 IMDSv2 is accessible: any pod can retrieve credentials for the AWS role eksctl-mkat-cluster-nodegroup-ng-NodeInstanceRole-AXWUFF35602Z
2023/07/11 21:56:23 IMDSv1 is not accessible to pods in your cluster: able to establish a network connection to the IMDS, but no credentials were returned
```

## FAQ 

### How does MKAT compare to other tools?

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

### What permissions does MKAT need to run?

See [this page](./permissions.md) for a detailed list of the permissions MKAT needs to run.

## Roadmap

We currently plan to:
* Add a feature to identify EKS pods that are exposed through an AWS load balancer, through the [aws-load-balancer-controller](https://github.com/kubernetes-sigs/aws-load-balancer-controller)
* Add support for GCP GKE
* Allow scanning for additional types of cloud credentials

## Acknowledgements

Thank you to Rami McCarthi and Mikail Tunç for their early testing and actionable feedback on MKAT!
