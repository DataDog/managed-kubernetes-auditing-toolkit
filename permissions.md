# Permissions needed to run MKAT

To be able to run MKAT and benefit from all its features, you need the following permissions.

## AWS permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
              "eks:DescribeCluster",
              "iam:ListRoles"
            ],
            "Resource": "*"
        }
    ]
}
```

Optionally, you can restrict `eks:DescribeCluster` to the specific EKS cluster you want to analyze, e.g.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster"
      ],
      "Resource": "arn:aws:eks:us-east-1:012345678901:cluster/your-eks-cluster"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles"
      ],
      "Resource": "*"
    }
  ]
}
```

## Kubernetes permissions

You will need a `ClusterRole` with the following permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: mkat
rules:
# mkat eks find-role-relationships
- apiGroups: [""]
  resources: ["serviceaccounts", "pods"]
  verbs: ["list"]
# mkat eks find-secrets
- apiGroups: [""]
  resources: ["pods", "secrets", "configmaps"]
  verbs: ["list"]
# mkat eks test-imds
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list", "get", "create", "delete"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
```

In EKS, you can for instance bind this ClusterRole to a `mkat-users` group, then use the [`aws-auth`](https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/#authorization-the-aws-auth-configmap) ConfigMap to assign the group to your AWS identity:

```bash
kubectl create clusterrolebinding mkat --clusterrole=mkat --group=mkat-users
```

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    # ...
    - rolearn: arn:aws:iam::012345678901:role/your-role
      groups: ["mkat-users"]
      username: mkat-user:{{SessionName}}
  mapUsers: |
    []
```