locals {
  objects = yamldecode(file("./objects.yaml"))
}

data "aws_eks_cluster" "cluster" {
  name = var.eks-cluster-name
}
data "aws_eks_cluster_auth" "cluster" {
  name = var.eks-cluster-name
}
provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}




