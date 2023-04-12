resource "kubernetes_namespace" "namespace" {
  for_each = toset(local.objects.namespaces)
  metadata {
    name = each.value
  }
}

resource "kubernetes_pod" "pod" {
  for_each = { for pod in local.objects.pods: "${pod.namespace}/${pod.name}" => pod }

  metadata {
    name = each.value.name
    namespace = each.value.namespace
  }

  spec {
    service_account_name = each.value.serviceAccount
    container {
      name = "main"
      image = "amazon/aws-cli:latest"
      command = ["sleep", "infinity"]
    }
  }

  depends_on = [kubernetes_namespace.namespace, kubernetes_service_account.service_account]
}