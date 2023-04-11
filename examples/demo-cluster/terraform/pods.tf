resource "kubernetes_pod" "pod" {
  for_each = {
    for pod in local.objects.pods : pod.name => pod
  }

  metadata {
    name = each.key
  }
  spec {
    service_account_name = each.value.serviceAccount
    container {
      name = "main"
      image = "amazon/aws-cli:latest"
      command = ["sleep", "infinity"]
    }
  }
}