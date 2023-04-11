

resource "kubernetes_service_account" "service_account" {
  for_each = { for serviceAccount in local.objects.serviceAccounts: serviceAccount.name => serviceAccount }

  metadata {
    name = each.value.name
    annotations = {
      "eks.amazonaws.com/role-arn" = module.iam_eks_role[each.value.role].iam_role_arn
    }
  }
}