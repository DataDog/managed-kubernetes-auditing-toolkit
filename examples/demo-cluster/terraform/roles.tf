data "aws_caller_identity" "current" {}

module "iam_eks_role" {
  source    = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  for_each = {for role in local.objects.roles: role.name => role}

  role_name = each.value.name

  role_policy_arns = {
    policy = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
  }

  oidc_providers = {
    one = {
      provider_arn               = format("arn:aws:iam::%s:oidc-provider/%s", data.aws_caller_identity.current.account_id, replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", ""))
      namespace_service_accounts = [for serviceAccount in each.value.allowedServiceAccounts: "default:${serviceAccount}"]
    }
  }
}