resource "kubernetes_secret" "creds" {
  metadata {
    name = "kafka-proxy-aws"
  }
  data = {
    # Note: These are fictional keys
    aws_access_key_id = "AKIAZ3MSJV4WWNKWW5FG",
    aws_secret_key = "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"
  }
}