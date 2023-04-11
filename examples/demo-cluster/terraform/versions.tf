terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 4.62.0"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
      version = "~> 2.19.0"
    }
  }
}

