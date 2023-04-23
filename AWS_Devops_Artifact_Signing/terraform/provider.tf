terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }


  backend "s3" {
    bucket = "cosign-aws-codepipeline"
    key    = "main/terraform.tfstate"
    region = "us-west-2"

  }

}
provider "aws" {
  region = "us-west-2"
  access_key = ""
  secret_key = ""

}
