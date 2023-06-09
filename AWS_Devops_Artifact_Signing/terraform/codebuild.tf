resource "aws_s3_bucket" "codebuild_s3" {
  bucket = "cosign-aws-codepipeline-ga-cb"
  #acl    = "private"
}

resource "aws_iam_role" "codebuild" {
  name = "cosign-aws-codepipeline-ga-codebuild"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codebuild.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "codebuild" {
  role = aws_iam_role.codebuild.name

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": [
        "*"
      ],
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "sts:AssumeRole",
        "codebuild:*"
      ]
    },
    {
      "Effect": "Allow",
      "Resource": [
        "${aws_ecr_repository.ecr.arn}"
      ],
      "Action": [
        "ecr:*"
      ]
    },
    {
      "Effect": "Allow",
      "Resource": [
        "*"
      ],
      "Action": [
        "ecr:GetAuthorizationToken"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:*"
      ],
      "Resource": [
        "${aws_s3_bucket.codebuild_s3.arn}",
        "${aws_s3_bucket.codebuild_s3.arn}/*",
        "${aws_s3_bucket.codepipeline_bucket.arn}",
        "${aws_s3_bucket.codepipeline_bucket.arn}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Resource": [
        "${aws_kms_key.cosign.arn}"
      ],
      "Action": [
        "kms:*"
      ]
    }
  ]
}
POLICY
}

data "aws_caller_identity" "current" {}

resource "aws_codebuild_project" "codebuild-BUILD" {
  name          = "${var.name}-codebuild-BUILD"
  description   = "${var.name}-codebuild-BUILD"
  build_timeout = "5"
  service_role  = aws_iam_role.codebuild.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                       = "aws/codebuild/amazonlinux2-x86_64-standard:4.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"
    privileged_mode             = "true"

    environment_variable {
      name  = "ACCOUNT_ID"
      value = data.aws_caller_identity.current.account_id
      type  = "PLAINTEXT"
    }

    environment_variable {
      name  = "COSIGN_ROLE_NAME"
      value = aws_iam_role.codebuild.name
    }
  }

  logs_config {
    cloudwatch_logs {
      group_name  = aws_cloudwatch_log_group.codebuild.name
      stream_name = aws_cloudwatch_log_stream.codebuild.name
    }

    s3_logs {
      status   = "ENABLED"
      location = "${aws_s3_bucket.codebuild_s3.id}/build-log"
    }
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = file("${path.module}/../buildspec.yml")
  }

  source_version = "master"

  tags = {
    env = var.name
  }
}

resource "aws_cloudwatch_log_group" "codebuild" {
  name = "${var.name}-codebuild"
}

resource "aws_cloudwatch_log_stream" "codebuild" {
  name           = "${var.name}-codebuild"
  log_group_name = aws_cloudwatch_log_group.codebuild.name
}
