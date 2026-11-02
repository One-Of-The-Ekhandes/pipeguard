provider "aws" {
  region = "eu-west-1"
}

resource "aws_security_group" "admin" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "company-reports"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "ci" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.reports.arn}/*"]
  }
}

resource "aws_db_instance" "main" {
  engine                      = "postgres"
  publicly_accessible         = false
  storage_encrypted           = true
  manage_master_user_password = true
}

resource "aws_instance" "build_agent" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.medium"
  metadata_options {
    http_tokens = "required"
  }
}
