provider "aws" {
  region     = "eu-west-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_security_group" "admin" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "company-reports"
  acl    = "public-read"
}

resource "aws_iam_policy" "ci" {
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
  password            = "Postgres2024!"
}

resource "aws_instance" "build_agent" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.medium"
}
