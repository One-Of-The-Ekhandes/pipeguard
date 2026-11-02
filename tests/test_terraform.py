from helpers import findings, ids

GOOD = '''
provider "aws" {
  region = "eu-west-1"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible         = false
  storage_encrypted           = true
  manage_master_user_password = true
}

resource "aws_instance" "app" {
  metadata_options {
    http_tokens = "required"
  }
}
'''


def test_clean_terraform():
    assert ids("terraform", GOOD) == []


def test_open_ssh_rdp_and_all_ports():
    tf = '''
resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group_rule" "rdp" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_vpc_security_group_ingress_rule" "all" {
  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "-1"
}
'''
    fs = [f for f in findings("terraform", tf) if f.rule.id == "PG-TF-001"]
    assert [f.line for f in fs] == [2, 9, 16]
    assert "port 3389" in fs[1].message


def test_public_s3():
    tf = '''
resource "aws_s3_bucket" "site" {
  bucket = "my-site"
  acl    = "public-read"
}
resource "aws_s3_bucket_public_access_block" "site" {
  bucket              = aws_s3_bucket.site.id
  block_public_acls   = true
  block_public_policy = false
}
'''
    assert ids("terraform", tf) == ["PG-TF-002", "PG-TF-002"]


def test_iam_admin_variants():
    tf = '''
resource "aws_iam_policy" "god" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
data "aws_iam_policy_document" "god" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
resource "aws_iam_role_policy_attachment" "admin" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_iam_policy" "scoped" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "*" }] })
}
'''
    fs = [f for f in findings("terraform", tf) if f.rule.id == "PG-TF-003"]
    assert [f.line for f in fs] == [1, 7, 12]
    assert str(fs[0].severity) == "critical"


def test_provider_keys_public_db_encryption_imds_secrets():
    tf = '''
provider "aws" {
  access_key = "AKIAEXAMPLEEXAMPLE12"
  secret_key = "abc123"
}
variable "db_password" {
  type    = string
  default = "P@ssw0rd!"
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
  password            = "hunter2hunter2"
}
resource "aws_ebs_volume" "data" {
  size = 10
}
resource "aws_instance" "app" {
  ami = "ami-123"
}
'''
    found = ids("terraform", tf)
    for rid, n in (("PG-TF-004", 2), ("PG-TF-005", 1), ("PG-TF-006", 2), ("PG-TF-007", 1), ("PG-TF-008", 2)):
        assert found.count(rid) == n, (rid, found)
