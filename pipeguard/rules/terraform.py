"""Terraform (AWS provider) rules.

A small block parser finds `resource`, `data`, `provider` and `variable` blocks with brace matching,
so rules can inspect each block's attributes and nested blocks with line numbers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from ..models import Finding, Severity, SourceFile
from ..registry import finding, rule
from .common import SECRET_NAME

HEADER_RE = re.compile(r'^\s*(resource|data|provider|variable|module)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{', re.M)
WORLD = ('"0.0.0.0/0"', '"::/0"')


@dataclass
class Block:
    kind: str       # resource | data | provider | variable | module
    type: str       # e.g. aws_security_group (or the provider/variable name)
    name: str
    line: int       # line of the header
    body: str       # text between the braces
    offset: int     # character offset of body in the file

    def attr(self, key: str) -> str | None:
        m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.+?)\s*$", self.body, re.M)
        return m.group(1) if m else None

    def sub_blocks(self, name: str) -> list[tuple[int, str]]:
        """Nested blocks like `ingress { ... }`: (offset within body, text)."""
        out = []
        for m in re.finditer(rf"^[ \t]*({re.escape(name)})\s*\{{", self.body, re.M):
            end = _match_brace(self.body, m.end() - 1)
            out.append((m.start(1), self.body[m.end():end]))
        return out


def _match_brace(text: str, open_idx: int) -> int:
    depth, i, in_str = 0, open_idx, False
    while i < len(text):
        ch = text[i]
        if ch == '"' and text[i - 1] != "\\":
            in_str = not in_str
        elif not in_str:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return len(text)


def parse(source: SourceFile) -> list[Block]:
    text = source.text
    blocks = []
    for m in HEADER_RE.finditer(text):
        end = _match_brace(text, m.end() - 1)
        line = text.count("\n", 0, m.start()) + 1
        blocks.append(Block(m.group(1), m.group(2), m.group(3) or "", line, text[m.end():end], m.end()))
    return blocks


def _line_at(source: SourceFile, offset: int) -> int:
    return source.text.count("\n", 0, offset) + 1


def _port_in_range(body: str, port: int) -> bool:
    proto = re.search(r'(?:ip_)?protocol\s*=\s*"?(-1|all)"?', body)
    if proto:
        return True
    f = re.search(r"from_port\s*=\s*(\d+)", body)
    t = re.search(r"to_port\s*=\s*(\d+)", body)
    if not f or not t:
        return False
    lo, hi = int(f.group(1)), int(t.group(1))
    return lo <= port <= hi or (lo == 0 and hi in (0, 65535))


@rule("PG-TF-001", "Admin port open to the internet", Severity.HIGH, "terraform",
      "SSH (22) or RDP (3389) open to 0.0.0.0/0 is scanned and brute-forced within minutes of going live.",
      "Restrict the source to your VPN or office range, or remove the rule and use AWS Systems Manager Session Manager.",
      ("https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html",))
def open_admin_port(source: SourceFile) -> Iterator[Finding]:
    for b in parse(source):
        candidates: list[tuple[int, str]] = []
        if b.type == "aws_security_group":
            candidates = b.sub_blocks("ingress")
        elif b.type == "aws_security_group_rule" and '"ingress"' in (b.attr("type") or ""):
            candidates = [(-1, b.body)]
        elif b.type == "aws_vpc_security_group_ingress_rule":
            candidates = [(-1, b.body)]
        for off, body in candidates:
            if any(w in body for w in WORLD):
                for port in (22, 3389):
                    if _port_in_range(body, port):
                        line = b.line if off < 0 else _line_at(source, b.offset + off)
                        yield finding(open_admin_port, source, line,
                                      f"{b.type}.{b.name} allows port {port} from anywhere (0.0.0.0/0).")
                        break


@rule("PG-TF-002", "S3 bucket can be made public", Severity.HIGH, "terraform",
      "A public-read ACL or a disabled public access block can expose every object in the bucket to the internet.",
      "Use acl = \"private\" (or no ACL with bucket owner enforced) and keep all four public access block settings true.",
      ("https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",))
def public_s3(source: SourceFile) -> Iterator[Finding]:
    for b in parse(source):
        if b.type in ("aws_s3_bucket", "aws_s3_bucket_acl"):
            acl = b.attr("acl") or ""
            if "public-read" in acl:
                yield finding(public_s3, source, b.line, f"{b.type}.{b.name} uses a public ACL ({acl}).")
        if b.type == "aws_s3_bucket_public_access_block":
            for key in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
                if (b.attr(key) or "").strip() == "false":
                    yield finding(public_s3, source, b.line, f"{b.type}.{b.name} sets {key} = false.")
                    break


@rule("PG-TF-003", "IAM policy grants full admin", Severity.CRITICAL, "terraform",
      "Action * on Resource * (or AdministratorAccess) lets the holder do anything in the account, so one "
      "leaked key or compromised workload becomes a full account takeover.",
      "Grant only the actions and resources the role needs; start from AWS managed job-function policies "
      "and use IAM Access Analyzer to generate least-privilege policies.",
      ("https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",))
def iam_admin(source: SourceFile) -> Iterator[Finding]:
    star_json = re.compile(r'"?Action"?\s*[:=]\s*(\[\s*)?"\*"', re.I)
    star_res = re.compile(r'"?Resource"?\s*[:=]\s*(\[\s*)?"\*"', re.I)
    for b in parse(source):
        if "arn:aws:iam::aws:policy/AdministratorAccess" in b.body:
            yield finding(iam_admin, source, b.line, f"{b.type}.{b.name} attaches AdministratorAccess.")
            continue
        if b.type == "aws_iam_policy_document":
            for off, st in b.sub_blocks("statement"):
                if re.search(r'actions\s*=\s*\[\s*"\*"\s*\]', st) and re.search(r'resources\s*=\s*\[\s*"\*"\s*\]', st) \
                        and '"Deny"' not in st:
                    yield finding(iam_admin, source, _line_at(source, b.offset + off),
                                  f"data.{b.type}.{b.name} allows every action on every resource.")
        elif b.type.startswith("aws_iam_") and star_json.search(b.body) and star_res.search(b.body) \
                and not re.search(r'"?Effect"?\s*[:=]\s*"Deny"', b.body):
            yield finding(iam_admin, source, b.line, f"{b.type}.{b.name} allows Action \"*\" on Resource \"*\".")


@rule("PG-TF-004", "Cloud credentials hardcoded in the provider", Severity.CRITICAL, "terraform",
      "Access keys in a provider block are committed to Git and readable by everyone with repository access.",
      "Remove them and use environment variables, an AWS profile, or OIDC role assumption in CI. Rotate the exposed keys.",
      ("https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication-and-configuration",))
def provider_keys(source: SourceFile) -> Iterator[Finding]:
    for b in parse(source):
        if b.kind == "provider":
            for key in ("access_key", "secret_key", "token"):
                val = b.attr(key) or ""
                if val.startswith('"') and len(val.strip('"')) > 0:
                    yield finding(provider_keys, source, _line_at(source, b.offset + b.body.find(key)),
                                  f'provider "{b.type}" has a literal {key}.')


@rule("PG-TF-005", "Database publicly accessible", Severity.HIGH, "terraform",
      "publicly_accessible = true gives the database a public endpoint, leaving only the password between "
      "the internet and your data.",
      "Set publicly_accessible = false and reach the database from inside the VPC or through a bastion/SSM.")
def public_db(source: SourceFile) -> Iterator[Finding]:
    for b in parse(source):
        if b.type in ("aws_db_instance", "aws_rds_cluster_instance") and (b.attr("publicly_accessible") or "") == "true":
            yield finding(public_db, source, b.line, f"{b.type}.{b.name} is publicly accessible.")


@rule("PG-TF-006", "Storage not encrypted at rest", Severity.MEDIUM, "terraform",
      "Unencrypted volumes, snapshots and database storage can be read by anyone who obtains a copy, "
      "and fail most compliance standards.",
      "Set storage_encrypted = true (RDS) or encrypted = true (EBS), ideally with a customer-managed KMS key.")
def unencrypted_storage(source: SourceFile) -> Iterator[Finding]:
    keys = {"aws_db_instance": "storage_encrypted", "aws_rds_cluster": "storage_encrypted", "aws_ebs_volume": "encrypted"}
    for b in parse(source):
        key = keys.get(b.type)
        if key and (b.attr(key) or "false").strip() != "true":
            yield finding(unencrypted_storage, source, b.line, f"{b.type}.{b.name} does not set {key} = true.")


@rule("PG-TF-007", "Instance metadata allows IMDSv1", Severity.MEDIUM, "terraform",
      "IMDSv1 answers simple GET requests, so an SSRF bug in any app on the instance can steal its IAM "
      "role credentials (the technique used in the 2019 Capital One breach).",
      "Add metadata_options { http_tokens = \"required\" } to require IMDSv2.",
      ("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",))
def imdsv1(source: SourceFile) -> Iterator[Finding]:
    for b in parse(source):
        if b.type in ("aws_instance", "aws_launch_template"):
            md = b.sub_blocks("metadata_options")
            if not md or not re.search(r'http_tokens\s*=\s*"required"', md[0][1]):
                yield finding(imdsv1, source, b.line, f"{b.type}.{b.name} does not require IMDSv2 (http_tokens = \"required\").")


@rule("PG-TF-008", "Secret hardcoded in Terraform", Severity.HIGH, "terraform",
      "Literal passwords in variables or resources end up in Git history and in the Terraform state file.",
      "Mark the variable sensitive with no default and supply it from a secrets manager, or use "
      "manage_master_user_password = true for RDS.")
def tf_hardcoded_secret(source: SourceFile) -> Iterator[Finding]:
    for b in parse(source):
        if b.kind == "variable" and SECRET_NAME.search(b.type):
            default = b.attr("default") or ""
            if default.startswith('"') and default.strip('"'):
                yield finding(tf_hardcoded_secret, source, b.line, f'variable "{b.type}" has a literal default value.')
        elif b.kind == "resource":
            for m in re.finditer(r'^[ \t]*(\w+)\s*=\s*"([^"$]+)"', b.body, re.M):
                if not _secret_attr(m.group(1)):
                    continue
                yield finding(tf_hardcoded_secret, source, _line_at(source, b.offset + m.start(1)),
                              f"{b.type}.{b.name} sets {m.group(1)} to a literal value.")


def _secret_attr(name: str) -> bool:
    parts = name.lower().split("_")
    return bool({"password", "passwd", "secret", "token"} & set(parts)) or "api_key" in name.lower()
