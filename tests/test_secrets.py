from helpers import ids

# Test values are built at run time so this file never contains a real-looking secret.
AWS = "AKIA" + "Q3EGRZWX5TQ7LMNB"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
KEY_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"


def test_aws_key_and_example_key():
    assert ids("other", f"aws_access_key_id = {AWS}\n") == ["PG-SEC-001"]
    assert ids("other", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n") == []


def test_private_key_and_github_token():
    assert ids("other", KEY_HEADER + "\nabc\n") == ["PG-SEC-002"]
    assert ids("other", f"token: {GH}\n") == ["PG-SEC-003"]


def test_slack():
    hook = "https://hooks.slack.com/services/" + "T0123ABCD/B0456EFGH/abcdefghijklmnopqrstuvwx"
    assert ids("other", f"SLACK_URL={hook}\n") == ["PG-SEC-004"]


def test_url_credentials_and_safe_variants():
    assert ids("other", "git clone https://bob:Sup3rS3cret@git.example.org/repo.git\n") == ["PG-SEC-005"]
    for safe in ("https://bob:$TOKEN@git.example.org", "https://bob:${{ secrets.T }}@x.org",
                 "postgres://user:password@localhost/db", "https://git.example.org/repo.git"):
        assert ids("other", safe + "\n") == [], safe


def test_secret_rules_run_on_every_file_kind():
    assert "PG-SEC-001" in ids("dockerfile", f"FROM alpine:3.20\nENV KEY_ID={AWS}\nUSER app\nHEALTHCHECK CMD true\n")
