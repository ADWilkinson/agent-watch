import pytest

from agent_watch.redact import evidence, redact, set_redact_terms, truncate

# All values below are fake and made up for these tests.
FAKES = [
    "sk-ant-api03-FAKEFAKEFAKEFAKE1234567890",
    "sk-proj-abcdefghijklmnop1234",
    "ghp_FAKEaaaaBBBBccccDDDD1234567890",
    "gho_FAKEaaaaBBBBccccDDDD1234",
    "github_pat_11FAKE0000_abcdefghijklmnopqrstuvwxyz",
    "xoxb-1234-5678-FAKEtoken",
    "AKIAFAKE1234567890AB",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlRkFLRQ",
    "0123456789abcdef0123456789abcdef0123",
    "Q2FmZUJhYmVGYWtlU2VjcmV0VmFsdWUxMjM0NTY3ODk=",
]


@pytest.mark.parametrize("secret", FAKES)
def test_secrets_removed(secret):
    out = redact(f"export X={secret} && echo done")
    assert secret not in out
    assert secret[:12] not in out


def test_bearer_and_query_params():
    out = redact("curl -H 'Authorization: Bearer abc.def.ghi123' 'https://x.example/a?token=s3cr3t&key=k3y&page=2'")
    assert "abc.def" not in out and "s3cr3t" not in out and "k3y" not in out
    assert "page=2" in out


def test_env_assignment_values():
    out = redact("STRIPE_SECRET=whsec_live_1 API_KEY=abc123 npm start")
    assert "whsec_live_1" not in out and "abc123" not in out


def test_private_key_block():
    block = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfake\n-----END OPENSSH PRIVATE KEY-----"
    out = redact(f"cat <<EOF\n{block}\nEOF")
    assert "AAAAfake" not in out and "[PRIVATE_KEY]" in out


def test_emails_and_phones():
    out = redact("mail jane.doe@example.co.uk or call +44 7700 900123 or 020 7946 0958")
    assert "@" not in out
    assert "7700" not in out and "7946" not in out


def test_home_paths_and_project_names():
    out = redact("cd /home/alice/projects/personal/secret-thing/src && ls /Users/bob/.ssh")
    assert "/home/" not in out and "/Users/" not in out
    assert "secret-thing" not in out and "alice" not in out
    assert "~/.ssh" in out


def test_cwd_becomes_repo():
    assert redact("Write /home/a/proj/x.py", cwd="/home/a/proj") == "Write <repo>/x.py"


def test_redact_terms_removed():
    try:
        set_redact_terms(["acme-corp", "client-x"])
        out = redact("npm i --save-exact @Acme-Corp/sdk client-x-tools")
        assert "acme" not in out.lower() and "client-x" not in out.lower()
        assert "[term]" in out
    finally:
        set_redact_terms([])


def test_no_redact_terms_by_default():
    set_redact_terms([])
    assert redact("npm i --save-exact acme-corp") == "npm i --save-exact acme-corp"


def test_plain_text_survives():
    s = "git push origin feature/add-login-button"
    assert redact(s) == s


def test_truncate_and_evidence():
    assert len(truncate("x" * 500)) == 160
    assert "\n" not in truncate("a\nb")
    long = "echo " + "ghp_" + "A1b2" * 20
    assert "A1b2" not in evidence(long)



def test_redacts_agent_scratch_uuid_and_ip():
    from agent_watch.redact import redact
    out = redact("Write /tmp/claude-1000/-home-x-projects-personal-site/732bb899-cc04-46ce-a304-784cab11f7a1/a.ts and curl http://100.64.12.34:8080 id 732bb899-cc04-46ce-a304-784cab11f7a1")
    assert "personal-site" not in out and "100.64" not in out and "732bb899" not in out
