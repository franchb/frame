"""Value-shape gate for the Tier-2 hardcoded-secret literal scan.

The name-based secret rules (CWE-259/321/798) match on the *target* name, e.g.
``(crypt|secret|private|signing)[._]?key``.  A constant whose name mentions a
key but whose value is a field name, filename, PEM block label or env-var name
is not a hardcoded secret -- e.g. Kubernetes' ``SSHAuthPrivateKey =
"ssh-privatekey"`` or ``ECPrivateKeyBlockType = "EC PRIVATE KEY"``.  These
tests pin that such identifier-shaped values stay silent while real key
material still fires.

Every silent case is paired with a firing twin at the same name/position so a
frontend that stops emitting the assignment makes the test fail loudly instead
of passing vacuously.
"""

import pytest

from frame.sil.scanner import FrameScanner, VulnType


PEM_BODY = (
    "-----BEGIN EC PRIVATE" " KEY-----\\n"
    "MHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oZjQRE3Uu1aroAoGCCqGSM49\\n"
    "AwEHoUQDQgAEoBUyo8CQAFPeYPvv78ylh5MwFZjTCLQeb042TjiMJxG+9DLFmRSM\\n"
    "-----END EC PRIVATE KEY-----\\n"
)
# Token-shaped fixtures are split with adjacent-literal concatenation so the
# committed source never contains a whole credential-format string (keeps
# secret scanners / push protection quiet); runtime values are unchanged.
AWS_KEY = "AKIA" "IOSFODNN7EXAMPLE"

# (language, extension, template with {name} and {value})
_TEMPLATES = [
    ("python", "py", 'def f():\n    {name} = "{value}"\n'),
    ("python", "py", '{name} = "{value}"\n'),
    ("java", "java", 'class C {{\n  void f() {{\n    String {name} = "{value}";\n  }}\n}}\n'),
    ("javascript", "js", 'function f() {{\n  const {name} = "{value}";\n}}\n'),
    ("csharp", "cs", 'class C {{\n  void F() {{\n    string {name} = "{value}";\n  }}\n}}\n'),
]

# Kubernetes-shaped constants that the name rule matches but whose values are
# identifiers / filenames / PEM labels, not secrets.
_K8S_NONSECRETS = [
    # camelCase (Go spelling), UPPER_SNAKE and snake_case variants.
    ("ServiceAccountPrivateKeyName", "sa.key"),
    ("SSHAuthPrivateKey", "ssh-privatekey"),
    ("ECPrivateKeyBlockType", "EC PRIVATE KEY"),
    ("BootstrapTokenSecretKey", "token-secret"),
    ("SERVICE_ACCOUNT_PRIVATE_KEY_NAME", "sa.key"),
    ("SSH_AUTH_PRIVATE_KEY", "ssh-privatekey"),
    ("EC_PRIVATE_KEY_BLOCK_TYPE", "EC PRIVATE KEY"),
    ("BOOTSTRAP_TOKEN_SECRET_KEY", "token-secret"),
    ("ssh_auth_private_key", "ssh-privatekey"),
    ("bootstrap_token_secret_key", "token-secret"),
]


def _secrets(lang, ext, code):
    result = FrameScanner(language=lang, verify=False).scan(code, "t." + ext)
    return [v for v in result.vulnerabilities if v.type == VulnType.HARDCODED_SECRET]


def _ids(params):
    return [f"{p[0]}-{i}" for i, p in enumerate(params)]


_SCAN_CASES = [(lang, ext, tpl, name, value)
               for (lang, ext, tpl) in _TEMPLATES
               for (name, value) in _K8S_NONSECRETS]


@pytest.mark.parametrize("lang,ext,tpl,name,value", _SCAN_CASES, ids=_ids(_SCAN_CASES))
def test_identifier_shaped_value_is_silent(lang, ext, tpl, name, value):
    code = tpl.format(name=name, value=value)
    hits = _secrets(lang, ext, code)
    assert not hits, f"false positive on {name} = {value!r} ({lang}): {hits}"


@pytest.mark.parametrize("lang,ext,tpl,name,value", _SCAN_CASES, ids=_ids(_SCAN_CASES))
def test_key_material_twin_fires(lang, ext, tpl, name, value):
    # Same name and position as the silent case, real key material as value.
    for secret in (PEM_BODY, AWS_KEY):
        code = tpl.format(name=name, value=secret)
        hits = _secrets(lang, ext, code)
        assert hits, f"missed key material in {name} ({lang}): {secret[:30]!r}"


@pytest.mark.parametrize("code", [
    # PEM armor line alone (no body) is a label, not a key.
    'def f():\n    private_key_header = "-----BEGIN RSA PRIVATE KEY-----"\n',
    # Filenames / paths.
    'def f():\n    private_key_file = "/etc/kubernetes/pki/sa.key"\n',
    'def f():\n    signing_key_path = "./certs/signing.pem"\n',
    'def f():\n    private_key = "tls.key"\n',
    'def f():\n    password_file = "secret.txt"\n',
    # Env-var name holding where the secret lives.
    'def f():\n    SECRET_KEY_ENV = "APP_SECRET_KEY"\n',
    'def f():\n    password_env = "DB_PASSWORD"\n',
    # Field / key names in a map or secret object.
    'def f():\n    api_key_field = "api-key"\n',
    'def f():\n    token_key = "token_id"\n',
    # Placeholders.
    'def f():\n    secret_key = "<your-secret-key>"\n',
    'def f():\n    secret_key = "$APP_SECRET_KEY"\n',
    'def f():\n    secret_key = "$(cat /run/secrets/key)"\n',
])
def test_nonsecret_shapes_python(code):
    assert not _secrets("python", "py", code), f"false positive on {code!r}"


@pytest.mark.parametrize("code,cwe", [
    # PEM with a base64 body -- the real Kubernetes hit shape.
    (f'def f():\n    ecdsa_private_key = "{PEM_BODY}"\n', "CWE-321"),
    # Python triple-quoted PEM (real newlines rather than escapes).
    ('ECDSA_PRIVATE_KEY = """-----BEGIN EC PRIVATE' ' KEY-----\n'
     'MHcCAQEEIBkg4LVWM9nuwNSk3yByxZpYRTBnVJk5oZjQRE3Uu1aroAoGCCqGSM49\n'
     '-----END EC PRIVATE KEY-----\n"""\n', "CWE-321"),
    # High-entropy token.
    ('def f():\n    secret_key = "q8Vz3Lr0XkP2mT9wYb7NcD4hJ6sF1aGe"\n', "CWE-321"),
    # High-entropy token containing '/', must not be mistaken for a path.
    ('def f():\n    aws_secret_access_key = "wJalrXUtnFEMI/' 'K7MDENG/bPxRfiCYEXAMPLEKEY"\n', None),
    # Known credential formats.
    (f'def f():\n    access_key = "{AWS_KEY}"\n', "CWE-798"),
    ('def f():\n    token = "gh' 'p_1A2b3C4d5E6f7G8h9I0jK1l2M3n4O5p6Q7r8"\n', "CWE-798"),
    ('def f():\n    token = "xox' 'b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"\n', "CWE-798"),
    ('def f():\n    auth_token = "ey' 'JhbGciOiJIUzI1NiJ9.ey' 'JzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"\n',
     "CWE-798"),
    # Short values carrying a credential prefix still fire.
    ('def f():\n    api_key = "sk_live_short1"\n', "CWE-798"),
    ('def f():\n    token = "ghp_short"\n', "CWE-798"),
    ('def f():\n    token = "xoxp-abc"\n', "CWE-798"),
    # Ambiguous human passwords keep firing (consistent with the existing
    # `password = "hunter2pass"` test): passwords are low-entropy by nature.
    ('def f():\n    DB_PASSWORD = "S3cr3t!Passw0rd"\n', "CWE-259"),
    ('def f():\n    password = "admin123"\n', "CWE-259"),
    ('def f():\n    password = "hunter2pass"\n', "CWE-259"),
    ('def f():\n    signing_key = "mysupersecretkey"\n', "CWE-321"),
    ('def f():\n    api_key = "sk_live_abcd1234"\n', "CWE-798"),
    # Identifier-shaped values NOT tied to the target name are real secrets
    # (regression rows: a value-only classifier silenced all of these).
    ('SECRET_KEY = "super-secret-key"\n', "CWE-321"),
    ('def f():\n    SECRET_KEY = "super-secret-key"\n', "CWE-321"),
    ('def f():\n    SECRET_KEY = "secret-key-change-in-production"\n', "CWE-321"),
    ('def f():\n    SECRET_KEY = "django-insecure-abcdefghijklmnopqrstuvwxyz"\n', "CWE-321"),
    ('def f():\n    secret = "my-app-secret"\n', "CWE-798"),
    ('def f():\n    client_secret = "dev-client-secret"\n', "CWE-798"),
    ('def f():\n    jwt_secret = "jwt_secret_key"\n', "CWE-798"),
    ('def f():\n    password = "correct-horse-battery-staple"\n', "CWE-259"),
    ('def f():\n    password = "hunter2_pass"\n', "CWE-259"),
    ('def f():\n    password = "PROD_DB_PASS_2024"\n', "CWE-259"),
    ('def f():\n    password = "ADMIN_PASS"\n', "CWE-259"),
    ('def f():\n    password = "pass.word"\n', "CWE-259"),
    ('def f():\n    token = "abc.def.ghi"\n', "CWE-798"),
    # Non-key file extension is only a filename when the name says so.
    ('def f():\n    password = "secret.txt"\n', "CWE-259"),
    # '$' inside a password is not an env-var placeholder.
    ('def f():\n    password = "$ecret"\n', "CWE-259"),
    ('def f():\n    password = "$uperman1"\n', "CWE-259"),
    # ALL-CAPS words not ending in a PEM block type are not a PEM label.
    ('def f():\n    secret_key = "TOP SECRET"\n', "CWE-321"),
])
def test_secret_shapes_fire_python(code, cwe):
    hits = _secrets("python", "py", code)
    assert hits, f"missed secret in {code!r}"
    if cwe is not None:
        assert hits[0].cwe_id == cwe


@pytest.mark.parametrize("lang,ext,code", [
    ("javascript", "js", 'function f() {\n  const password = "PROD_DB_PASS_2024";\n}\n'),
    ("javascript", "js", 'function f() {\n  const client_secret = "dev-client-secret";\n}\n'),
    ("java", "java", 'class C {\n  void f() {\n    String secret_key = "super-secret-key";\n  }\n}\n'),
])
def test_unrelated_identifier_value_fires_other_languages(lang, ext, code):
    assert _secrets(lang, ext, code), f"missed secret in {code!r} ({lang})"


# --- unit tests of the classifier itself -----------------------------------

@pytest.mark.parametrize("target,value", [
    ("ServiceAccountPrivateKeyName", "sa.key"),
    ("SSHAuthPrivateKey", "ssh-privatekey"),
    ("ECPrivateKeyBlockType", "EC PRIVATE KEY"),
    ("BootstrapTokenSecretKey", "token-secret"),
    ("private_key", "-----BEGIN RSA PRIVATE KEY-----"),
    ("private_key", "-----END CERTIFICATE-----"),
    ("private_key", "/etc/kubernetes/pki/sa.key"),
    ("signing_key", "./certs/signing.pem"),
    ("private_key", "~/.ssh/id_rsa"),
    ("private_key", "tls.crt"),
    ("SSH_PRIVATE_KEY_FILE", "id_rsa"),
    ("SECRET_KEY_ENV", "APP_SECRET_KEY"),
    ("secret_key", "<your-secret-key>"),
    ("secret_key", "${SECRET_KEY}"),
    ("CLIENT_SECRET_NAME", "kube-apiserver-client-kubelet"),
    ("privateKeyRef", "private-key-ref"),
    ("token_key", "token_id"),
    # Accepted cost: a value that only echoes the name stays silent.
    ("secret_key", "secret-key"),
])
def test_classifier_nonsecret(target, value):
    assert FrameScanner._is_nonsecret_value(target, value)


@pytest.mark.parametrize("target,value", [
    ("private_key", PEM_BODY), ("access_key", AWS_KEY),
    ("secret_key", "q8Vz3Lr0XkP2mT9wYb7NcD4hJ6sF1aGe"),
    ("aws_secret_access_key", "wJalrXUtnFEMI/" "K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("token", "xox" "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"),
    # Credential prefixes veto suppression at any length, even under a
    # descriptor-named target.
    ("api_key_name", "sk_live_short1"), ("token_field", "ghp_short"),
    ("token_var", "xoxp-abc"),
    ("password", "hunter2pass"), ("password", "S3cr3t!Passw0rd"),
    ("api_key", "sk_live_abcd1234"), ("signing_key", "mysupersecretkey"),
    ("SECRET_KEY", "super-secret-key"), ("SECRET_KEY", "secret-key-change-in-production"),
    ("SECRET_KEY", "django-insecure-abcdefghijklmnopqrstuvwxyz"),
    ("secret", "my-app-secret"), ("client_secret", "dev-client-secret"),
    ("jwt_secret", "jwt_secret_key"), ("password", "correct-horse-battery-staple"),
    ("password", "hunter2_pass"), ("password", "PROD_DB_PASS_2024"),
    ("password", "ADMIN_PASS"), ("password", "pass.word"), ("token", "abc.def.ghi"),
    ("password", "secret.txt"), ("password", "$ecret"), ("password", "$uperman1"),
    ("secret_key", "TOP SECRET"),
])
def test_classifier_not_nonsecret(target, value):
    assert not FrameScanner._is_nonsecret_value(target, value)


def test_name_tokens():
    assert FrameScanner._name_tokens("SSHAuthPrivateKey") == ["ssh", "auth", "private", "key"]
    assert FrameScanner._name_tokens("BOOTSTRAP_TOKEN_SECRET_KEY") == ["bootstrap", "token", "secret", "key"]
    assert FrameScanner._name_tokens("ecPrivateKey2Name") == ["ec", "private", "key2", "name"]
