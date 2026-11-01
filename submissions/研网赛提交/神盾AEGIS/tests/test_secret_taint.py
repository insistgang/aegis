import base64
import json
from urllib.parse import quote, quote_plus

import pytest

from aegis import features
from aegis.features import SecretRecord, carries_secret


AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
OPAQUE_SECRET = "opaque-river-lantern-7Qp9~"


def test_base64_of_observed_aws_key_is_tainted():
    record = SecretRecord(source="credentials", kind="observed", needles=[AWS_KEY])
    payload = base64.b64encode(AWS_KEY.encode()).decode()

    assert carries_secret([record], json.dumps({"payload": payload}))


def test_sensitive_env_retains_opaque_secret_and_complete_payload():
    text = f"PORT=8080\nAPP_SECRET={OPAQUE_SECRET}\nLOG_LEVEL=info\n"

    record = features.harvest_secret("env-result", text, "/work/.env")

    assert record is not None
    assert record.source == "env-result"
    assert record.path == "/work/.env"
    assert text in record.needles
    assert OPAQUE_SECRET in record.needles
    assert "8080" not in record.needles
    assert "info" not in record.needles
    assert carries_secret([record], json.dumps({"task": OPAQUE_SECRET}))
    assert not carries_secret([record], "Connect to port 8080; log level is info.")


def test_non_sensitive_prose_does_not_create_a_secret_record():
    assert features.harvest_secret("readme", "Use port 8080 and read the documentation.", "/work/README.md") is None


def test_existing_literal_and_sensitive_path_references_remain_tainted():
    record = SecretRecord(source="credentials", kind="observed", needles=[AWS_KEY], path="~/.aws/credentials")

    assert carries_secret([record], AWS_KEY)
    assert carries_secret([record], "Upload ~/.aws/credentials")
    assert not carries_secret([record], "Upload the public release notes")


def _b64(text):
    return base64.b64encode(text.encode()).decode()


@pytest.mark.parametrize(
    "encode",
    [
        _b64,
        lambda text: _b64(text).rstrip("="),
        lambda text: base64.urlsafe_b64encode(text.encode()).decode(),
        lambda text: base64.urlsafe_b64encode(text.encode()).decode().rstrip("="),
        lambda text: text.encode().hex(),
        lambda text: text.encode().hex().upper(),
        lambda text: quote(text, safe=""),
        quote_plus,
        lambda text: "".join(f"%{byte:02X}" for byte in text.encode()),
        lambda text: _b64(text.encode().hex()),
        lambda text: _b64(_b64(text)),
        lambda text: _b64(text).encode().hex(),
        lambda text: quote(_b64(text), safe=""),
    ],
)
def test_reversible_variants_of_opaque_value_are_tainted(encode):
    secret = "vault:??>>/secret word-7Qp9~"
    record = features.harvest_secret("env", f'APP_SECRET="{secret}"\nPORT=8080\n', "/app/.env")

    payload = encode(secret)
    assert carries_secret([record], json.dumps({"payload": payload}))
    cleaned = features.redact_session({"payload": payload, "safe": "public documentation"}, [record])
    assert payload not in cleaned["payload"]
    assert cleaned["safe"] == "public documentation"


@pytest.mark.parametrize(
    "payload",
    [
        json.dumps({"parts": [AWS_KEY[:9], AWS_KEY[9:]]}),
        f"send('{AWS_KEY[:9]}' + '{AWS_KEY[9:]}')",
        json.dumps({"payload": AWS_KEY}).replace("AKIA", "\\u0041\\u004b\\u0049\\u0041"),
        f'{{"payload": "{_b64(AWS_KEY)[:10]}" + "{_b64(AWS_KEY)[10:]}"}}',
    ],
)
def test_split_and_escaped_literals_are_tainted_without_execution(payload):
    record = SecretRecord(source="aws", kind="observed", needles=[AWS_KEY])

    assert carries_secret([record], payload)


@pytest.mark.parametrize(
    ("path", "text", "secret"),
    [
        ("/app/.env", f'export API_TOKEN="{OPAQUE_SECRET}" # local only\nPORT=8080', OPAQUE_SECRET),
        ("~/.aws/credentials", f"[service]\npassword: {OPAQUE_SECRET}\nport = 8080", OPAQUE_SECRET),
        ("/app/credentials.json", json.dumps({"credentials": {"opaque": OPAQUE_SECRET}, "port": 8080}), OPAQUE_SECRET),
        ("/app/.env", "PRIVATE_TOKEN='opaque-line-one\nopaque-line-two'\nPORT=8080", "opaque-line-one\nopaque-line-two"),
    ],
)
def test_sensitive_configuration_values_are_parsed_without_comments(path, text, secret):
    record = features.harvest_secret("config", text, path)

    assert secret in record.needles
    assert "8080" not in record.needles
    assert carries_secret([record], secret)


def test_recursive_redaction_covers_full_returns_variants_keys_and_split_arrays():
    text = f"PORT=8080\nAPP_SECRET={OPAQUE_SECRET}\n"
    record = features.harvest_secret("config", text, "/app/.env")
    original = {
        "return": text,
        "nested": [{"base64": _b64(OPAQUE_SECRET)}, {"hex": OPAQUE_SECRET.encode().hex()}],
        "split": [OPAQUE_SECRET[:12], OPAQUE_SECRET[12:]],
        OPAQUE_SECRET: "value under a sensitive key",
        "benign": "Connect to port 8080 and read the documentation.",
    }

    cleaned = features.redact_session(original, [record])
    blob = json.dumps(cleaned)

    assert OPAQUE_SECRET not in blob
    assert _b64(OPAQUE_SECRET) not in blob
    assert OPAQUE_SECRET.encode().hex() not in blob
    assert OPAQUE_SECRET[:12] not in blob
    assert OPAQUE_SECRET[12:] not in blob
    assert cleaned["benign"] == original["benign"]
    assert original["return"] == text


def test_redaction_covers_escaped_and_split_scalar_strings():
    record = SecretRecord(source="aws", kind="observed", needles=[AWS_KEY])
    escaped = "".join(f"\\u{ord(char):04x}" for char in AWS_KEY)
    payload = {"escaped": escaped, "concat": f"'{AWS_KEY[:10]}' + '{AWS_KEY[10:]}'", "safe": "ordinary notes"}

    cleaned = features.redact_session(payload, [record])

    assert AWS_KEY[:10] not in cleaned["concat"]
    assert escaped not in cleaned["escaped"]
    assert cleaned["safe"] == "ordinary notes"


def test_redaction_keeps_existing_pattern_protection_without_session_records():
    cleaned = features.redact_session({"token": AWS_KEY, "safe": "public documentation"}, [])

    assert cleaned == {"token": "«redacted»", "safe": "public documentation"}


def test_innocent_prose_is_not_fragmented_into_universal_taint():
    record = features.harvest_secret("sensitive-note", "Read the public deployment documentation before proceeding.\n", "/app/.env")

    assert not carries_secret([record], "Read the public deployment documentation")
    assert not carries_secret([record], _b64("deployment documentation"))
    assert features.redact_session({"note": "public deployment documentation", "port": "8080"}, [record]) == {
        "note": "public deployment documentation", "port": "8080"
    }


@pytest.mark.parametrize(
    "payload",
    [
        "".join(char.upper() if index % 3 else char.lower() for index, char in enumerate(AWS_KEY.encode().hex())),
        "\n".join([_b64(AWS_KEY)[:12], _b64(AWS_KEY)[12:]]),
    ],
)
def test_standard_hex_case_and_base64_line_wrapping_are_normalized(payload):
    record = SecretRecord(source="aws", kind="observed", needles=[AWS_KEY])

    assert carries_secret([record], json.dumps({"payload": payload}))
    assert features.redact_session({"payload": payload}, [record])["payload"] == "«redacted»"


def test_double_quoted_env_escapes_are_decoded_but_single_quoted_values_are_literal():
    text = 'PRIVATE_TOKEN="opaque-line-one\\nopaque-line-two"\nAPI_KEY=\'opaque\\n-literal-value\''

    record = features.harvest_secret("env", text, "/app/.env")

    assert "opaque-line-one\nopaque-line-two" in record.needles
    assert "opaque\\n-literal-value" in record.needles


def test_deeply_malformed_configuration_remains_a_full_payload_without_crashing():
    text = "[" * 1500 + '"not-a-credential"' + "]" * 1500

    record = features.harvest_secret("env", text, "/app/.env")

    assert text in record.needles
    assert carries_secret([record], json.dumps({"payload": text}))


@pytest.mark.parametrize("secret", ["fox", "p4ss!", "7"])
def test_short_credential_scalars_and_encodings_are_protected_without_substring_taint(secret):
    record = features.harvest_secret("env", f"PASSWORD={secret}\nPORT=8080\n", "/app/.env")

    assert secret in record.needles
    assert "8080" not in record.needles
    assert carries_secret([record], json.dumps({"payload": secret}))
    assert carries_secret([record], json.dumps({"payload": _b64(secret)}))
    assert not carries_secret([record], f"The pre{secret}suffix release uses port 8080.")
    cleaned = features.redact_session({"payload": secret, "safe": f"pre{secret}suffix", "port": "8080"}, [record])
    assert cleaned["payload"] == "«redacted»"
    assert cleaned["safe"] == f"pre{secret}suffix"
    assert cleaned["port"] == "8080"


def test_secret_dictionary_keys_do_not_overwrite_each_other_or_existing_public_keys():
    record = SecretRecord(source="env", kind="observed", needles=[OPAQUE_SECRET])
    payload = {
        OPAQUE_SECRET: "raw-key-value",
        _b64(OPAQUE_SECRET): "encoded-key-value",
        "«redacted»": "public-key-value",
        "«redacted» [2]": "another-public-key-value",
        "safe": "ordinary notes",
    }

    cleaned = features.redact_session(payload, [record])

    assert len(cleaned) == len(payload)
    assert set(cleaned.values()) == set(payload.values())
    assert cleaned["«redacted»"] == "public-key-value"
    assert cleaned["«redacted» [2]"] == "another-public-key-value"
    assert cleaned["safe"] == "ordinary notes"
    assert not carries_secret([record], json.dumps(cleaned))


@pytest.mark.parametrize(
    "payload",
    [
        {OPAQUE_SECRET[:11]: 1, OPAQUE_SECRET[11:]: 2, "safe": "ordinary notes"},
        {OPAQUE_SECRET[:11]: OPAQUE_SECRET[11:], "safe": "ordinary notes"},
        {"outer": {OPAQUE_SECRET[:11]: 1, OPAQUE_SECRET[11:]: 2}, "safe": "ordinary notes"},
    ],
)
def test_reconstructable_secrets_split_across_keys_and_values_are_redacted(payload):
    record = SecretRecord(source="env", kind="observed", needles=[OPAQUE_SECRET])

    assert carries_secret([record], json.dumps(payload))
    cleaned = features.redact_session(payload, [record])

    assert not carries_secret([record], json.dumps(cleaned))
    assert cleaned["safe"] == "ordinary notes"


@pytest.mark.parametrize(
    "encoded",
    [
        "".join(f"\\u{ord(char):04x}" for char in OPAQUE_SECRET),
        "".join(f"%{byte:02X}" for byte in OPAQUE_SECRET.encode()),
        "".join(char.upper() if index % 3 else char.lower() for index, char in enumerate(OPAQUE_SECRET.encode().hex())),
    ],
)
def test_split_encoded_or_escaped_fragments_do_not_survive_recursive_redaction(encoded):
    record = SecretRecord(source="env", kind="observed", needles=[OPAQUE_SECRET])
    payload = {"parts": [encoded[:13], encoded[13:]], "safe": "ordinary notes"}

    assert carries_secret([record], json.dumps(payload))
    cleaned = features.redact_session(payload, [record])

    assert not carries_secret([record], json.dumps(cleaned))
    assert cleaned["safe"] == "ordinary notes"
