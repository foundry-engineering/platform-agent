from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

import platform_agent.grant_signing as signing
from platform_agent.grant_signing import (
    ExecutionGrantSigner,
    GrantSigningError,
    sign_execution_grant,
)


def _grant() -> dict[str, object]:
    return {
        "schema_version": "execution-grant.v1",
        "grant_id": "sgr_" + "a" * 32,
        "task_id": "tsk_" + "b" * 32,
    }


def _install_protocol(
    monkeypatch: pytest.MonkeyPatch,
    *,
    verification_error: Exception | None = None,
) -> None:
    def validate(value: object) -> None:
        assert isinstance(value, dict)
        signatures = value.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            raise ValueError("missing signatures")
        for signature in signatures:
            assert isinstance(signature, dict)
            if signature.get("signed_sha256") != "c" * 64:
                raise ValueError("wrong payload")
            raw = base64.b64decode(str(signature.get("sig_b64")), validate=True)
            if len(raw) != 64:
                raise ValueError("bad signature")

    def verify(value: object, keys: object) -> tuple[str, ...]:
        if verification_error is not None:
            raise verification_error
        assert isinstance(keys, dict)
        assert all(isinstance(value, bytes) and len(value) == 32 for value in keys.values())
        return tuple(sorted(keys))

    monkeypatch.setattr(
        signing.importlib,
        "import_module",
        lambda name: SimpleNamespace(
            validate_execution_grant=validate,
            execution_grant_signed_payload_sha256=lambda value: "c" * 64,
            execution_grant_signing_message=lambda value: b"canonical-message",
            verify_execution_grant_signatures=verify,
        ),
    )


def _signer(kid: str, byte: bytes) -> ExecutionGrantSigner:
    return ExecutionGrantSigner(
        kid=kid,
        public_key=byte * 32,
        sign=lambda message: byte * 64,
    )


def test_external_signers_produce_sorted_verified_canonical_signatures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_protocol(monkeypatch)
    calls: list[bytes] = []

    def sign_a(message: bytes) -> bytes:
        calls.append(message)
        return b"a" * 64

    signed = sign_execution_grant(
        _grant(),
        signers=(
            _signer("kid_zeta.v1", b"z"),
            ExecutionGrantSigner(
                kid="kid_alpha.v1",
                public_key=b"a" * 32,
                sign=sign_a,
            ),
        ),
    )

    signatures = signed["signatures"]
    assert isinstance(signatures, list)
    assert [item["kid"] for item in signatures] == ["kid_alpha.v1", "kid_zeta.v1"]
    assert calls == [b"canonical-message"]


def test_no_signer_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch)
    with pytest.raises(GrantSigningError, match="at least one"):
        sign_execution_grant(_grant(), signers=())


def test_signer_requires_exact_raw_ed25519_public_key() -> None:
    with pytest.raises(ValueError, match="32 raw Ed25519 bytes"):
        ExecutionGrantSigner(kid="kid_bad.v1", public_key=b"short", sign=lambda message: b"x" * 64)


def test_duplicate_signer_key_ids_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch)
    signer = _signer("kid_same.v1", b"x")
    with pytest.raises(GrantSigningError, match="unique"):
        sign_execution_grant(_grant(), signers=(signer, signer))


def test_signer_output_must_be_exact_ed25519_length(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch)
    with pytest.raises(GrantSigningError, match="64-byte"):
        sign_execution_grant(
            _grant(),
            signers=(
                ExecutionGrantSigner(
                    kid="kid_short.v1",
                    public_key=b"x" * 32,
                    sign=lambda message: b"x",
                ),
            ),
        )


def test_signer_output_must_verify_cryptographically(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_protocol(monkeypatch, verification_error=ValueError("invalid signature"))
    with pytest.raises(GrantSigningError, match="cryptographic verification"):
        sign_execution_grant(_grant(), signers=(_signer("kid_test.v1", b"x"),))


def test_protocol_validation_failure_is_not_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        signing.importlib,
        "import_module",
        lambda name: SimpleNamespace(
            validate_execution_grant=lambda value: (_ for _ in ()).throw(ValueError("bad")),
            execution_grant_signed_payload_sha256=lambda value: "c" * 64,
            execution_grant_signing_message=lambda value: b"canonical-message",
            verify_execution_grant_signatures=lambda value, keys: tuple(sorted(keys)),
        ),
    )

    with pytest.raises(GrantSigningError, match="canonical validation"):
        sign_execution_grant(_grant(), signers=(_signer("kid_test.v1", b"x"),))
