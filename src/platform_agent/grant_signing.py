from __future__ import annotations

import base64
import importlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast


class GrantSigningError(RuntimeError):
    """Raised when execution authority cannot be signed canonically."""


SignerCallback = Callable[[bytes], bytes]
GrantValidator = Callable[[object], None]
GrantPayloadHasher = Callable[[object], str]
GrantSigningMessage = Callable[[object], bytes]
GrantSignatureVerifier = Callable[[object, Mapping[str, bytes]], tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class ExecutionGrantSigner:
    """External signing adapter; private key material never enters Foundry documents.

    ``public_key`` is the raw 32-byte Ed25519 public key corresponding to the
    external signer.  Foundry verifies the returned signature immediately before
    issuing authority so a broken/misconfigured HSM/KMS cannot emit unusable or
    falsely trusted grants.
    """

    kid: str
    public_key: bytes
    sign: SignerCallback

    def __post_init__(self) -> None:
        if not self.kid:
            raise ValueError("execution-grant signer key id must not be empty")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("execution-grant signer public key must be 32 raw Ed25519 bytes")


def _protocol_runtime() -> tuple[
    GrantValidator,
    GrantPayloadHasher,
    GrantSigningMessage,
    GrantSignatureVerifier,
]:
    try:
        module = importlib.import_module("agent_protocol.execution_grant")
    except ModuleNotFoundError as exc:
        raise GrantSigningError("canonical signed Execution Grant contract is unavailable") from exc

    validator = getattr(module, "validate_execution_grant", None)
    payload_hasher = getattr(module, "execution_grant_signed_payload_sha256", None)
    signing_message = getattr(module, "execution_grant_signing_message", None)
    signature_verifier = getattr(module, "verify_execution_grant_signatures", None)
    if (
        not callable(validator)
        or not callable(payload_hasher)
        or not callable(signing_message)
        or not callable(signature_verifier)
    ):
        raise GrantSigningError("installed agent-protocol lacks signed-grant support")
    return (
        cast(GrantValidator, validator),
        cast(GrantPayloadHasher, payload_hasher),
        cast(GrantSigningMessage, signing_message),
        cast(GrantSignatureVerifier, signature_verifier),
    )


def sign_execution_grant(
    unsigned_grant: Mapping[str, Any],
    *,
    signers: Sequence[ExecutionGrantSigner],
) -> dict[str, object]:
    """Attach and independently verify canonical Ed25519 signatures.

    Signers may live behind customer-controlled HSM/KMS services.  Foundry does
    not trust the signing service response merely because it is 64 bytes; every
    returned signature is verified against the signer's configured public key
    before the grant is returned to callers.
    """
    if not signers:
        raise GrantSigningError("at least one execution-grant signer is required")

    kids = [signer.kid for signer in signers]
    if len(kids) != len(set(kids)):
        raise GrantSigningError("execution-grant signer key ids must be unique")

    document: dict[str, object] = dict(unsigned_grant)
    document.pop("signatures", None)
    validator, payload_hasher, signing_message, signature_verifier = _protocol_runtime()
    payload_sha256 = payload_hasher(document)
    message = signing_message(document)

    ordered_signers = tuple(sorted(signers, key=lambda item: item.kid))
    signatures: list[dict[str, str]] = []
    for signer in ordered_signers:
        try:
            signature = signer.sign(message)
        except Exception as exc:
            raise GrantSigningError(f"execution-grant signer failed: {signer.kid}") from exc
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise GrantSigningError(
                f"execution-grant signer must return a 64-byte Ed25519 signature: {signer.kid}"
            )
        signatures.append(
            {
                "kid": signer.kid,
                "alg": "ed25519",
                "signed_sha256": payload_sha256,
                "sig_b64": base64.b64encode(signature).decode("ascii"),
            }
        )

    document["signatures"] = signatures
    try:
        validator(document)
    except Exception as exc:
        raise GrantSigningError("signed Execution Grant failed canonical validation") from exc

    trusted_keys = {signer.kid: signer.public_key for signer in ordered_signers}
    try:
        verified = signature_verifier(document, trusted_keys)
    except Exception as exc:
        raise GrantSigningError("execution-grant signer output failed cryptographic verification") from exc

    expected_kids = tuple(signer.kid for signer in ordered_signers)
    if tuple(verified) != expected_kids:
        raise GrantSigningError("execution-grant signature verification set does not match signers")
    return document
