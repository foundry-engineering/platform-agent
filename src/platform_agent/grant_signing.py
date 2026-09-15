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


@dataclass(frozen=True, slots=True)
class ExecutionGrantSigner:
    """External signing adapter; private key material never enters Foundry documents."""

    kid: str
    sign: SignerCallback



def _protocol_runtime() -> tuple[GrantValidator, GrantPayloadHasher, GrantSigningMessage]:
    try:
        module = importlib.import_module("agent_protocol.execution_grant")
    except ModuleNotFoundError as exc:
        raise GrantSigningError("canonical signed Execution Grant contract is unavailable") from exc

    validator = getattr(module, "validate_execution_grant", None)
    payload_hasher = getattr(module, "execution_grant_signed_payload_sha256", None)
    signing_message = getattr(module, "execution_grant_signing_message", None)
    if not callable(validator) or not callable(payload_hasher) or not callable(signing_message):
        raise GrantSigningError("installed agent-protocol lacks signed-grant support")
    return (
        cast(GrantValidator, validator),
        cast(GrantPayloadHasher, payload_hasher),
        cast(GrantSigningMessage, signing_message),
    )


def sign_execution_grant(
    unsigned_grant: Mapping[str, Any],
    *,
    signers: Sequence[ExecutionGrantSigner],
) -> dict[str, object]:
    """Attach canonical Ed25519 signatures using external signing adapters."""
    if not signers:
        raise GrantSigningError("at least one execution-grant signer is required")

    kids = [signer.kid for signer in signers]
    if any(not kid for kid in kids) or len(kids) != len(set(kids)):
        raise GrantSigningError("execution-grant signer key ids must be non-empty and unique")

    document: dict[str, object] = dict(unsigned_grant)
    document.pop("signatures", None)
    validator, payload_hasher, signing_message = _protocol_runtime()
    payload_sha256 = payload_hasher(document)
    message = signing_message(document)

    signatures: list[dict[str, str]] = []
    for signer in sorted(signers, key=lambda item: item.kid):
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
    return document
