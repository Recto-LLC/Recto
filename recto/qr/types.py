"""
recto.qr.types — wire-format dataclasses for QR-encoded signed payloads.

The QR-as-visual-transport primitive is downstream of Hard Rule #13
(docs/hard-rules.md): signed
payloads are portable artifacts — the bytes themselves are the
canonical record, NOT a row in any centralized database. QR codes
serve as one transport layer for those bytes (alongside HTTP and the
folder-drop event bus).

This module defines the shared envelope schema, one top-level shape:

  **QRPayloadV1** — generic signed-payload envelope. Used for
  single-signer artifacts (capability JWS, pairing JWS, manumission
  JWS, future-N). Body is kind-specific.

It carries a **_qr_meta** envelope describing how the payload
survives QR transport (format versioning, max-size bookkeeping,
fragmentation support for >2953-byte payloads). The QR's bytes are
the source of truth; metadata enables future format evolution
without breaking v1 readers.

See `recto/qr/SPEC.md` for the human-readable spec.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# QR version 40 at error-correction-level L holds up to 2953 bytes.
# This is the canonical upper bound for a single-QR payload; larger
# payloads must fragment across multiple QRs via _qr_meta.fragmentation.
QR_MAX_SIZE_BYTES_V40_L = 2953

# QR version 40 at error-correction-level M holds 2331 bytes.
QR_MAX_SIZE_BYTES_V40_M = 2331

# QR version 40 at error-correction-level Q holds 1663 bytes.
QR_MAX_SIZE_BYTES_V40_Q = 1663

# QR version 40 at error-correction-level H holds 1273 bytes.
QR_MAX_SIZE_BYTES_V40_H = 1273

# v1 schema versioning. Bumped only on breaking schema changes; additive
# field extensions stay at v1. Future v2 would land as a sibling
# QRPayloadV2 dataclass + version dispatch in encode/decode helpers.
QR_SCHEMA_VERSION = 1

# Canonical format-string for the _qr_meta.format field. Encodes:
#   - "qr"  the transport (QR code)
#   - "png" the rendering output (PNG image)
#   - "v1"  the schema version
QR_FORMAT_PNGV1 = "qr-pngv1"
QR_FORMAT_SVGV1 = "qr-svgv1"


@dataclass(frozen=True)
class QRMeta:
    """Transport metadata for a QR-encoded signed payload.

    Describes how the payload survives QR transport (format versioning,
    capacity bookkeeping, fragmentation for oversize payloads). NOT
    included in any signature — the QR's signature wraps the payload
    body, not the meta envelope.

    Future schema extensions (v2+) add fields here without breaking
    v1 readers; v1 readers ignore unknown fields.
    """

    # Format-string identifying the QR rendering output. v1 supports
    # "qr-pngv1" (PNG) and "qr-svgv1" (SVG). v2 may add "qr-pngv2"
    # for higher-density encodings or "qr-mp4v1" for animated QRs.
    format: str = QR_FORMAT_PNGV1

    # Max bytes the encoded payload can hold without requiring
    # fragmentation. Capped by QR_MAX_SIZE_BYTES_V40_L (2953) at the
    # most permissive error-correction level. Consumers may set
    # this lower at higher EC levels (M=2331, Q=1663, H=1273).
    max_size_bytes: int = QR_MAX_SIZE_BYTES_V40_L

    # Multi-QR fragmentation descriptor. None for single-QR payloads
    # (the common case). When set, indicates this QR is part `part` of
    # `of` in a sequence; consumers reassemble by concatenating
    # payloads in order. Reserved for future use — v1 single-QR
    # encoding is the supported path.
    fragmentation: dict[str, int] | None = None


@dataclass(frozen=True)
class QRPayloadV1:
    """Generic signed-payload envelope for single-signer QR artifacts.

    Used for capability JWS, pairing JWS, manumission JWS, citation
    receipts, THRU transaction receipts, and any future Recto-produced
    signed payload that fits the single-signer model. The signature
    over the canonical-JSON encoding of the WHOLE envelope (excluding
    `_qr_meta`) IS the artifact's authority chain back to the
    operator's master pubkey.

    Body shape is kind-specific. For capability JWS, body is typically
    a single field `{"jws": "<3-part JWS string>"}`. For richer
    kinds (citation receipts, promotion certificates), body carries
    the kind's full structured payload.
    """

    # Schema version. Always 1 for QRPayloadV1; future v2 lands as a
    # sibling dataclass with `v: int = 2`.
    v: int = QR_SCHEMA_VERSION

    # Canonical kind-key identifying the payload's semantic class.
    # Recto-side canonical kinds: "capability_request", "pairing_jws",
    # "manumission_jws", "citation_receipt", "thru_receipt",
    # "promotion_certificate", "agent_lease".
    # Downstream consumers may add their own kind-keys; uniqueness is
    # the only constraint.
    kind: str = ""

    # Issuer principal (RFC 7519 `iss` claim shape). Typically
    # "phone:operator:enclave" for operator-signed artifacts;
    # "agent:<id>" for agent-signed artifacts post-manumission.
    iss: str = ""

    # Audience principal list (RFC 7519 `aud` shape). Indicates which
    # consumers the artifact is intended for. Empty list = unscoped
    # (any consumer that can verify the signature can use).
    aud: tuple[str, ...] = ()

    # Issued-at unix timestamp (seconds since epoch, UTC).
    iat: int = 0

    # Expiration unix timestamp (seconds since epoch, UTC). 0 = never
    # expires. Trust artifacts that should outlive any platform's
    # runtime (THRU receipts, citation graphs, manumission JWS) set
    # this to 0; short-lived authority artifacts (capability_request)
    # set this to iat + N seconds.
    exp: int = 0

    # JWT ID — UUID for cross-instance uniqueness. Used by consumers
    # to detect replay attempts and to deduplicate during sync.
    jti: str = ""

    # Kind-specific body payload. Encoded as canonical JSON within
    # the signing input. Shape varies by `kind`; consumers dispatch
    # on `kind` to select the right body schema.
    body: dict[str, Any] = field(default_factory=dict)

    # Transport metadata. NOT signed. See QRMeta docstring.
    _qr_meta: QRMeta = field(default_factory=QRMeta)

