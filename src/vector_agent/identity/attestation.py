"""Attestation client (Part 2 §4): attest, revoke, contest and withdraw.

Also the COSE_Sign1 envelope of §4.2: :func:`envelope_sig_structure` gives the
bytes that the issuer key signs (Ed25519), and :func:`verify_envelope` checks
an attestation's ``envelope_sig``. The protected header uses RFC 8949 §4.2.1
core deterministic encoding; COSE_Sign1 and ``Sig_structure`` follow RFC 9052
§4.2–§4.4; the ``Ed25519`` algorithm value -19 is RFC 9864; the CWT claims
header (15) is RFC 9597; header parameters 258 and 259 are the COSE Hash
Envelope (draft-ietf-cose-hash-envelope).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import replace

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pycardano import Address, Asset, AssetName, MultiAsset, ScriptHash, TransactionOutput, Value
from pycardano.serialization import RawCBOR

from vector_agent.identity.constants import (
    ANCHOR_URI_MAX_BYTES,
    DAYS_90_MS,
    MIN_ATTESTATION_LOVELACE,
    PURPOSE_ASSERTION,
)
from vector_agent.identity.context import AuthenticOutput, IdentityContext
from vector_agent.identity.errors import IdentityLookupError, IdentityRuleError
from vector_agent.identity.ids import blake2b_224, key_hash, vector_did, vector_id_from_seed
from vector_agent.identity.rules import Effective, active_key, effective, validate_attestation
from vector_agent.identity.tx import (
    DEFAULT_VALID_FOR_S,
    BuiltTx,
    TxPlan,
    build,
    make_window,
    min_lovelace,
)
from vector_agent.identity.types import (
    ATT_ACTIVE,
    Anchor,
    AttActive,
    Attest,
    AttestationDatum,
    AttRevoked,
    Burn,
    Contest,
    Link,
    OutputReference,
    RevokeAtt,
    Withdraw,
)

__all__ = [
    "Attestations",
    "did_key",
    "envelope_protected_header",
    "envelope_sig_structure",
    "verify_envelope",
]

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = _BASE58[rest] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def did_key(public_key: bytes) -> str:
    """``did:key`` of an Ed25519 key: ``z`` + base58btc(0xed 0x01 || key) (W3C did:key v0.7)."""
    return "did:key:z" + _base58btc(b"\xed\x01" + bytes(public_key))


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * width):
            return bytes([(major << 5) | info]) + value.to_bytes(width, "big")
    raise IdentityRuleError("integer too large")


def _int(value: int) -> bytes:
    return _head(0, value) if value >= 0 else _head(1, -1 - value)


def _bstr(value: bytes) -> bytes:
    return _head(2, len(value)) + value


def _tstr(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _head(3, len(raw)) + raw


def _issuer_did(datum: AttestationDatum) -> tuple[str, str]:
    """The issuer DID and the kid of §4.2."""
    if datum.issuer_id is not None:
        did = vector_did(datum.issuer_id.hex())
        return did, f"{did}#{key_hash(datum.issuer)}"
    did = did_key(datum.issuer)
    return did, f"{did}#{did[len('did:key:'):]}"


def envelope_protected_header(datum: AttestationDatum) -> bytes:
    """The protected header of §4.2 in core deterministic encoding (keys 1, 4, 15, 258, 259)."""
    issuer, kid = _issuer_did(datum)
    claims = (
        _head(5, 3)
        + _int(1) + _tstr(issuer)
        + _int(2) + _tstr(vector_did(datum.subject.hex()))
        + _int(6) + _int(datum.issued_at // 1000)
    )
    entries = [
        _int(1) + _int(-19),
        _int(4) + _bstr(kid.encode("utf-8")),
        _int(15) + claims,
        _int(258) + _int(-16),
    ]
    if datum.format is not None:
        entries.append(_int(259) + _int(datum.format))
    return _head(5, len(entries)) + b"".join(entries)


def envelope_sig_structure(datum: AttestationDatum) -> bytes:
    """``Sig_structure = ["Signature1", protected, h'', digest]``: the bytes that the issuer signs."""
    return _head(4, 4) + _tstr("Signature1") + _bstr(envelope_protected_header(datum)) + _bstr(b"") + _bstr(
        datum.digest
    )


def verify_envelope(datum: AttestationDatum) -> bool:
    """True when ``envelope_sig`` is a valid Ed25519 signature of the issuer key (False when absent)."""
    if datum.envelope_sig is None:
        return False
    try:
        VerifyKey(datum.issuer).verify(envelope_sig_structure(datum), datum.envelope_sig)
    except (BadSignatureError, ValueError):
        return False
    return True


def _bytes32(value: str | bytes, name: str) -> bytes:
    raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    if len(raw) != 32:
        raise IdentityRuleError(f"{name}: expected 32 bytes")
    return raw


def withdrawable(datum: AttestationDatum, lo: int) -> bool:
    """Revoked with ``at + 90 days <= lo``, or ``valid_until + 90 days <= lo``."""
    revoked = isinstance(datum.status, AttRevoked) and datum.status.at + DAYS_90_MS <= lo
    expired = datum.valid_until is not None and datum.valid_until + DAYS_90_MS <= lo
    return revoked or expired


class Attestations:
    """Builders for the attestation contract, and attestation reads."""

    def __init__(self, ctx: IdentityContext) -> None:
        self.ctx = ctx

    def get(self, attestation_id: str | bytes) -> AuthenticOutput[AttestationDatum]:
        found = self.ctx.find_attestation(attestation_id)
        if found is None:
            name = attestation_id if isinstance(attestation_id, str) else attestation_id.hex()
            raise IdentityLookupError(f"no attestation {name}")
        return found

    def _output(self, attestation_id: bytes, datum: AttestationDatum, lovelace: int) -> TransactionOutput:
        script = self.ctx.scripts.attestation
        value = Value(lovelace, MultiAsset({ScriptHash(script.hash): Asset({AssetName(attestation_id): 1})}))
        return TransactionOutput(script.address, value, datum=RawCBOR(datum.to_cbor()))

    def _issuer_authority(self, plan: TxPlan, datum: AttestationDatum, by: str) -> None:
        if datum.issuer_id is None:
            if by != "issuer":
                raise IdentityRuleError("an attestation without issuer_id: only the issuer key acts")
            plan.require(blake2b_224(datum.issuer))
            return
        issuer = self.ctx.record(datum.issuer_id)
        plan.reference(issuer.utxo)
        if by == "controller":
            plan.require(blake2b_224(issuer.datum.controller))
        elif by == "issuer":
            if not active_key(issuer.datum, blake2b_224(datum.issuer), PURPOSE_ASSERTION):
                raise IdentityRuleError("the issuer key is no longer listed with the assertion purpose; act as controller")
            plan.require(blake2b_224(datum.issuer))
        else:
            raise IdentityRuleError("by is 'issuer' or 'controller'")

    def attest(
        self,
        funding_address: str | Address,
        *,
        subject: str | bytes,
        issuer: str | bytes,
        att_type: int,
        digest: bytes,
        issuer_id: str | bytes | None = None,
        format: int | None = None,
        profile: bytes | None = None,
        locator: str | bytes | None = None,
        valid_from: int | None = None,
        valid_until: int | None = None,
        solicited: bool = False,
        links: Sequence[Link] = (),
        sign_envelope: Callable[[bytes], bytes] | None = None,
        seed: OutputReference | None = None,
        deposit: int = MIN_ATTESTATION_LOVELACE,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Issue an attestation about ``subject``; the new token name is ``BuiltTx.created_id``.

        ``issuer`` is the issuer's Ed25519 public key; it signs the transaction.
        ``issued_at`` is the upper bound of the validity range. With
        ``sign_envelope``, the builder passes it the ``Sig_structure`` (§4.2)
        and stores the 64-byte Ed25519 signature that it returns.
        """
        ctx = self.ctx
        window = make_window(ctx, valid_for=valid_for)
        plan = TxPlan(window)
        if seed is None:
            utxos = ctx.ledger.context.utxos(ctx.address_of(funding_address))
            if not utxos:
                raise IdentityLookupError("the funding address has no output to use as a seed")
            seed_utxo = min(utxos, key=lambda u: (str(u.input.transaction_id), u.input.index))
        else:
            seed_utxo = ctx.ledger.utxo(seed)
            if seed_utxo is None:
                raise IdentityLookupError(f"the seed {seed} is spent or unknown")
        plan.add_input(seed_utxo)
        seed_ref = OutputReference(bytes(seed_utxo.input.transaction_id.payload), seed_utxo.input.index)
        attestation_id = bytes.fromhex(vector_id_from_seed(seed_ref.tx_id, seed_ref.index))
        plan.created_id = attestation_id

        issuer_key = bytes.fromhex(issuer) if isinstance(issuer, str) else bytes(issuer)
        subject_id = _bytes32(subject, "subject")
        subject_rec = ctx.record(subject_id)
        plan.reference(subject_rec.utxo)
        plan.require(blake2b_224(issuer_key))
        if solicited:
            plan.require(blake2b_224(subject_rec.datum.controller))
        issuer_ref = None
        if issuer_id is not None:
            issuer_ref = _bytes32(issuer_id, "issuer_id")
            issuer_rec = ctx.record(issuer_ref)
            ancestors = ctx.ancestors(issuer_rec.datum)
            plan.reference(issuer_rec.utxo, *(a.utxo for a in ancestors))
            if not active_key(issuer_rec.datum, blake2b_224(issuer_key), PURPOSE_ASSERTION):
                raise IdentityRuleError("the issuer record does not list the issuer key with the assertion purpose")
            find = {a.id: a.datum for a in ancestors}.get
            if effective(issuer_rec.datum, find, window.lo, window.hi) != Effective.ACTIVE:
                raise IdentityRuleError("the issuer record's effective status must be Active")
        datum = AttestationDatum(
            subject=subject_id,
            issuer=issuer_key,
            issuer_id=issuer_ref,
            att_type=att_type,
            format=format,
            profile=profile,
            digest=bytes(digest),
            locator=None if locator is None else (locator.encode() if isinstance(locator, str) else bytes(locator)),
            envelope_sig=None,
            issued_at=window.hi,
            valid_from=valid_from,
            valid_until=valid_until,
            solicited=solicited,
            status=ATT_ACTIVE,
            contested=None,
            links=tuple(links),
        )
        if sign_envelope is not None:
            signature = bytes(sign_envelope(envelope_sig_structure(datum)))
            datum = replace(datum, envelope_sig=signature)
            if not verify_envelope(datum):
                raise IdentityRuleError("sign_envelope did not return a valid Ed25519 signature of the issuer key")
        validate_attestation(datum)
        plan.mint(ctx.script_source("attestation"), {attestation_id: 1}, Attest(seed_ref))
        output = self._output(attestation_id, datum, deposit)
        floor = max(MIN_ATTESTATION_LOVELACE, min_lovelace(ctx, output))
        if deposit < floor:
            raise IdentityRuleError(f"an attestation holds at least {floor} base units")
        plan.output(output)
        return build(ctx, plan, funding_address)

    def revoke(
        self,
        funding_address: str | Address,
        attestation_id: str | bytes,
        *,
        reason: int,
        by: str = "issuer",
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """``RevokeAtt``: the status becomes ``AttRevoked { at: lo, reason }``.

        ``by`` is ``issuer`` (the issuer key) or ``controller`` (the controller
        of the registered issuer).
        """
        att = self.get(attestation_id)
        if not isinstance(att.datum.status, AttActive):
            raise IdentityRuleError("the attestation is already revoked")
        if not 0 <= reason < 1 << 63:
            raise IdentityRuleError("reason must be in [0, 2^63)")
        window = make_window(self.ctx, valid_for=valid_for)
        plan = TxPlan(window)
        self._issuer_authority(plan, att.datum, by)
        new = replace(att.datum, status=AttRevoked(window.lo, reason))
        plan.spend(att.utxo, self.ctx.script_source("attestation"), RevokeAtt(reason))
        plan.output(self._output(att.id, new, att.lovelace))
        return build(self.ctx, plan, funding_address)

    def contest(
        self,
        funding_address: str | Address,
        attestation_id: str | bytes,
        *,
        uri: str | bytes,
        sha256: bytes,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """``Contest``: the subject's controller anchors its reply (a URI and its SHA-256)."""
        att = self.get(attestation_id)
        anchor = Anchor(uri.encode() if isinstance(uri, str) else bytes(uri), bytes(sha256))
        if not 1 <= len(anchor.uri) <= ANCHOR_URI_MAX_BYTES or len(anchor.sha256) != 32:
            raise IdentityRuleError("the reply URI has 1..256 bytes and its SHA-256 32 bytes")
        window = make_window(self.ctx, valid_for=valid_for)
        plan = TxPlan(window)
        subject = self.ctx.record(att.datum.subject)
        plan.reference(subject.utxo)
        plan.require(blake2b_224(subject.datum.controller))
        new = replace(att.datum, contested=anchor)
        plan.spend(att.utxo, self.ctx.script_source("attestation"), Contest())
        plan.output(self._output(att.id, new, att.lovelace))
        return build(self.ctx, plan, funding_address)

    def withdraw(
        self,
        funding_address: str | Address,
        attestation_id: str | bytes,
        *,
        by: str = "issuer",
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """``Withdraw`` with ``Burn``: 90 days after revocation or expiry, the deposit returns."""
        att = self.get(attestation_id)
        window = make_window(self.ctx, valid_for=valid_for)
        if not withdrawable(att.datum, window.lo):
            raise IdentityRuleError("an attestation can be withdrawn 90 days after its revocation or its valid_until")
        plan = TxPlan(window)
        self._issuer_authority(plan, att.datum, by)
        source = self.ctx.script_source("attestation")
        plan.spend(att.utxo, source, Withdraw())
        plan.mint(source, {att.id: -1}, Burn())
        return build(self.ctx, plan, funding_address)
