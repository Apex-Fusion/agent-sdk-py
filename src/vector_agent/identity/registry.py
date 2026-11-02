"""Identity registry client: every operation of Part 1 §6 and Part 2 §3.

Each builder reads the current record, applies the rule of its row in the
Part 2 §3.5 table, and returns an unsigned :class:`~vector_agent.identity.tx.BuiltTx`
with the key hashes that must sign. The builders check the contract rules
first and raise ``ValueError`` with the broken rule, so a transaction that the
contract would reject is not built.

Reads: :meth:`IdentityRegistry.record` reads the record output from the
ledger (Koios and Ogmios); :meth:`IdentityRegistry.resolve` and
:meth:`IdentityRegistry.current_record` use the gateway's HTTPS binding.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace

from pycardano import (
    Address,
    Asset,
    AssetName,
    MultiAsset,
    Network,
    ScriptHash,
    TransactionOutput,
    UTxO,
    Value,
    VerificationKeyHash,
)
from pycardano.serialization import RawCBOR

from vector_agent.identity.constants import (
    DAYS_7_MS,
    DAYS_30_MS,
    LEGACY_OWNER_CHANGE_LOVELACE,
    MAX_DEPTH,
    MIN_RECORD_LOVELACE,
    REASON_DISPUTE_VERDICT,
    REASON_KEY_COMPROMISE,
    REVOKE_REASONS,
    RIGHT_REVOKE,
    RIGHT_SUSPEND,
    ROLE_MAX_RIGHTS,
    SUSPEND_REASONS,
)
from vector_agent.identity.context import AuthenticOutput, IdentityContext, datum_bytes, utxo_ref
from vector_agent.identity.errors import IdentityLookupError, IdentityRuleError
from vector_agent.identity.gateway import AgentView, DidResolution
from vector_agent.identity.ids import (
    allowlist_proof,
    blake2b_224,
    blake2b_256,
    vector_id_from_seed,
    verify_allowlist_proof,
)
from vector_agent.identity.plutus_data import Constr
from vector_agent.identity.rules import (
    Effective,
    accountable,
    covers,
    effective,
    eligible_guardian,
    guardian_bound,
    has_right,
    holds_of,
    kept_holds,
    terminal,
    tombstone,
    validate_identity_datum,
)
from vector_agent.identity.tx import (
    DEFAULT_VALID_FOR_S,
    BuiltTx,
    TxPlan,
    Window,
    build,
    make_window,
    min_lovelace,
)
from vector_agent.identity.types import (
    ACTIVE,
    BY_CONTROLLER,
    CONTROLLER_SET,
    ROOT,
    Adopt,
    ByParty,
    ControllerSetSigner,
    Hold,
    IdentityDatum,
    IdentitySpend,
    Key,
    KeyCredential,
    KeyHashSigner,
    KeyType,
    LegacyDatum,
    OutputReference,
    Party,
    PendingRecovery,
    Register,
    Retired,
    Revoked,
    Role,
    ScriptSigner,
    Signer,
    Subagent,
    Suspended,
)

__all__ = ["IdentityRegistry", "PartySpec", "ed25519_key", "p256_key", "p256_pop_message"]

#: Module-1 ``identity_party`` withdraw redeemer ``PartyApproval.Consent``.
MODULE1_CONSENT = Constr(0)
#: Legacy registry redeemers: spend ``Deregister``, mint ``Burn``.
LEGACY_DEREGISTER = Constr(1)
LEGACY_BURN = Constr(1)


def _text(value: str | bytes, name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError(f"{name}: expected str or bytes")


def _id(value: str | bytes, name: str = "identifier") -> bytes:
    raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    if len(raw) != 32:
        raise IdentityRuleError(f"{name}: expected 32 bytes (64 hexadecimal characters)")
    return raw


def _public_key(value: str | bytes, name: str) -> bytes:
    raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
    if len(raw) != 32:
        raise IdentityRuleError(f"{name}: expected a 32-byte Ed25519 public key")
    return raw


def ed25519_key(public_key: str | bytes, purposes: int) -> Key:
    """A listed Ed25519 key. ``purposes`` is a sum of 1, 2, 8 and 16."""
    return Key(KeyType.ED25519, _public_key(public_key, "public_key"), purposes)


def p256_key(public_key: str | bytes, pop: str | bytes, purposes: int) -> Key:
    """A listed P-256 key (33-byte compressed point) with its proof of possession."""
    point = bytes.fromhex(public_key) if isinstance(public_key, str) else bytes(public_key)
    proof = bytes.fromhex(pop) if isinstance(pop, str) else bytes(pop)
    return Key(KeyType.P256, point, purposes, proof)


def p256_pop_message(vector_id: str, public_key: bytes) -> bytes:
    """The UTF-8 bytes that a P-256 key signs (ES256) as ``pop`` (Part 1 §5)."""
    return f"did:vector:{vector_id}#{blake2b_224(bytes(public_key)).hex()}".encode()


@dataclass(frozen=True)
class PartySpec:
    """A new party. ``rights`` defaults to the role's highest rights, ``not_before``
    to the lower bound of the transaction's validity range (so the party covers it)."""

    role: Role
    signer: Signer
    rights: int | None = None
    organisation: str | bytes | None = None
    not_before: int | None = None
    not_after: int | None = None
    removal_after: int | None = None

    def to_party(self, lo: int) -> Party:
        return Party(
            role=self.role,
            signer=self.signer,
            organisation=None if self.organisation is None else _text(self.organisation, "organisation"),
            not_before=lo if self.not_before is None else self.not_before,
            not_after=self.not_after,
            rights=ROLE_MAX_RIGHTS[self.role] if self.rights is None else self.rights,
            removal_after=self.removal_after,
        )


def _parties(parties: Sequence[Party | PartySpec], lo: int) -> tuple[Party, ...]:
    return tuple(p.to_party(lo) if isinstance(p, PartySpec) else p for p in parties)


def _same(left: Party, right: Party) -> bool:
    return left.role == right.role and left.signer == right.signer


def _notice_only(old: Party, new: Party, hi: int) -> bool:
    return (
        old.removal_after is None
        and new.removal_after is not None
        and new.removal_after >= hi + DAYS_7_MS
        and replace(old, removal_after=new.removal_after) == new
    )


class IdentityRegistry:
    """Builders for every identity-registry operation, and the record reads."""

    def __init__(self, ctx: IdentityContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def record(self, vector_id: str | bytes) -> AuthenticOutput[IdentityDatum]:
        """The current record output (live record or tombstone) from the ledger."""
        return self.ctx.record(vector_id)

    def resolve(self, did: str, **options) -> DidResolution:
        """DID resolution through the gateway (Part 1 §7.4); see ``IdentityGateway.resolve``."""
        return self.ctx.gateway.resolve(did, **options)

    def current_record(self, agent: str) -> AgentView:
        """The gateway's view of an agent without version options (Part 1 §7.2–§7.3)."""
        return self.ctx.gateway.current_record(agent)

    def next_identifier(self, funding_address: str | Address) -> tuple[OutputReference, str]:
        """A seed from the funding address and the identifier that a registration with it gets.

        Use it when keys must sign over the identifier before the registration (P-256 ``pop``).
        """
        utxos = self.ctx.ledger.context.utxos(self.ctx.address_of(funding_address))
        if not utxos:
            raise IdentityLookupError("the funding address has no output to use as a seed")
        seed = min(utxos, key=lambda u: (str(u.input.transaction_id), u.input.index))
        ref = utxo_ref(seed)
        return ref, vector_id_from_seed(ref.tx_id, ref.index)

    # ------------------------------------------------------------------
    # Shared steps
    # ------------------------------------------------------------------

    def _ok(self, plan: TxPlan, signer: Signer, controller: bytes, what: str) -> None:
        """Require the signature that ``ok(signer)`` needs (key hash or controller)."""
        if isinstance(signer, KeyHashSigner):
            plan.require(signer.hash)
        elif isinstance(signer, ControllerSetSigner):
            plan.require(blake2b_224(controller))
        else:
            raise IdentityRuleError(f"{what}: Module-1 acts only through its own verdict transactions")

    def _record_output(
        self, plan: TxPlan, vector_id: bytes, datum: IdentityDatum, lovelace: int, *, live_floor: bool
    ) -> None:
        scripts = self.ctx.scripts
        m1 = None
        if any(isinstance(p.signer, ScriptSigner) for p in datum.parties):
            config = self.ctx.config_record
            if config is None:
                raise IdentityLookupError("the record names Module-1, but the configuration record is missing")
            plan.reference(config[0])
            m1 = config[1]
        validate_identity_datum(datum, m1)
        value = Value(
            lovelace, MultiAsset({ScriptHash(scripts.identity.hash): Asset({AssetName(vector_id): 1})})
        )
        output = TransactionOutput(scripts.identity.address, value, datum=RawCBOR(datum.to_cbor()))
        floor = max(min_lovelace(self.ctx, output), MIN_RECORD_LOVELACE if live_floor else 0)
        if lovelace < floor:
            raise IdentityRuleError(f"the record output needs at least {floor} base units, got {lovelace}")
        plan.output(output)

    def _min_record_lovelace(self, vector_id: bytes, datum: IdentityDatum) -> int:
        scripts = self.ctx.scripts
        value = Value(0, MultiAsset({ScriptHash(scripts.identity.hash): Asset({AssetName(vector_id): 1})}))
        return min_lovelace(
            self.ctx, TransactionOutput(scripts.identity.address, value, datum=RawCBOR(datum.to_cbor()))
        )

    def _creation_checks(self, plan: TxPlan, record: IdentityDatum, window: Window) -> None:
        """Rules 4–8 of Register (Part 2 §3.4): status, accountability, guardians, signatures."""
        if not accountable(record, window.lo, window.hi):
            raise IdentityRuleError("the record needs an Accountable Party that covers the validity range "
            f"[{window.lo}, {window.hi}]")
        if not guardian_bound(record, window.hi):
            raise IdentityRuleError("guardian_threshold exceeds the guardians with the recover right")
        plan.require(blake2b_224(record.controller))
        for key in record.keys:
            if key.key_type == KeyType.ED25519:
                plan.require(blake2b_224(key.key))
        for party in record.parties:
            if isinstance(party.signer, ScriptSigner):
                self._module1_consent(plan, party, window)
            else:
                self._ok(plan, party.signer, record.controller, "party")

    def _module1_consent(self, plan: TxPlan, party: Party, window: Window) -> None:
        """Module-1 becomes a party: its withdraw handler approves with ``Consent``."""
        m1 = self.ctx.module1
        if m1 is None or party.signer != ScriptSigner(m1):
            raise IdentityRuleError("a script party must be the approved Module-1 contract")
        if party.role not in (Role.ACCOUNTABLE, Role.RESPONSIBLE):
            raise IdentityRuleError("Module-1 can be only an Accountable or a Responsible Party")
        if (
            party.rights != ROLE_MAX_RIGHTS[party.role]
            or party.not_before > window.lo
            or party.not_after is not None
            or party.removal_after is not None
        ):
            raise IdentityRuleError("Module-1 consents only with the role's highest rights, not_before <= lo, "
            "no not_after and no removal_after")
        if not plan.withdrawals:
            plan.withdraw_zero(self.ctx.module1_source(), MODULE1_CONSENT)

    def _identity_spend(
        self, vector_id: str | bytes, valid_for: int, *, allow_terminal: bool = False, live_only: bool = True
    ) -> tuple[AuthenticOutput[IdentityDatum], Window, TxPlan]:
        rec = self.ctx.record(vector_id)
        if terminal(rec.datum.status) and not allow_terminal:
            raise IdentityRuleError("the record is a tombstone: only Reclaim and SetSuccessor are allowed")
        if live_only is False and not terminal(rec.datum.status):
            raise IdentityRuleError("the record is live: this action needs a tombstone")
        window = make_window(self.ctx, valid_for=valid_for)
        return rec, window, TxPlan(window)

    def _finish_spend(
        self,
        funding_address: str | Address,
        plan: TxPlan,
        rec: AuthenticOutput[IdentityDatum],
        redeemer: IdentitySpend,
        new: IdentityDatum,
        lovelace: int,
        *,
        live_floor: bool,
    ) -> BuiltTx:
        plan.spend(rec.utxo, self.ctx.script_source("identity"), redeemer)
        self._record_output(plan, rec.id, new, lovelace, live_floor=live_floor)
        return build(self.ctx, plan, funding_address)

    def _successor(self, plan: TxPlan, successor: str | bytes, vector_id: bytes) -> bytes:
        s = _id(successor, "successor")
        if s == vector_id:
            raise IdentityRuleError("a record cannot be its own successor")
        rec = self.ctx.record(s)
        if not isinstance(rec.datum.lineage, type(ROOT)) or terminal(rec.datum.status):
            raise IdentityRuleError("the successor must be a live record without a parent")
        plan.reference(rec.utxo)
        plan.require(blake2b_224(rec.datum.controller))
        return s

    def _lineage_find(self, refs: list[AuthenticOutput[IdentityDatum]]):
        by_id = {r.id: r.datum for r in refs}
        return by_id.get

    # ------------------------------------------------------------------
    # Create (Part 2 §3.4)
    # ------------------------------------------------------------------

    def register(
        self,
        funding_address: str | Address,
        *,
        controller: str | bytes,
        name: str | bytes,
        parties: Sequence[Party | PartySpec],
        keys: Sequence[Key] = (),
        description: str | bytes = b"",
        framework: str | bytes = b"",
        endpoint: str | bytes = b"",
        capabilities: Sequence[str | bytes] = (),
        guardian_threshold: int = 0,
        parent: str | bytes | None = None,
        seed: OutputReference | None = None,
        deposit: int = MIN_RECORD_LOVELACE,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Register a new record; with ``parent``, a subagent of that record.

        The seed is an output of the funding address (or ``seed``); the new
        identifier is in ``BuiltTx.created_id``.
        """
        ctx = self.ctx
        window = make_window(ctx, valid_for=valid_for)
        plan = TxPlan(window)
        if seed is None:
            seed, _ = self.next_identifier(funding_address)
        seed_utxo = ctx.ledger.utxo(seed)
        if seed_utxo is None:
            raise IdentityLookupError(f"the seed {seed} is spent or unknown")
        plan.add_input(seed_utxo)
        vector_id = bytes.fromhex(vector_id_from_seed(seed.tx_id, seed.index))
        plan.created_id = vector_id

        lineage = ROOT
        if parent is not None:
            parent_rec = ctx.record(_id(parent, "parent"))
            ancestors = ctx.ancestors(parent_rec.datum)
            find = self._lineage_find(ancestors)
            if effective(parent_rec.datum, find, window.lo, window.hi) != Effective.ACTIVE:
                raise IdentityRuleError("the parent's effective status must be Active")
            depth = (parent_rec.datum.lineage.depth if isinstance(parent_rec.datum.lineage, Subagent) else 0) + 1
            if depth > MAX_DEPTH:
                raise IdentityRuleError("a subagent is at most 4 levels below its root")
            lineage = Subagent(parent_rec.id, parent_rec.datum.subagent_epoch, depth)
            plan.reference(parent_rec.utxo, *(a.utxo for a in ancestors))
            plan.require(blake2b_224(parent_rec.datum.controller))

        record = IdentityDatum(
            controller=_public_key(controller, "controller"),
            keys=tuple(keys),
            parties=_parties(parties, window.lo),
            guardian_threshold=guardian_threshold,
            pending_recovery=None,
            lineage=lineage,
            subagent_epoch=0,
            name=_text(name, "name"),
            description=_text(description, "description"),
            framework=_text(framework, "framework"),
            endpoint=_text(endpoint, "endpoint"),
            capabilities=tuple(_text(c, "capability") for c in capabilities),
            created_at=window.hi,
            status=ACTIVE,
        )
        self._creation_checks(plan, record, window)
        plan.mint(ctx.script_source("identity"), {vector_id: 1}, Register(seed))
        self._record_output(plan, vector_id, record, deposit, live_floor=True)
        return build(ctx, plan, funding_address)

    def adopt(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        controller: str | bytes,
        parties: Sequence[Party | PartySpec],
        keys: Sequence[Key] = (),
        proof: Sequence[bytes] | None = None,
        allowlist: Sequence[str] | None = None,
        name: str | bytes | None = None,
        description: str | bytes | None = None,
        framework: str | bytes | None = None,
        endpoint: str | bytes | None = None,
        capabilities: Sequence[str | bytes] | None = None,
        guardian_threshold: int = 0,
        owner_address: str | Address | None = None,
        legacy_datum: bytes | None = None,
        deposit: int = MIN_RECORD_LOVELACE,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Move a legacy record to the identity registry (Part 2 §3.4 ``Adopt``).

        The profile comes from the legacy record unless given. ``proof`` is the
        allowlist Merkle proof; or pass the published ``allowlist`` to compute it.
        The legacy deposit goes to ``owner_address`` (default: the enterprise
        address of the legacy owner key), at least 10 AP3X as the legacy
        Deregister rule requires.
        """
        ctx = self.ctx
        scripts = ctx.scripts
        vid = _id(vector_id)
        if proof is None:
            if allowlist is None:
                raise IdentityRuleError("give the allowlist proof or the allowlist")
            proof = allowlist_proof(allowlist, vid.hex())
        proof = tuple(bytes(p) for p in proof)
        if not verify_allowlist_proof(scripts.legacy_root, vid.hex(), proof):
            raise IdentityRuleError("the identifier is not on the allowlist of this deployment (proof fails)")

        legacy = self._legacy_record(vid)
        raw = datum_bytes(legacy)
        if raw is None:
            if legacy_datum is None:
                raise IdentityRuleError("the legacy record has no inline datum: pass legacy_datum (its CBOR)")
            if blake2b_256(legacy_datum) != bytes(legacy.output.datum_hash.payload):
                raise IdentityRuleError("legacy_datum does not match the datum hash of the legacy record")
            raw = legacy_datum
        old = LegacyDatum.from_cbor(raw)
        if not isinstance(old.owner, KeyCredential):
            raise IdentityRuleError("the legacy owner is a script: it cannot sign the adoption")

        window = make_window(ctx, valid_for=valid_for)
        plan = TxPlan(window)
        plan.created_id = vid
        record = IdentityDatum(
            controller=_public_key(controller, "controller"),
            keys=tuple(keys),
            parties=_parties(parties, window.lo),
            guardian_threshold=guardian_threshold,
            pending_recovery=None,
            lineage=ROOT,
            subagent_epoch=0,
            name=old.name if name is None else _text(name, "name"),
            description=old.description if description is None else _text(description, "description"),
            framework=old.framework if framework is None else _text(framework, "framework"),
            endpoint=old.endpoint if endpoint is None else _text(endpoint, "endpoint"),
            capabilities=old.capabilities
            if capabilities is None
            else tuple(_text(c, "capability") for c in capabilities),
            created_at=window.hi,
            status=ACTIVE,
        )
        self._creation_checks(plan, record, window)
        plan.require(old.owner.hash)
        plan.spend(legacy, ctx.script_source("legacy"), LEGACY_DEREGISTER, None if legacy_datum is None else RawCBOR(raw))
        plan.mint(ctx.script_source("legacy"), {vid: -1}, LEGACY_BURN)
        plan.mint(ctx.script_source("identity"), {vid: 1}, Adopt(proof))
        self._record_output(plan, vid, record, deposit, live_floor=True)
        owner = (
            ctx.address_of(owner_address)
            if owner_address is not None
            else Address(payment_part=VerificationKeyHash(old.owner.hash), network=Network.MAINNET)
        )
        if bytes(owner.payment_part.payload) != old.owner.hash:
            raise IdentityRuleError("owner_address must pay to the legacy owner key")
        legacy_lovelace = legacy.output.amount if isinstance(legacy.output.amount, int) else legacy.output.amount.coin
        plan.output(TransactionOutput(owner, max(legacy_lovelace, LEGACY_OWNER_CHANGE_LOVELACE)))
        return build(ctx, plan, funding_address)

    def _legacy_record(self, vector_id: bytes) -> UTxO:
        scripts = self.ctx.scripts
        legacy_address = Address(payment_part=ScriptHash(scripts.legacy_hash), network=Network.MAINNET)
        for utxo in self.ctx.ledger.token_utxos(scripts.legacy_hash, vector_id):
            amount = utxo.output.amount
            if utxo.output.address != legacy_address or isinstance(amount, int):
                continue
            bundle = amount.multi_asset.get(ScriptHash(scripts.legacy_hash), {})
            if len(bundle) == 1 and bundle.get(AssetName(vector_id), 0) == 1:
                return utxo
        raise IdentityLookupError(f"no legacy record for {vector_id.hex()} at the legacy address")

    # ------------------------------------------------------------------
    # Update and controller actions (Part 2 §3.5, §3.6)
    # ------------------------------------------------------------------

    def update(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        name: str | bytes | None = None,
        description: str | bytes | None = None,
        framework: str | bytes | None = None,
        endpoint: str | bytes | None = None,
        capabilities: Sequence[str | bytes] | None = None,
        keys: Sequence[Key] | None = None,
        parties: Sequence[Party | PartySpec] | None = None,
        guardian_threshold: int | None = None,
        deposit: int | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Change the profile, the keys, the parties or the guardian threshold.

        ``keys`` and ``parties`` replace the whole lists. Keep a party by passing
        the same :class:`Party`; give a removal notice with
        ``dataclasses.replace(party, removal_after=t)`` (``t >= hi + 7 days``).
        """
        rec, window, plan = self._identity_spend(vector_id, valid_for)
        old = rec.datum
        changes: dict = {}
        for field_name, value in (
            ("name", name),
            ("description", description),
            ("framework", framework),
            ("endpoint", endpoint),
        ):
            if value is not None:
                changes[field_name] = _text(value, field_name)
        if capabilities is not None:
            changes["capabilities"] = tuple(_text(c, "capability") for c in capabilities)
        if keys is not None:
            changes["keys"] = tuple(keys)
        if parties is not None:
            changes["parties"] = _parties(parties, window.lo)
        if guardian_threshold is not None:
            changes["guardian_threshold"] = guardian_threshold
            if guardian_threshold == 0:
                changes["pending_recovery"] = None
        new = replace(old, **changes)
        if new == old and deposit is None:
            raise IdentityRuleError("the update changes nothing")
        plan.require(blake2b_224(old.controller))
        self._update_signers(plan, old, new, window)
        lovelace = rec.lovelace if deposit is None else deposit
        return self._finish_spend(funding_address, plan, rec, IdentitySpend("Update"), new, lovelace, live_floor=True)

    def _update_signers(self, plan: TxPlan, old: IdentityDatum, new: IdentityDatum, window: Window) -> None:
        """The signatures of the Update rules (Part 2 §3.6)."""
        old_keys = {k.key: k for k in old.keys}
        for key in new.keys:
            kept = old_keys.get(key.key)
            if kept is not None:
                if kept != key:
                    raise IdentityRuleError("a kept key keeps its type, purposes and proof; remove it and add it again")
            elif key.key_type == KeyType.ED25519:
                plan.require(blake2b_224(key.key))
        last = -1
        appointed = False
        for party in new.parties:
            index = next((i for i, p in enumerate(old.parties) if _same(p, party)), None)
            if index is None:
                appointed = True
                if isinstance(party.signer, ScriptSigner):
                    self._module1_consent(plan, party, window)
                else:
                    self._ok(plan, party.signer, old.controller, "a new party")
                continue
            if appointed or index <= last:
                raise IdentityRuleError("kept parties keep their order, and new parties come last")
            last = index
            match = old.parties[index]
            if party == match or _notice_only(match, party, window.hi):
                continue
            if match.removal_after is None and party.removal_after is not None and replace(
                match, removal_after=party.removal_after
            ) == party:
                raise IdentityRuleError(f"a removal notice must be at least 7 days after hi ({window.hi + DAYS_7_MS})")
            self._ok(plan, party.signer, old.controller, "a changed party")
        for party in old.parties:
            if any(_same(party, p) for p in new.parties):
                continue
            if party.removal_after is not None and party.removal_after <= window.lo:
                continue
            if isinstance(party.signer, ScriptSigner):
                raise IdentityRuleError("Module-1 can be removed only after its removal notice has passed")
            self._ok(plan, party.signer, old.controller, "a removed party")
        if (new.parties != old.parties or new.guardian_threshold != old.guardian_threshold) and not guardian_bound(
            new, window.hi
        ):
            raise IdentityRuleError("guardian_threshold exceeds the guardians with the recover right")
        if plan.withdrawals and any(
            isinstance(p.signer, ScriptSigner) and p not in new.parties for p in old.parties
        ):
            raise IdentityRuleError("Module-1 consents only when its existing parties stay unchanged")

    def change_controller(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        new_controller: str | bytes,
        *,
        deposit: int | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Install a new controller key. Ends all subagents and a pending recovery."""
        rec, _, plan = self._identity_spend(vector_id, valid_for)
        old = rec.datum
        controller = _public_key(new_controller, "new_controller")
        new = replace(old, controller=controller, subagent_epoch=old.subagent_epoch + 1, pending_recovery=None)
        plan.require(blake2b_224(old.controller), blake2b_224(controller))
        lovelace = rec.lovelace if deposit is None else deposit
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("ChangeController"), new, lovelace, live_floor=True
        )

    def end_subagents(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """``BumpEpoch``: every subagent created under an older epoch ends."""
        rec, _, plan = self._identity_spend(vector_id, valid_for)
        new = replace(rec.datum, subagent_epoch=rec.datum.subagent_epoch + 1)
        plan.require(blake2b_224(rec.datum.controller))
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("BumpEpoch"), new, rec.lovelace, live_floor=True
        )

    # ------------------------------------------------------------------
    # Holds (Part 2 §3.5 Suspend, Unsuspend)
    # ------------------------------------------------------------------

    def _actor(self, plan: TxPlan, record: IdentityDatum, by_party: int | None, right: int, window: Window):
        if by_party is None:
            plan.require(blake2b_224(record.controller))
            return BY_CONTROLLER, CONTROLLER_SET
        if not 0 <= by_party < len(record.parties):
            raise IdentityRuleError(f"no party with index {by_party}")
        party = record.parties[by_party]
        if not has_right(party.rights, right):
            raise IdentityRuleError(f"party {by_party} does not have the {'suspend' if right == RIGHT_SUSPEND else 'revoke'} right")
        if not covers(party, window.lo, window.hi):
            raise IdentityRuleError(f"party {by_party} does not cover the validity range")
        self._ok(plan, party.signer, record.controller, f"party {by_party}")
        return ByParty(by_party), party.signer

    def suspend(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        reason: int,
        until: int | None = None,
        duration_ms: int | None = None,
        by_party: int | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Add or renew the author's hold. The controller acts, or the party ``by_party``.

        The hold runs from ``lo`` to ``until`` (or ``lo + duration_ms``), with
        ``hi < until <= lo + 30 days``.
        """
        rec, window, plan = self._identity_spend(vector_id, valid_for)
        if reason not in SUSPEND_REASONS or reason == REASON_DISPUTE_VERDICT:
            raise IdentityRuleError(f"reason {reason} is not allowed in Suspend")
        if (until is None) == (duration_ms is None):
            raise IdentityRuleError("give exactly one of until and duration_ms")
        end = until if until is not None else window.lo + duration_ms
        if not window.hi < end <= window.lo + DAYS_30_MS:
            raise IdentityRuleError(f"until must be in ({window.hi}, {window.lo + DAYS_30_MS}]")
        actor, author = self._actor(plan, rec.datum, by_party, RIGHT_SUSPEND, window)
        holds = kept_holds(holds_of(rec.datum.status), rec.datum.parties, window.lo, author) + (
            Hold(author, reason, window.lo, end),
        )
        if len(holds) > 10:
            raise IdentityRuleError("a record has at most 10 holds")
        new = replace(rec.datum, status=Suspended(holds))
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("Suspend", actor=actor), new, rec.lovelace, live_floor=True
        )

    def unsuspend(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        author: Signer = CONTROLLER_SET,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Lift the hold of ``author`` (default: the controller's own hold)."""
        rec, window, plan = self._identity_spend(vector_id, valid_for)
        holds = holds_of(rec.datum.status)
        if not any(h.by == author for h in holds):
            raise IdentityRuleError("the record has no hold by this author")
        self._ok(plan, author, rec.datum.controller, "the author")
        remaining = kept_holds(holds, rec.datum.parties, window.lo, author)
        new = replace(rec.datum, status=Suspended(remaining) if remaining else ACTIVE)
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("Unsuspend", author=author), new, rec.lovelace, live_floor=True
        )

    # ------------------------------------------------------------------
    # Final actions (Part 2 §3.5, §3.7)
    # ------------------------------------------------------------------

    def revoke(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        reason: int,
        invalid_from: int | None = None,
        successor: str | bytes | None = None,
        by_party: int | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Revoke the identity: a tombstone with ``Revoked``. Only the controller names a successor."""
        rec, window, plan = self._identity_spend(vector_id, valid_for)
        if reason not in REVOKE_REASONS or reason == REASON_DISPUTE_VERDICT:
            raise IdentityRuleError(f"reason {reason} is not allowed in Revoke")
        if invalid_from is None and reason == REASON_KEY_COMPROMISE:
            raise IdentityRuleError("reason 1 (keyCompromise) needs invalid_from")
        if invalid_from is not None and not rec.datum.created_at <= invalid_from <= window.lo:
            raise IdentityRuleError(f"invalid_from must be in [{rec.datum.created_at}, {window.lo}]")
        actor, author = self._actor(plan, rec.datum, by_party, RIGHT_REVOKE, window)
        s = None
        if successor is not None:
            if by_party is not None:
                raise IdentityRuleError("only the controller names a successor")
            s = self._successor(plan, successor, rec.id)
        new = tombstone(rec.datum, Revoked(author, reason, window.lo, invalid_from, s))
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("Revoke", actor=actor), new, rec.lovelace, live_floor=False
        )

    def retire(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        successor: str | bytes | None = None,
        release_deposit: bool = False,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Retire the identity: a tombstone with ``Retired``. ``release_deposit`` keeps
        only the ledger minimum in the tombstone."""
        rec, window, plan = self._identity_spend(vector_id, valid_for)
        plan.require(blake2b_224(rec.datum.controller))
        s = self._successor(plan, successor, rec.id) if successor is not None else None
        new = tombstone(rec.datum, Retired(window.lo, s))
        lovelace = self._min_record_lovelace(rec.id, new) if release_deposit else rec.lovelace
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("Retire"), new, lovelace, live_floor=False
        )

    def reclaim(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Take back the deposit of a tombstone above the ledger minimum."""
        rec, _, plan = self._identity_spend(vector_id, valid_for, allow_terminal=True, live_only=False)
        plan.require(blake2b_224(rec.datum.controller))
        lovelace = self._min_record_lovelace(rec.id, rec.datum)
        if lovelace >= rec.lovelace:
            raise IdentityRuleError("the tombstone holds no deposit above the ledger minimum")
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("Reclaim"), rec.datum, lovelace, live_floor=False
        )

    def set_successor(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        successor: str | bytes,
        *,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """Name the successor of a tombstone that has none."""
        rec, _, plan = self._identity_spend(vector_id, valid_for, allow_terminal=True, live_only=False)
        status = rec.datum.status
        if status.successor is not None:
            raise IdentityRuleError("the tombstone already names a successor")
        plan.require(blake2b_224(rec.datum.controller))
        s = self._successor(plan, successor, rec.id)
        new = replace(rec.datum, status=replace(status, successor=s))
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("SetSuccessor"), new, rec.lovelace, live_floor=False
        )

    # ------------------------------------------------------------------
    # Recovery (Part 2 §3.5)
    # ------------------------------------------------------------------

    def _guardians(
        self, plan: TxPlan, record: IdentityDatum, guardians: Sequence[int] | None, window: Window
    ) -> tuple[int, ...]:
        if record.guardian_threshold < 1:
            raise IdentityRuleError("the record has no guardians (guardian_threshold is 0)")
        eligible = [i for i, p in enumerate(record.parties) if eligible_guardian(p, window.lo, window.hi)]
        chosen = tuple(eligible[: record.guardian_threshold] if guardians is None else guardians)
        for index in chosen:
            if index not in eligible:
                raise IdentityRuleError(f"party {index} is not an eligible guardian over the validity range")
        signers = [record.parties[i].signer for i in chosen]
        if len(set(signers)) != len(signers):
            raise IdentityRuleError("the guardians must have distinct signers")
        if len(chosen) < record.guardian_threshold:
            raise IdentityRuleError(f"at least {record.guardian_threshold} guardians must act")
        for signer in signers:
            self._ok(plan, signer, record.controller, "a guardian")
        return chosen

    def start_recovery(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        new_controller: str | bytes,
        *,
        guardians: Sequence[int] | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """``RecoverInit``: guardians propose a new controller; anybody completes it after 7 days.

        ``guardians`` are party indices; default: the first eligible guardians.
        """
        rec, window, plan = self._identity_spend(vector_id, valid_for)
        if rec.datum.pending_recovery is not None:
            raise IdentityRuleError("a recovery is already pending")
        chosen = self._guardians(plan, rec.datum, guardians, window)
        controller = _public_key(new_controller, "new_controller")
        plan.require(blake2b_224(controller))
        new = replace(rec.datum, pending_recovery=PendingRecovery(controller, window.hi + DAYS_7_MS))
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("RecoverInit", guardians=chosen), new, rec.lovelace, live_floor=True
        )

    def cancel_recovery(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        guardians: Sequence[int] | None = None,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """``RecoverCancel``: guardians remove the pending recovery."""
        rec, window, plan = self._identity_spend(vector_id, valid_for)
        if rec.datum.pending_recovery is None:
            raise IdentityRuleError("no recovery is pending")
        chosen = self._guardians(plan, rec.datum, guardians, window)
        new = replace(rec.datum, pending_recovery=None)
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("RecoverCancel", guardians=chosen), new, rec.lovelace, live_floor=True
        )

    def complete_recovery(
        self,
        funding_address: str | Address,
        vector_id: str | bytes,
        *,
        valid_for: int = DEFAULT_VALID_FOR_S,
    ) -> BuiltTx:
        """``RecoverFinalize``: install the pending controller after its delay. Anybody can submit it."""
        rec, window, plan = self._identity_spend(vector_id, valid_for)
        pending = rec.datum.pending_recovery
        if pending is None:
            raise IdentityRuleError("no recovery is pending")
        if pending.effective_after > window.lo:
            raise IdentityRuleError(f"the recovery completes at {pending.effective_after} (lo is {window.lo})")
        new = replace(
            rec.datum,
            controller=pending.new_controller,
            pending_recovery=None,
            subagent_epoch=rec.datum.subagent_epoch + 1,
        )
        return self._finish_spend(
            funding_address, plan, rec, IdentitySpend("RecoverFinalize"), new, rec.lovelace, live_floor=True
        )
