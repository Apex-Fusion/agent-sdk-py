"""On-chain types of the identity registry and the contracts that use it.

Field order and constructor order are part of the on-chain format:

- identity records and the identity redeemers: ``did:vector`` method
  specification Part 1 §5 and implementation plan Part 2 §3.1
  (``lib/vector_identity/types.ak`` and ``redeemers.ak``);
- attestations (§4), delegations (§5.2), vaults (§5.3), the new escrow
  (§6.1) and the new advert (§6.2) (``lib/identity_marketplace/types.ak``).

A record type is ``Constr 0`` with its fields in order. The constructors of a
sum type are numbered from 0 in the order shown. ``Option`` is ``Some = 0``,
``None = 1``; ``Bool`` is ``False = 0``, ``True = 1``.

Every ``ByteArray`` is :class:`bytes`, also UTF-8 text: the contracts do not
check UTF-8, so a reader must accept any bytes. Decoders check the shape and
the fixed byte lengths that the types state. They do not check the counts,
the text limits or the relations between fields; the builders do that.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, ClassVar, TypeVar

from vector_agent.identity.plutus_data import (
    Constr,
    PlutusData,
    PlutusDataError,
    decode_data,
    encode_data,
)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fields(data: PlutusData, path: str, index: int, count: int) -> tuple[PlutusData, ...]:
    if not isinstance(data, Constr):
        raise PlutusDataError(f"{path}: expected a constructor")
    if data.index != index:
        raise PlutusDataError(f"{path}: constructor {data.index} (expected {index})")
    if len(data.fields) != count:
        raise PlutusDataError(f"{path}: {len(data.fields)} fields (expected {count})")
    return data.fields


def _variant(data: PlutusData, path: str, arities: Sequence[int]) -> tuple[int, tuple]:
    if not isinstance(data, Constr):
        raise PlutusDataError(f"{path}: expected a constructor")
    if not 0 <= data.index < len(arities):
        raise PlutusDataError(
            f"{path}: unknown constructor {data.index} (expected 0..{len(arities) - 1})"
        )
    if len(data.fields) != arities[data.index]:
        raise PlutusDataError(
            f"{path}: constructor {data.index} has {len(data.fields)} fields "
            f"(expected {arities[data.index]})"
        )
    return data.index, data.fields


def _bytes(data: PlutusData, path: str, size: int | None = None) -> bytes:
    if not isinstance(data, bytes):
        raise PlutusDataError(f"{path}: expected bytes")
    if size is not None and len(data) != size:
        raise PlutusDataError(f"{path}: {len(data)} bytes (expected {size})")
    return data


def _int(data: PlutusData, path: str) -> int:
    if isinstance(data, bool) or not isinstance(data, int):
        raise PlutusDataError(f"{path}: expected an integer")
    return data


def _bool(data: PlutusData, path: str) -> bool:
    index, _ = _variant(data, path, (0, 0))
    return index == 1


def _list(data: PlutusData, path: str, item: Callable[[PlutusData, str], T]) -> tuple[T, ...]:
    if not isinstance(data, list):
        raise PlutusDataError(f"{path}: expected a list")
    return tuple(item(value, f"{path}[{i}]") for i, value in enumerate(data))


def _option(data: PlutusData, path: str, item: Callable[[PlutusData, str], T]) -> T | None:
    index, fields = _variant(data, path, (1, 0))
    return item(fields[0], f"{path}.some") if index == 0 else None


def _some(value: Any, encode: Callable[[Any], PlutusData] = lambda v: v) -> Constr:
    return Constr(1) if value is None else Constr(0, (encode(value),))


def _bool_data(value: bool) -> Constr:
    return Constr(1 if value else 0)


def _ints(data: PlutusData, path: str) -> int:
    return _int(data, path)


def _bytes_any(data: PlutusData, path: str) -> bytes:
    return _bytes(data, path)


def _sized(size: int) -> Callable[[PlutusData, str], bytes]:
    return lambda data, path: _bytes(data, path, size)


class _Codec:
    """``to_cbor`` / ``from_cbor`` for a type with ``to_data`` / ``from_data``."""

    def to_data(self) -> PlutusData:  # pragma: no cover - every subclass overrides it
        raise NotImplementedError

    def to_cbor(self) -> bytes:
        """The CBOR bytes of this value, as Aiken ``cbor.serialise`` writes them."""
        return encode_data(self.to_data())

    def to_cbor_hex(self) -> str:
        return self.to_cbor().hex()

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "") -> Any:  # pragma: no cover
        raise NotImplementedError

    @classmethod
    def from_cbor(cls, raw: bytes | str) -> Any:
        """Decode CBOR bytes (or hex) of this type."""
        if isinstance(raw, str):
            raw = bytes.fromhex(raw)
        return cls.from_data(decode_data(raw), cls.__name__)


# ---------------------------------------------------------------------------
# Ledger types (Aiken stdlib cardano/*)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OutputReference(_Codec):
    """``OutputReference { transaction_id, output_index }``."""

    tx_id: bytes
    index: int

    def to_data(self) -> Constr:
        return Constr(0, (self.tx_id, self.index))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "OutputReference") -> OutputReference:
        tx_id, index = _fields(data, path, 0, 2)
        return cls(_bytes(tx_id, f"{path}.tx_id", 32), _int(index, f"{path}.index"))

    @classmethod
    def parse(cls, text: str) -> OutputReference:
        """Parse ``<64 hex>#<index>``."""
        tx_id, sep, index = text.strip().partition("#")
        if not sep or len(tx_id) != 64 or not index.isdigit():
            raise ValueError(f"expected <tx id>#<index>, got {text!r}")
        return cls(bytes.fromhex(tx_id), int(index))

    def __str__(self) -> str:
        return f"{self.tx_id.hex()}#{self.index}"


@dataclass(frozen=True)
class KeyCredential(_Codec):
    """``VerificationKey(hash)``: constructor 0."""

    hash: bytes

    def to_data(self) -> Constr:
        return Constr(0, (self.hash,))


@dataclass(frozen=True)
class ScriptCredential(_Codec):
    """``Script(hash)``: constructor 1."""

    hash: bytes

    def to_data(self) -> Constr:
        return Constr(1, (self.hash,))


Credential = KeyCredential | ScriptCredential


def credential_from_data(data: PlutusData, path: str = "Credential") -> Credential:
    index, (value,) = _variant(data, path, (1, 1))
    hash_ = _bytes(value, f"{path}.hash", 28)
    return KeyCredential(hash_) if index == 0 else ScriptCredential(hash_)


@dataclass(frozen=True)
class InlineStake(_Codec):
    """``Inline(credential)``: constructor 0 of ``StakeCredential``."""

    credential: Credential

    def to_data(self) -> Constr:
        return Constr(0, (self.credential.to_data(),))


@dataclass(frozen=True)
class PointerStake(_Codec):
    """``Pointer { slot_number, transaction_index, certificate_index }``: constructor 1."""

    slot_number: int
    transaction_index: int
    certificate_index: int

    def to_data(self) -> Constr:
        return Constr(1, (self.slot_number, self.transaction_index, self.certificate_index))


StakeCredential = InlineStake | PointerStake


def stake_credential_from_data(data: PlutusData, path: str = "StakeCredential") -> StakeCredential:
    index, fields = _variant(data, path, (1, 3))
    if index == 0:
        return InlineStake(credential_from_data(fields[0], f"{path}.credential"))
    return PointerStake(*(_int(v, f"{path}[{i}]") for i, v in enumerate(fields)))


@dataclass(frozen=True)
class PlutusAddress(_Codec):
    """``Address { payment_credential, stake_credential }`` as Plutus Data."""

    payment: Credential
    stake: StakeCredential | None = None

    def to_data(self) -> Constr:
        return Constr(0, (self.payment.to_data(), _some(self.stake, lambda s: s.to_data())))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "Address") -> PlutusAddress:
        payment, stake = _fields(data, path, 0, 2)
        return cls(
            credential_from_data(payment, f"{path}.payment"),
            _option(stake, f"{path}.stake", stake_credential_from_data),
        )


# ---------------------------------------------------------------------------
# Identity record (Part 1 §5)
# ---------------------------------------------------------------------------


class KeyType(IntEnum):
    ED25519 = 0
    P256 = 1


class Role(IntEnum):
    ACCOUNTABLE = 0
    RESPONSIBLE = 1
    PROVIDER = 2
    DISTRIBUTOR = 3
    GUARDIAN = 4


@dataclass(frozen=True)
class Key(_Codec):
    """A listed key. ``purposes`` is a sum of 1, 2, 8 and 16."""

    key_type: KeyType
    key: bytes
    purposes: int
    pop: bytes | None = None

    def to_data(self) -> Constr:
        return Constr(
            0, (Constr(int(self.key_type)), self.key, self.purposes, _some(self.pop))
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "Key") -> Key:
        key_type, key, purposes, pop = _fields(data, path, 0, 4)
        index, _ = _variant(key_type, f"{path}.key_type", (0, 0))
        return cls(
            KeyType(index),
            _bytes(key, f"{path}.key"),
            _int(purposes, f"{path}.purposes"),
            _option(pop, f"{path}.pop", _bytes_any),
        )


@dataclass(frozen=True)
class KeyHashSigner(_Codec):
    """``KeyHash { hash }``: a 28-byte key hash."""

    hash: bytes

    def to_data(self) -> Constr:
        return Constr(0, (self.hash,))


@dataclass(frozen=True)
class ScriptSigner(_Codec):
    """``Script { hash }``: only the approved Module-1 contract."""

    hash: bytes

    def to_data(self) -> Constr:
        return Constr(1, (self.hash,))


@dataclass(frozen=True)
class ControllerSetSigner(_Codec):
    """``ControllerSet``: whoever is the record's controller."""

    def to_data(self) -> Constr:
        return Constr(2)


CONTROLLER_SET = ControllerSetSigner()

Signer = KeyHashSigner | ScriptSigner | ControllerSetSigner


def signer_from_data(data: PlutusData, path: str = "Signer") -> Signer:
    index, fields = _variant(data, path, (1, 1, 0))
    if index == 0:
        return KeyHashSigner(_bytes(fields[0], f"{path}.hash", 28))
    if index == 1:
        return ScriptSigner(_bytes(fields[0], f"{path}.hash", 28))
    return CONTROLLER_SET


@dataclass(frozen=True)
class Party(_Codec):
    """A party. ``rights`` is a sum of suspend (1), revoke (2) and recover (4)."""

    role: Role
    signer: Signer
    organisation: bytes | None
    not_before: int
    not_after: int | None
    rights: int
    removal_after: int | None = None

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                Constr(int(self.role)),
                self.signer.to_data(),
                _some(self.organisation),
                self.not_before,
                _some(self.not_after),
                self.rights,
                _some(self.removal_after),
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "Party") -> Party:
        role, signer, organisation, not_before, not_after, rights, removal_after = _fields(
            data, path, 0, 7
        )
        role_index, _ = _variant(role, f"{path}.role", (0, 0, 0, 0, 0))
        return cls(
            Role(role_index),
            signer_from_data(signer, f"{path}.signer"),
            _option(organisation, f"{path}.organisation", _bytes_any),
            _int(not_before, f"{path}.not_before"),
            _option(not_after, f"{path}.not_after", _ints),
            _int(rights, f"{path}.rights"),
            _option(removal_after, f"{path}.removal_after", _ints),
        )


@dataclass(frozen=True)
class Root(_Codec):
    """Lineage ``Root``: an independent agent."""

    def to_data(self) -> Constr:
        return Constr(0)


ROOT = Root()


@dataclass(frozen=True)
class Subagent(_Codec):
    """Lineage ``Subagent { parent, parent_epoch, depth }``."""

    parent: bytes
    parent_epoch: int
    depth: int

    def to_data(self) -> Constr:
        return Constr(1, (self.parent, self.parent_epoch, self.depth))


Lineage = Root | Subagent


def lineage_from_data(data: PlutusData, path: str = "Lineage") -> Lineage:
    index, fields = _variant(data, path, (0, 3))
    if index == 0:
        return ROOT
    parent, epoch, depth = fields
    return Subagent(
        _bytes(parent, f"{path}.parent", 32),
        _int(epoch, f"{path}.parent_epoch"),
        _int(depth, f"{path}.depth"),
    )


@dataclass(frozen=True)
class Hold(_Codec):
    """One author's suspension: ``Hold { by, reason, since, until }``."""

    by: Signer
    reason: int
    since: int
    until: int

    def to_data(self) -> Constr:
        return Constr(0, (self.by.to_data(), self.reason, self.since, self.until))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "Hold") -> Hold:
        by, reason, since, until = _fields(data, path, 0, 4)
        return cls(
            signer_from_data(by, f"{path}.by"),
            _int(reason, f"{path}.reason"),
            _int(since, f"{path}.since"),
            _int(until, f"{path}.until"),
        )


@dataclass(frozen=True)
class Active(_Codec):
    """Status ``Active``."""

    def to_data(self) -> Constr:
        return Constr(0)


ACTIVE = Active()


@dataclass(frozen=True)
class Suspended(_Codec):
    """Status ``Suspended { holds }`` (1..10 holds)."""

    holds: tuple[Hold, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.holds, tuple):
            object.__setattr__(self, "holds", tuple(self.holds))

    def to_data(self) -> Constr:
        return Constr(1, ([hold.to_data() for hold in self.holds],))


@dataclass(frozen=True)
class Revoked(_Codec):
    """Status ``Revoked { by, reason, at, invalid_from, successor }`` (a tombstone)."""

    by: Signer
    reason: int
    at: int
    invalid_from: int | None = None
    successor: bytes | None = None

    def to_data(self) -> Constr:
        return Constr(
            2,
            (
                self.by.to_data(),
                self.reason,
                self.at,
                _some(self.invalid_from),
                _some(self.successor),
            ),
        )


@dataclass(frozen=True)
class Retired(_Codec):
    """Status ``Retired { at, successor }`` (a tombstone)."""

    at: int
    successor: bytes | None = None

    def to_data(self) -> Constr:
        return Constr(3, (self.at, _some(self.successor)))


Status = Active | Suspended | Revoked | Retired


def status_from_data(data: PlutusData, path: str = "Status") -> Status:
    index, fields = _variant(data, path, (0, 1, 5, 2))
    if index == 0:
        return ACTIVE
    if index == 1:
        return Suspended(_list(fields[0], f"{path}.holds", Hold.from_data))
    if index == 2:
        by, reason, at, invalid_from, successor = fields
        return Revoked(
            signer_from_data(by, f"{path}.by"),
            _int(reason, f"{path}.reason"),
            _int(at, f"{path}.at"),
            _option(invalid_from, f"{path}.invalid_from", _ints),
            _option(successor, f"{path}.successor", _sized(32)),
        )
    at, successor = fields
    return Retired(_int(at, f"{path}.at"), _option(successor, f"{path}.successor", _sized(32)))


@dataclass(frozen=True)
class PendingRecovery(_Codec):
    """``PendingRecovery { new_controller, effective_after }``."""

    new_controller: bytes
    effective_after: int

    def to_data(self) -> Constr:
        return Constr(0, (self.new_controller, self.effective_after))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "PendingRecovery") -> PendingRecovery:
        new_controller, effective_after = _fields(data, path, 0, 2)
        return cls(
            _bytes(new_controller, f"{path}.new_controller"),
            _int(effective_after, f"{path}.effective_after"),
        )


@dataclass(frozen=True)
class IdentityDatum(_Codec):
    """The inline datum of an identity record: ``Constr 0`` with 14 fields."""

    controller: bytes
    keys: tuple[Key, ...]
    parties: tuple[Party, ...]
    guardian_threshold: int
    pending_recovery: PendingRecovery | None
    lineage: Lineage
    subagent_epoch: int
    name: bytes
    description: bytes
    framework: bytes
    endpoint: bytes
    capabilities: tuple[bytes, ...]
    created_at: int
    status: Status

    def __post_init__(self) -> None:
        for name in ("keys", "parties", "capabilities"):
            value = getattr(self, name)
            if not isinstance(value, tuple):
                object.__setattr__(self, name, tuple(value))

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.controller,
                [key.to_data() for key in self.keys],
                [party.to_data() for party in self.parties],
                self.guardian_threshold,
                _some(self.pending_recovery, lambda p: p.to_data()),
                self.lineage.to_data(),
                self.subagent_epoch,
                self.name,
                self.description,
                self.framework,
                self.endpoint,
                list(self.capabilities),
                self.created_at,
                self.status.to_data(),
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "IdentityDatum") -> IdentityDatum:
        f = _fields(data, path, 0, 14)
        return cls(
            controller=_bytes(f[0], f"{path}.controller"),
            keys=_list(f[1], f"{path}.keys", Key.from_data),
            parties=_list(f[2], f"{path}.parties", Party.from_data),
            guardian_threshold=_int(f[3], f"{path}.guardian_threshold"),
            pending_recovery=_option(f[4], f"{path}.pending_recovery", PendingRecovery.from_data),
            lineage=lineage_from_data(f[5], f"{path}.lineage"),
            subagent_epoch=_int(f[6], f"{path}.subagent_epoch"),
            name=_bytes(f[7], f"{path}.name"),
            description=_bytes(f[8], f"{path}.description"),
            framework=_bytes(f[9], f"{path}.framework"),
            endpoint=_bytes(f[10], f"{path}.endpoint"),
            capabilities=_list(f[11], f"{path}.capabilities", _bytes_any),
            created_at=_int(f[12], f"{path}.created_at"),
            status=status_from_data(f[13], f"{path}.status"),
        )


@dataclass(frozen=True)
class LegacyDatum(_Codec):
    """Legacy registry record: ``Constr 0`` with 7 fields."""

    owner: Credential
    name: bytes
    description: bytes
    capabilities: tuple[bytes, ...]
    framework: bytes
    endpoint: bytes
    registered_at: int

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.owner.to_data(),
                self.name,
                self.description,
                list(self.capabilities),
                self.framework,
                self.endpoint,
                self.registered_at,
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "LegacyDatum") -> LegacyDatum:
        owner, name, description, capabilities, framework, endpoint, registered_at = _fields(
            data, path, 0, 7
        )
        return cls(
            credential_from_data(owner, f"{path}.owner"),
            _bytes(name, f"{path}.name"),
            _bytes(description, f"{path}.description"),
            _list(capabilities, f"{path}.capabilities", _bytes_any),
            _bytes(framework, f"{path}.framework"),
            _bytes(endpoint, f"{path}.endpoint"),
            _int(registered_at, f"{path}.registered_at"),
        )


# ---------------------------------------------------------------------------
# Identity redeemers (Part 2 §3.1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Register(_Codec):
    """Mint redeemer ``Register { seed }``."""

    seed: OutputReference

    def to_data(self) -> Constr:
        return Constr(0, (self.seed.to_data(),))


@dataclass(frozen=True)
class Adopt(_Codec):
    """Mint redeemer ``Adopt { proof }``: a Merkle proof against ``legacy_root``."""

    proof: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.proof, tuple):
            object.__setattr__(self, "proof", tuple(self.proof))

    def to_data(self) -> Constr:
        return Constr(1, (list(self.proof),))


IdentityMint = Register | Adopt


def identity_mint_from_data(data: PlutusData, path: str = "IdentityMint") -> IdentityMint:
    index, (value,) = _variant(data, path, (1, 1))
    if index == 0:
        return Register(OutputReference.from_data(value, f"{path}.seed"))
    return Adopt(_list(value, f"{path}.proof", _sized(32)))


@dataclass(frozen=True)
class ByController(_Codec):
    """Actor ``ByController``."""

    def to_data(self) -> Constr:
        return Constr(0)


BY_CONTROLLER = ByController()


@dataclass(frozen=True)
class ByParty(_Codec):
    """Actor ``ByParty { index }``: the index of the acting party."""

    index: int

    def to_data(self) -> Constr:
        return Constr(1, (self.index,))


Actor = ByController | ByParty


def actor_from_data(data: PlutusData, path: str = "Actor") -> Actor:
    index, fields = _variant(data, path, (0, 1))
    return BY_CONTROLLER if index == 0 else ByParty(_int(fields[0], f"{path}.index"))


@dataclass(frozen=True)
class IdentitySpend(_Codec):
    """Spend redeemer of the identity contract.

    ``action`` is the constructor name. ``actor`` is set for Suspend and
    Revoke, ``author`` for Unsuspend, ``guardians`` for RecoverInit and
    RecoverCancel.
    """

    ACTIONS: ClassVar[tuple[str, ...]] = (
        "Update",
        "ChangeController",
        "Suspend",
        "Unsuspend",
        "Revoke",
        "Retire",
        "Reclaim",
        "SetSuccessor",
        "BumpEpoch",
        "RecoverInit",
        "RecoverCancel",
        "RecoverFinalize",
    )

    action: str
    actor: Actor | None = None
    author: Signer | None = None
    guardians: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        if self.action not in self.ACTIONS:
            raise ValueError(f"unknown identity spend action {self.action!r}")
        needs = {
            "Suspend": "actor",
            "Revoke": "actor",
            "Unsuspend": "author",
            "RecoverInit": "guardians",
            "RecoverCancel": "guardians",
        }.get(self.action)
        for name in ("actor", "author", "guardians"):
            if (getattr(self, name) is not None) != (name == needs):
                state = "required" if name == needs else "not allowed"
                raise ValueError(f"{self.action}: field {name} is {state}")
        if self.guardians is not None and not isinstance(self.guardians, tuple):
            object.__setattr__(self, "guardians", tuple(self.guardians))

    def to_data(self) -> Constr:
        index = self.ACTIONS.index(self.action)
        if self.actor is not None:
            return Constr(index, (self.actor.to_data(),))
        if self.author is not None:
            return Constr(index, (self.author.to_data(),))
        if self.guardians is not None:
            return Constr(index, (list(self.guardians),))
        return Constr(index)

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "IdentitySpend") -> IdentitySpend:
        index, fields = _variant(data, path, (0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0))
        action = cls.ACTIONS[index]
        if action in ("Suspend", "Revoke"):
            return cls(action, actor=actor_from_data(fields[0], f"{path}.actor"))
        if action == "Unsuspend":
            return cls(action, author=signer_from_data(fields[0], f"{path}.author"))
        if action in ("RecoverInit", "RecoverCancel"):
            return cls(action, guardians=_list(fields[0], f"{path}.guardians", _ints))
        return cls(action)


# ---------------------------------------------------------------------------
# Attestations (Part 2 §4)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttActive(_Codec):
    def to_data(self) -> Constr:
        return Constr(0)


ATT_ACTIVE = AttActive()


@dataclass(frozen=True)
class AttRevoked(_Codec):
    """``AttRevoked { at, reason }``."""

    at: int
    reason: int

    def to_data(self) -> Constr:
        return Constr(1, (self.at, self.reason))


AttStatus = AttActive | AttRevoked


def att_status_from_data(data: PlutusData, path: str = "AttStatus") -> AttStatus:
    index, fields = _variant(data, path, (0, 2))
    if index == 0:
        return ATT_ACTIVE
    return AttRevoked(_int(fields[0], f"{path}.at"), _int(fields[1], f"{path}.reason"))


@dataclass(frozen=True)
class Anchor(_Codec):
    """The subject's reply: ``uri`` 1..256 bytes, ``sha256`` 32 bytes."""

    uri: bytes
    sha256: bytes

    def to_data(self) -> Constr:
        return Constr(0, (self.uri, self.sha256))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "Anchor") -> Anchor:
        uri, sha256 = _fields(data, path, 0, 2)
        return cls(_bytes(uri, f"{path}.uri"), _bytes(sha256, f"{path}.sha256", 32))


@dataclass(frozen=True)
class Link(_Codec):
    """``rel``: 0 supersedes, 1 depends_on, 2 corroborates, 3 disputes."""

    rel: int
    target: bytes

    def to_data(self) -> Constr:
        return Constr(0, (self.rel, self.target))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "Link") -> Link:
        rel, target = _fields(data, path, 0, 2)
        return cls(_int(rel, f"{path}.rel"), _bytes(target, f"{path}.target", 32))


@dataclass(frozen=True)
class AttestationDatum(_Codec):
    """An attestation: ``Constr 0`` with 16 fields."""

    subject: bytes
    issuer: bytes
    issuer_id: bytes | None
    att_type: int
    format: int | None
    profile: bytes | None
    digest: bytes
    locator: bytes | None
    envelope_sig: bytes | None
    issued_at: int
    valid_from: int | None
    valid_until: int | None
    solicited: bool
    status: AttStatus
    contested: Anchor | None
    links: tuple[Link, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.links, tuple):
            object.__setattr__(self, "links", tuple(self.links))

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.subject,
                self.issuer,
                _some(self.issuer_id),
                self.att_type,
                _some(self.format),
                _some(self.profile),
                self.digest,
                _some(self.locator),
                _some(self.envelope_sig),
                self.issued_at,
                _some(self.valid_from),
                _some(self.valid_until),
                _bool_data(self.solicited),
                self.status.to_data(),
                _some(self.contested, lambda a: a.to_data()),
                [link.to_data() for link in self.links],
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "AttestationDatum") -> AttestationDatum:
        f = _fields(data, path, 0, 16)
        return cls(
            subject=_bytes(f[0], f"{path}.subject", 32),
            issuer=_bytes(f[1], f"{path}.issuer", 32),
            issuer_id=_option(f[2], f"{path}.issuer_id", _sized(32)),
            att_type=_int(f[3], f"{path}.att_type"),
            format=_option(f[4], f"{path}.format", _ints),
            profile=_option(f[5], f"{path}.profile", _sized(32)),
            digest=_bytes(f[6], f"{path}.digest", 32),
            locator=_option(f[7], f"{path}.locator", _bytes_any),
            envelope_sig=_option(f[8], f"{path}.envelope_sig", _sized(64)),
            issued_at=_int(f[9], f"{path}.issued_at"),
            valid_from=_option(f[10], f"{path}.valid_from", _ints),
            valid_until=_option(f[11], f"{path}.valid_until", _ints),
            solicited=_bool(f[12], f"{path}.solicited"),
            status=att_status_from_data(f[13], f"{path}.status"),
            contested=_option(f[14], f"{path}.contested", Anchor.from_data),
            links=_list(f[15], f"{path}.links", Link.from_data),
        )


@dataclass(frozen=True)
class Attest(_Codec):
    """Mint redeemer ``Attest { seed }``."""

    seed: OutputReference

    def to_data(self) -> Constr:
        return Constr(0, (self.seed.to_data(),))


@dataclass(frozen=True)
class Burn(_Codec):
    """Mint redeemer ``Burn`` (with a ``Withdraw`` spend)."""

    def to_data(self) -> Constr:
        return Constr(1)


AttestationMint = Attest | Burn


def attestation_mint_from_data(data: PlutusData, path: str = "AttestationMint") -> AttestationMint:
    index, fields = _variant(data, path, (1, 0))
    if index == 0:
        return Attest(OutputReference.from_data(fields[0], f"{path}.seed"))
    return Burn()


@dataclass(frozen=True)
class RevokeAtt(_Codec):
    """Spend redeemer ``RevokeAtt { reason }``."""

    reason: int

    def to_data(self) -> Constr:
        return Constr(0, (self.reason,))


@dataclass(frozen=True)
class Contest(_Codec):
    def to_data(self) -> Constr:
        return Constr(1)


@dataclass(frozen=True)
class Withdraw(_Codec):
    def to_data(self) -> Constr:
        return Constr(2)


AttestationSpend = RevokeAtt | Contest | Withdraw


def attestation_spend_from_data(
    data: PlutusData, path: str = "AttestationSpend"
) -> AttestationSpend:
    index, fields = _variant(data, path, (1, 0, 0))
    if index == 0:
        return RevokeAtt(_int(fields[0], f"{path}.reason"))
    return Contest() if index == 1 else Withdraw()


# ---------------------------------------------------------------------------
# Delegations (§5.2) and vaults (§5.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrincipalKey(_Codec):
    """Delegator ``PrincipalKey { hash, organisation }``."""

    hash: bytes
    organisation: bytes | None = None

    def to_data(self) -> Constr:
        return Constr(0, (self.hash, _some(self.organisation)))


@dataclass(frozen=True)
class AgentDelegator(_Codec):
    """Delegator ``Agent { id }``: a registered agent."""

    id: bytes

    def to_data(self) -> Constr:
        return Constr(1, (self.id,))


Delegator = PrincipalKey | AgentDelegator


def delegator_from_data(data: PlutusData, path: str = "Delegator") -> Delegator:
    index, fields = _variant(data, path, (2, 1))
    if index == 0:
        return PrincipalKey(
            _bytes(fields[0], f"{path}.hash", 28),
            _option(fields[1], f"{path}.organisation", _bytes_any),
        )
    return AgentDelegator(_bytes(fields[0], f"{path}.id", 32))


@dataclass(frozen=True)
class ValueLimit(_Codec):
    """``ValueLimit { per_tx, total, period_ms }`` (base units and milliseconds)."""

    per_tx: int
    total: int
    period_ms: int

    def to_data(self) -> Constr:
        return Constr(0, (self.per_tx, self.total, self.period_ms))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "ValueLimit") -> ValueLimit:
        per_tx, total, period_ms = _fields(data, path, 0, 3)
        return cls(
            _int(per_tx, f"{path}.per_tx"),
            _int(total, f"{path}.total"),
            _int(period_ms, f"{path}.period_ms"),
        )


@dataclass(frozen=True)
class DelegationDatum(_Codec):
    """A delegation: ``Constr 0`` with 12 fields. Patterns are UTF-8 bytes."""

    delegator: Delegator
    parent: bytes | None
    delegate: bytes
    delegate_key: bytes
    actions: tuple[bytes, ...]
    resources: tuple[bytes, ...]
    not_before: int
    not_after: int
    depth: int
    remaining: int
    purpose: bytes | None = None
    value: ValueLimit | None = None

    def __post_init__(self) -> None:
        for name in ("actions", "resources"):
            value = getattr(self, name)
            if not isinstance(value, tuple):
                object.__setattr__(self, name, tuple(value))

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.delegator.to_data(),
                _some(self.parent),
                self.delegate,
                self.delegate_key,
                list(self.actions),
                list(self.resources),
                self.not_before,
                self.not_after,
                self.depth,
                self.remaining,
                _some(self.purpose),
                _some(self.value, lambda v: v.to_data()),
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "DelegationDatum") -> DelegationDatum:
        f = _fields(data, path, 0, 12)
        return cls(
            delegator=delegator_from_data(f[0], f"{path}.delegator"),
            parent=_option(f[1], f"{path}.parent", _sized(32)),
            delegate=_bytes(f[2], f"{path}.delegate", 32),
            delegate_key=_bytes(f[3], f"{path}.delegate_key", 28),
            actions=_list(f[4], f"{path}.actions", _bytes_any),
            resources=_list(f[5], f"{path}.resources", _bytes_any),
            not_before=_int(f[6], f"{path}.not_before"),
            not_after=_int(f[7], f"{path}.not_after"),
            depth=_int(f[8], f"{path}.depth"),
            remaining=_int(f[9], f"{path}.remaining"),
            purpose=_option(f[10], f"{path}.purpose", _sized(32)),
            value=_option(f[11], f"{path}.value", ValueLimit.from_data),
        )


@dataclass(frozen=True)
class Delegate(_Codec):
    """Mint redeemer ``Delegate { seed }``."""

    seed: OutputReference

    def to_data(self) -> Constr:
        return Constr(0, (self.seed.to_data(),))


@dataclass(frozen=True)
class Undelegate(_Codec):
    """Mint redeemer ``Undelegate``; also the only spend redeemer of a delegation."""

    def to_data(self) -> Constr:
        return Constr(1)


DelegationMint = Delegate | Undelegate


def delegation_mint_from_data(data: PlutusData, path: str = "DelegationMint") -> DelegationMint:
    index, fields = _variant(data, path, (1, 0))
    if index == 0:
        return Delegate(OutputReference.from_data(fields[0], f"{path}.seed"))
    return Undelegate()


@dataclass(frozen=True)
class VaultLive(_Codec):
    """Vault datum ``Live { owner, delegation, spent, period_start }``."""

    owner: Delegator
    delegation: bytes
    spent: int
    period_start: int

    def to_data(self) -> Constr:
        return Constr(0, (self.owner.to_data(), self.delegation, self.spent, self.period_start))


@dataclass(frozen=True)
class VaultReturned(_Codec):
    """Vault datum ``Returned { owner }``: an escrow refund; only Close spends it."""

    owner: Delegator

    def to_data(self) -> Constr:
        return Constr(1, (self.owner.to_data(),))


VaultDatum = VaultLive | VaultReturned


def vault_datum_from_data(data: PlutusData, path: str = "VaultDatum") -> VaultDatum:
    index, fields = _variant(data, path, (4, 1))
    if index == 1:
        return VaultReturned(delegator_from_data(fields[0], f"{path}.owner"))
    owner, delegation, spent, period_start = fields
    return VaultLive(
        delegator_from_data(owner, f"{path}.owner"),
        _bytes(delegation, f"{path}.delegation", 32),
        _int(spent, f"{path}.spent"),
        _int(period_start, f"{path}.period_start"),
    )


class VaultSpend(IntEnum):
    PAY = 0
    CLOSE = 1

    def to_data(self) -> Constr:
        return Constr(int(self))


# ---------------------------------------------------------------------------
# New escrow (§6.1) and new advert (§6.2)
# ---------------------------------------------------------------------------


class EscrowState(IntEnum):
    OPEN = 0
    CLAIMED = 1
    SUBMITTED = 2
    ACCEPTED = 3
    RECLAIMED = 4
    RELEASED = 5


@dataclass(frozen=True)
class Refund(_Codec):
    """Where buyer payouts go: ``Refund { address, datum }``."""

    address: PlutusAddress
    datum: PlutusData | None = None

    def to_data(self) -> Constr:
        return Constr(0, (self.address.to_data(), _some(self.datum)))

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "Refund") -> Refund:
        address, datum = _fields(data, path, 0, 2)
        return cls(
            PlutusAddress.from_data(address, f"{path}.address"),
            _option(datum, f"{path}.datum", lambda d, _p: d),
        )


@dataclass(frozen=True)
class EscrowDatum(_Codec):
    """The new escrow datum: the 14 legacy fields, ``agent_id`` and ``refund``."""

    buyer_pkh: bytes
    supplier_pkh: bytes
    advert_ref: OutputReference
    capability_id: bytes
    request_spec_hash: bytes
    prompt_hash: bytes
    payment_lovelace: int
    buyer_bond_lovelace: int
    supplier_bond_lovelace: int
    deliver_by: int
    posted_at: int
    submitted_at: int | None
    result_receipt_hash: bytes | None
    state: EscrowState
    agent_id: bytes
    refund: Refund | None

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.buyer_pkh,
                self.supplier_pkh,
                self.advert_ref.to_data(),
                self.capability_id,
                self.request_spec_hash,
                self.prompt_hash,
                self.payment_lovelace,
                self.buyer_bond_lovelace,
                self.supplier_bond_lovelace,
                self.deliver_by,
                self.posted_at,
                _some(self.submitted_at),
                _some(self.result_receipt_hash),
                Constr(int(self.state)),
                self.agent_id,
                _some(self.refund, lambda r: r.to_data()),
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "EscrowDatum") -> EscrowDatum:
        f = _fields(data, path, 0, 16)
        state, _ = _variant(f[13], f"{path}.state", (0, 0, 0, 0, 0, 0))
        return cls(
            buyer_pkh=_bytes(f[0], f"{path}.buyer_pkh", 28),
            supplier_pkh=_bytes(f[1], f"{path}.supplier_pkh", 28),
            advert_ref=OutputReference.from_data(f[2], f"{path}.advert_ref"),
            capability_id=_bytes(f[3], f"{path}.capability_id"),
            request_spec_hash=_bytes(f[4], f"{path}.request_spec_hash", 32),
            prompt_hash=_bytes(f[5], f"{path}.prompt_hash", 32),
            payment_lovelace=_int(f[6], f"{path}.payment_lovelace"),
            buyer_bond_lovelace=_int(f[7], f"{path}.buyer_bond_lovelace"),
            supplier_bond_lovelace=_int(f[8], f"{path}.supplier_bond_lovelace"),
            deliver_by=_int(f[9], f"{path}.deliver_by"),
            posted_at=_int(f[10], f"{path}.posted_at"),
            submitted_at=_option(f[11], f"{path}.submitted_at", _ints),
            result_receipt_hash=_option(f[12], f"{path}.result_receipt_hash", _sized(32)),
            state=EscrowState(state),
            agent_id=_bytes(f[14], f"{path}.agent_id", 32),
            refund=_option(f[15], f"{path}.refund", Refund.from_data),
        )


@dataclass(frozen=True)
class EscrowRedeemer(_Codec):
    """Escrow redeemers in the legacy order, then ``RefundRevoked``."""

    ACTIONS: ClassVar[tuple[str, ...]] = (
        "Claim",
        "Submit",
        "Accept",
        "Reclaim",
        "Release",
        "RefundRevoked",
    )

    action: str
    receipt_hash: bytes | None = None

    def __post_init__(self) -> None:
        if self.action not in self.ACTIONS:
            raise ValueError(f"unknown escrow action {self.action!r}")
        if (self.receipt_hash is not None) != (self.action == "Submit"):
            raise ValueError("receipt_hash is set exactly for Submit")

    def to_data(self) -> Constr:
        index = self.ACTIONS.index(self.action)
        if self.receipt_hash is not None:
            return Constr(index, (self.receipt_hash,))
        return Constr(index)

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "EscrowRedeemer") -> EscrowRedeemer:
        index, fields = _variant(data, path, (0, 1, 0, 0, 0, 0))
        if index == 1:
            return cls("Submit", _bytes(fields[0], f"{path}.receipt_hash", 32))
        return cls(cls.ACTIONS[index])


class AdvertStatus(IntEnum):
    ACTIVE = 0
    RETIRED = 1


@dataclass(frozen=True)
class AdvertDatum(_Codec):
    """The new advert datum: the 13 legacy fields and ``agent_id`` as field 13."""

    supplier_pkh: bytes
    capability_id: bytes
    model: bytes
    max_output_tokens: int
    max_processing_ms: int
    price_lovelace: int
    supplier_bond_lovelace: int
    buyer_bond_lovelace: int
    endpoint_url: bytes
    detail_uri: bytes
    detail_hash: bytes
    advertised_at: int
    status: AdvertStatus
    agent_id: bytes

    def to_data(self) -> Constr:
        return Constr(
            0,
            (
                self.supplier_pkh,
                self.capability_id,
                self.model,
                self.max_output_tokens,
                self.max_processing_ms,
                self.price_lovelace,
                self.supplier_bond_lovelace,
                self.buyer_bond_lovelace,
                self.endpoint_url,
                self.detail_uri,
                self.detail_hash,
                self.advertised_at,
                Constr(int(self.status)),
                self.agent_id,
            ),
        )

    @classmethod
    def from_data(cls, data: PlutusData, path: str = "AdvertDatum") -> AdvertDatum:
        f = _fields(data, path, 0, 14)
        status, _ = _variant(f[12], f"{path}.status", (0, 0))
        return cls(
            supplier_pkh=_bytes(f[0], f"{path}.supplier_pkh", 28),
            capability_id=_bytes(f[1], f"{path}.capability_id"),
            model=_bytes(f[2], f"{path}.model"),
            max_output_tokens=_int(f[3], f"{path}.max_output_tokens"),
            max_processing_ms=_int(f[4], f"{path}.max_processing_ms"),
            price_lovelace=_int(f[5], f"{path}.price_lovelace"),
            supplier_bond_lovelace=_int(f[6], f"{path}.supplier_bond_lovelace"),
            buyer_bond_lovelace=_int(f[7], f"{path}.buyer_bond_lovelace"),
            endpoint_url=_bytes(f[8], f"{path}.endpoint_url"),
            detail_uri=_bytes(f[9], f"{path}.detail_uri"),
            detail_hash=_bytes(f[10], f"{path}.detail_hash", 32),
            advertised_at=_int(f[11], f"{path}.advertised_at"),
            status=AdvertStatus(status),
            agent_id=_bytes(f[13], f"{path}.agent_id", 32),
        )


class AdvertRedeemer(IntEnum):
    POST_ADVERT = 0
    UPDATE_ADVERT = 1
    RETIRE_ADVERT = 2

    def to_data(self) -> Constr:
        return Constr(int(self))


# ---------------------------------------------------------------------------
# Decoders of the sum types, by CBOR
# ---------------------------------------------------------------------------


def _from_cbor(decode: Callable[[PlutusData, str], T], raw: bytes | str, name: str) -> T:
    if isinstance(raw, str):
        raw = bytes.fromhex(raw)
    return decode(decode_data(raw), name)


def decode_identity_mint(raw: bytes | str) -> IdentityMint:
    return _from_cbor(identity_mint_from_data, raw, "IdentityMint")


def decode_attestation_mint(raw: bytes | str) -> AttestationMint:
    return _from_cbor(attestation_mint_from_data, raw, "AttestationMint")


def decode_attestation_spend(raw: bytes | str) -> AttestationSpend:
    return _from_cbor(attestation_spend_from_data, raw, "AttestationSpend")


def decode_delegation_mint(raw: bytes | str) -> DelegationMint:
    return _from_cbor(delegation_mint_from_data, raw, "DelegationMint")


def decode_vault_datum(raw: bytes | str) -> VaultDatum:
    return _from_cbor(vault_datum_from_data, raw, "VaultDatum")


def decode_vault_spend(raw: bytes | str) -> VaultSpend:
    index, _ = _from_cbor(lambda d, p: _variant(d, p, (0, 0)), raw, "VaultSpend")
    return VaultSpend(index)


def decode_advert_redeemer(raw: bytes | str) -> AdvertRedeemer:
    index, _ = _from_cbor(lambda d, p: _variant(d, p, (0, 0, 0)), raw, "AdvertRedeemer")
    return AdvertRedeemer(index)
