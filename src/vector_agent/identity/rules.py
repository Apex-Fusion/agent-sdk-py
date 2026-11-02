"""Off-chain copies of the contract rules that the builders check first.

The functions follow the on-chain library ``vector_identity`` (Part 2 §3.10)
and the validity rules of the datums (Part 2 §3.3, §4.1, §5.1, §5.2). A
builder that breaks one of them would only produce a transaction that the
ledger rejects, so the builders refuse early with a clear message instead.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import replace
from enum import Enum

from vector_agent.identity.constants import (
    ATTESTATION_TYPES,
    CAPABILITY_MAX_BYTES,
    DAYS_30_MS,
    DAYS_366_MS,
    DESCRIPTION_MAX_BYTES,
    ENDPOINT_MAX_BYTES,
    FRAMEWORK_MAX_BYTES,
    LOCATOR_MAX_BYTES,
    MAX_ACTIONS,
    MAX_CAPABILITIES,
    MAX_CONTENT_FORMAT,
    MAX_DEPTH,
    MAX_ESCROW_LOVELACE,
    MAX_HOLDS,
    MAX_KEYS,
    MAX_LINK_REL,
    MAX_LINKS,
    MAX_PARTIES,
    MAX_RECORD_INT,
    MAX_RESOURCES,
    MAX_TIME_MS,
    NAME_MAX_BYTES,
    ORGANISATION_MAX_BYTES,
    PURPOSE_ASSERTION,
    PURPOSE_AUTHENTICATION,
    PURPOSE_DELEGATION,
    PURPOSE_TRANSACTION,
    RIGHT_RECOVER,
    ROLE_MAX_RIGHTS,
)
from vector_agent.identity.errors import IdentityRuleError
from vector_agent.identity.ids import blake2b_224
from vector_agent.identity.types import (
    AgentDelegator,
    AttestationDatum,
    ControllerSetSigner,
    DelegationDatum,
    Hold,
    IdentityDatum,
    Key,
    KeyHashSigner,
    KeyType,
    Party,
    PrincipalKey,
    Retired,
    Revoked,
    Role,
    Root,
    ScriptSigner,
    Signer,
    Status,
    Subagent,
    Suspended,
    ValueLimit,
)

__all__ = [
    "Effective",
    "accountable",
    "active_key",
    "covered",
    "covers",
    "covers_pattern",
    "current_author",
    "effective",
    "eligible_guardian",
    "guardian_bound",
    "has_capability",
    "has_right",
    "holds_of",
    "identity_datum_problems",
    "independent",
    "kept_holds",
    "narrower",
    "terminal",
    "tombstone",
    "valid_action_pattern",
    "valid_limit",
    "valid_resource_pattern",
    "validate_attestation",
    "validate_delegation",
    "validate_identity_datum",
]


class Effective(Enum):
    """The effective status of ``vector_identity.effective``."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    RETIRED = "retired"


# ---------------------------------------------------------------------------
# vector_identity (Part 2 §3.10) and §3.2 definitions
# ---------------------------------------------------------------------------


def _key_has_purpose(key: Key, purpose: int) -> bool:
    if purpose in (PURPOSE_AUTHENTICATION, PURPOSE_ASSERTION):
        allowed = True
    elif purpose in (PURPOSE_TRANSACTION, PURPOSE_DELEGATION):
        allowed = key.key_type == KeyType.ED25519
    else:
        allowed = False
    return allowed and (key.purposes // purpose) % 2 == 1


def active_key(record: IdentityDatum, key_hash: bytes, purpose: int) -> bool:
    """The record lists a key with ``blake2b_224(key) == key_hash`` and the purpose."""
    return any(
        _key_has_purpose(key, purpose) and blake2b_224(key.key) == key_hash for key in record.keys
    )


def independent(record: IdentityDatum) -> bool:
    return isinstance(record.lineage, Root)


def has_capability(record: IdentityDatum, capability: bytes) -> bool:
    return capability in record.capabilities


def has_right(rights: int, right: int) -> bool:
    return (rights // right) % 2 == 1


def terminal(status: Status) -> bool:
    return isinstance(status, (Revoked, Retired))


def covers(party: Party, lo: int, hi: int) -> bool:
    """``not_before <= lo``, and ``not_after`` is empty or ``>= hi``."""
    return party.not_before <= lo and (party.not_after is None or party.not_after >= hi)


def accountable(record: IdentityDatum, lo: int, hi: int) -> bool:
    return any(p.role == Role.ACCOUNTABLE and covers(p, lo, hi) for p in record.parties)


def eligible_guardian(party: Party, lo: int, hi: int) -> bool:
    return party.role == Role.GUARDIAN and has_right(party.rights, RIGHT_RECOVER) and covers(party, lo, hi)


def guardian_bound(record: IdentityDatum, hi: int) -> bool:
    """``guardian_threshold`` is at most the number of guardians with the recover right in time."""
    count = sum(
        1
        for p in record.parties
        if p.role == Role.GUARDIAN
        and has_right(p.rights, RIGHT_RECOVER)
        and (p.not_after is None or p.not_after >= hi)
    )
    return record.guardian_threshold <= count


def holds_of(status: Status) -> tuple[Hold, ...]:
    return status.holds if isinstance(status, Suspended) else ()


def current_author(signer: Signer, parties: Iterable[Party]) -> bool:
    if isinstance(signer, KeyHashSigner):
        return any(p.signer == signer for p in parties)
    return True


def kept_holds(holds: Sequence[Hold], parties: Sequence[Party], lo: int, author: Signer) -> tuple[Hold, ...]:
    """The holds in force whose author is a current author other than ``author``."""
    return tuple(
        h for h in holds if h.until > lo and h.by != author and current_author(h.by, parties)
    )


def tombstone(record: IdentityDatum, status: Status) -> IdentityDatum:
    """The tombstone of ``record`` (Part 2 §3.7)."""
    return replace(
        record,
        keys=(),
        parties=(),
        guardian_threshold=0,
        pending_recovery=None,
        description=b"",
        framework=b"",
        endpoint=b"",
        capabilities=(),
        status=status,
    )


def effective(
    record: IdentityDatum,
    find: Callable[[bytes], IdentityDatum | None],
    lo: int,
    hi: int,
) -> Effective:
    """``vector_identity.effective`` over ``[lo, hi]``; ``find`` returns an ancestor record.

    Raises ``LookupError`` when an ancestor is missing (the contract fails then).
    """
    return _effective_within(record, find, lo, hi, MAX_DEPTH)


def _effective_within(record, find, lo, hi, left) -> Effective:
    if isinstance(record.status, Revoked):
        return Effective.REVOKED
    if isinstance(record.status, Retired):
        return Effective.RETIRED
    inherited = Effective.ACTIVE
    if isinstance(record.lineage, Subagent):
        if left <= 0:
            raise LookupError("the lineage is deeper than 4 ancestors")
        parent = find(record.lineage.parent)
        if parent is None:
            raise LookupError(f"ancestor {record.lineage.parent.hex()} not found")
        if parent.subagent_epoch > record.lineage.parent_epoch:
            inherited = Effective.REVOKED
        else:
            inherited = _effective_within(parent, find, lo, hi, left - 1)
    if inherited != Effective.ACTIVE:
        return inherited
    if any(h.until > lo for h in holds_of(record.status)):
        return Effective.SUSPENDED
    return Effective.ACTIVE if accountable(record, lo, hi) else Effective.SUSPENDED


# ---------------------------------------------------------------------------
# Valid identity datum (Part 2 §3.3)
# ---------------------------------------------------------------------------


def _valid_time(t: int | None) -> bool:
    return t is None or (isinstance(t, int) and 0 <= t <= MAX_TIME_MS)


def _valid_uint(n: int) -> bool:
    return isinstance(n, int) and 0 <= n <= MAX_RECORD_INT


def _signer_problem(signer: Signer, role: Role | None, m1: bytes | None) -> str | None:
    if isinstance(signer, KeyHashSigner):
        return None if len(signer.hash) == 28 else "a key hash signer must have 28 bytes"
    if isinstance(signer, ScriptSigner):
        if len(signer.hash) != 28:
            return "a script signer must have 28 bytes"
        if role is not None and role not in (Role.ACCOUNTABLE, Role.RESPONSIBLE):
            return f"role {role.name} cannot have a script signer"
        if role is not None and signer.hash != m1:
            return "a script party must be the approved Module-1 contract (configuration record)"
        return None
    if isinstance(signer, ControllerSetSigner):
        if role is not None and role not in (Role.ACCOUNTABLE, Role.RESPONSIBLE):
            return f"role {role.name} cannot have the controller as signer"
        return None
    return "unknown signer"


def _key_problem(key: Key) -> str | None:
    if key.key_type == KeyType.ED25519:
        if len(key.key) != 32:
            return "an Ed25519 key has 32 bytes"
        if key.pop is not None:
            return "an Ed25519 key has no pop"
        if not 1 <= key.purposes <= 27 or (key.purposes // 4) % 2:
            return "Ed25519 purposes are a non-empty sum of 1, 2, 8 and 16"
        return None
    if len(key.key) != 33:
        return "a P-256 key is a 33-byte compressed point"
    if key.pop is None or len(key.pop) != 64:
        return "a P-256 key needs a 64-byte pop"
    if not 1 <= key.purposes <= 3:
        return "P-256 purposes are a non-empty sum of 1 and 2"
    return None


def _party_problem(party: Party, m1: bytes | None) -> str | None:
    if not 0 <= party.rights <= 7 or party.rights & ~ROLE_MAX_RIGHTS[party.role]:
        return f"rights {party.rights} exceed the highest rights of role {party.role.name}"
    problem = _signer_problem(party.signer, party.role, m1)
    if problem:
        return problem
    if party.organisation is not None and not 1 <= len(party.organisation) <= ORGANISATION_MAX_BYTES:
        return "organisation has 1..64 bytes"
    if not _valid_time(party.not_before) or not _valid_time(party.not_after):
        return "party times must be valid times"
    if party.not_after is not None and party.not_after <= party.not_before:
        return "not_after must be after not_before"
    if not _valid_time(party.removal_after):
        return "removal_after must be a valid time"
    return None


def _hold_problems(holds: Sequence[Hold]) -> list[str]:
    problems = []
    if not 1 <= len(holds) <= MAX_HOLDS:
        problems.append("a suspended record has 1..10 holds")
    authors = [h.by for h in holds]
    if len(set(authors)) != len(authors):
        problems.append("each author has at most one hold")
    for h in holds:
        problem = _signer_problem(h.by, None, None)
        if problem:
            problems.append(problem)
        if not (_valid_uint(h.reason) and _valid_time(h.since) and _valid_time(h.until)):
            problems.append("hold fields must be valid")
        if not h.since < h.until or h.until - h.since > DAYS_30_MS:
            problems.append("a hold lasts at most 30 days, with since < until")
    return problems


def identity_datum_problems(record: IdentityDatum, m1: bytes | None = None) -> list[str]:
    """Every reason why ``record`` is not a valid datum (empty when it is valid)."""
    problems: list[str] = []
    if len(record.controller) != 32:
        problems.append("controller is a 32-byte Ed25519 key")
    if len(record.keys) > MAX_KEYS:
        problems.append("at most 8 keys")
    key_bytes = [k.key for k in record.keys]
    if len(set(key_bytes)) != len(key_bytes):
        problems.append("a key is listed twice")
    problems += [f"key {i}: {p}" for i, k in enumerate(record.keys) if (p := _key_problem(k))]
    if len(record.parties) > MAX_PARTIES:
        problems.append("at most 8 parties")
    pairs = [(p.role, p.signer) for p in record.parties]
    if len(set(pairs)) != len(pairs):
        problems.append("two parties have the same role and signer")
    problems += [f"party {i}: {p}" for i, q in enumerate(record.parties) if (p := _party_problem(q, m1))]
    if not _valid_uint(record.guardian_threshold):
        problems.append("guardian_threshold must be >= 0")
    if record.pending_recovery is not None:
        if record.guardian_threshold < 1:
            problems.append("a pending recovery needs a guardian threshold of at least 1")
        if len(record.pending_recovery.new_controller) != 32:
            problems.append("the new controller is a 32-byte key")
        if not _valid_time(record.pending_recovery.effective_after):
            problems.append("effective_after must be a valid time")
    if isinstance(record.lineage, Subagent):
        lineage = record.lineage
        if len(lineage.parent) != 32 or not _valid_uint(lineage.parent_epoch):
            problems.append("a subagent names a 32-byte parent and a valid epoch")
        if not 1 <= lineage.depth <= MAX_DEPTH:
            problems.append("a subagent depth is 1..4")
        if record.endpoint:
            problems.append("a subagent has an empty endpoint")
    if not _valid_uint(record.subagent_epoch):
        problems.append("subagent_epoch must be >= 0")
    if not 1 <= len(record.name) <= NAME_MAX_BYTES:
        problems.append("name has 1..64 bytes")
    if len(record.description) > DESCRIPTION_MAX_BYTES:
        problems.append("description has at most 256 bytes")
    if len(record.framework) > FRAMEWORK_MAX_BYTES:
        problems.append("framework has at most 64 bytes")
    if len(record.endpoint) > ENDPOINT_MAX_BYTES:
        problems.append("endpoint has at most 256 bytes")
    if len(record.capabilities) > MAX_CAPABILITIES:
        problems.append("at most 16 capabilities")
    if len(set(record.capabilities)) != len(record.capabilities):
        problems.append("a capability is listed twice")
    if any(not 1 <= len(c) <= CAPABILITY_MAX_BYTES for c in record.capabilities):
        problems.append("a capability has 1..64 bytes")
    if not _valid_time(record.created_at):
        problems.append("created_at must be a valid time")
    status = record.status
    if isinstance(status, Suspended):
        problems += _hold_problems(status.holds)
    elif terminal(status):
        cleared = tombstone(record, status)
        if cleared != record:
            problems.append("a tombstone has no keys, parties, threshold, recovery or profile text")
        if isinstance(status, Revoked) and (
            _signer_problem(status.by, None, None)
            or not _valid_uint(status.reason)
            or not _valid_time(status.at)
            or not _valid_time(status.invalid_from)
        ):
            problems.append("revocation fields must be valid")
        successor = status.successor
        if successor is not None and len(successor) != 32:
            problems.append("a successor is a 32-byte identifier")
    return problems


def validate_identity_datum(record: IdentityDatum, m1: bytes | None = None) -> None:
    """Raise ``ValueError`` when ``record`` is not a valid datum (Part 2 §3.3)."""
    problems = identity_datum_problems(record, m1)
    if problems:
        raise IdentityRuleError("invalid identity record: " + "; ".join(problems))


# ---------------------------------------------------------------------------
# Attestations (Part 2 §4.1)
# ---------------------------------------------------------------------------


def validate_attestation(datum: AttestationDatum) -> None:
    """Raise ``ValueError`` when the content rules of a new attestation fail."""
    problems = []
    if len(datum.subject) != 32 or len(datum.issuer) != 32:
        problems.append("subject and issuer have 32 bytes")
    if datum.issuer_id is not None and len(datum.issuer_id) != 32:
        problems.append("issuer_id has 32 bytes")
    if datum.att_type not in ATTESTATION_TYPES:
        problems.append("att_type is 0..5 or 15")
    if datum.format is not None and not 0 <= datum.format <= MAX_CONTENT_FORMAT:
        problems.append("format is a CoAP Content-Format number (0..65535)")
    if datum.profile is not None and len(datum.profile) != 32:
        problems.append("profile has 32 bytes")
    if len(datum.digest) != 32:
        problems.append("digest is a 32-byte SHA-256")
    if datum.locator is not None and len(datum.locator) > LOCATOR_MAX_BYTES:
        problems.append("locator has at most 256 bytes")
    if datum.envelope_sig is not None and len(datum.envelope_sig) != 64:
        problems.append("envelope_sig has 64 bytes")
    if datum.valid_until is None:
        if datum.att_type in (2, 3):
            problems.append("types 2 and 3 need valid_until")
        limit = MAX_TIME_MS
    else:
        if not datum.issued_at <= datum.valid_until <= datum.issued_at + DAYS_366_MS:
            problems.append("valid_until is in [issued_at, issued_at + 366 days]")
        limit = datum.valid_until
    if datum.valid_from is not None and not (_valid_time(datum.valid_from) and datum.valid_from <= limit):
        problems.append("valid_from is at or before valid_until")
    if len(datum.links) > MAX_LINKS:
        problems.append("at most 4 links")
    if any(not 0 <= link.rel <= MAX_LINK_REL or len(link.target) != 32 for link in datum.links):
        problems.append("a link has rel 0..3 and a 32-byte target")
    if problems:
        raise IdentityRuleError("invalid attestation: " + "; ".join(problems))


# ---------------------------------------------------------------------------
# Delegation patterns (Part 2 §5.1) and datums (§5.2)
# ---------------------------------------------------------------------------

_SEG = r"[a-z0-9-]+"
_INTERNAL = re.compile(rf"{_SEG}(?:\.{_SEG})*")
_PREFIX = re.compile(rf"{_SEG}(?:\.{_SEG})*\.\*")
_EXTERNAL = re.compile(r"(?:oauth:|mcp:|https://)[\x21-\x7e]+")
_SCRIPT = re.compile(r"script:[0-9a-f]{56}")


def _text(pattern: bytes) -> str | None:
    try:
        return pattern.decode("ascii")
    except UnicodeDecodeError:
        return None


def valid_action_pattern(pattern: bytes) -> bool:
    text = _text(pattern)
    return text is not None and (
        text == "*"
        or _EXTERNAL.fullmatch(text) is not None
        or _PREFIX.fullmatch(text) is not None
        or _INTERNAL.fullmatch(text) is not None
    )


def valid_resource_pattern(pattern: bytes) -> bool:
    text = _text(pattern)
    return text is not None and (
        text == "*" or _EXTERNAL.fullmatch(text) is not None or _SCRIPT.fullmatch(text) is not None
    )


def covers_pattern(pattern: bytes, value: bytes) -> bool:
    """``p = "*"``, ``p = a``, or ``p = x ".*"`` and ``a`` starts with ``x "."``."""
    if pattern in (b"*", value):
        return True
    return (
        len(pattern) >= 3
        and pattern.endswith(b".*")
        and value.startswith(pattern[:-1])
        and not pattern.startswith((b"mcp:", b"oauth:", b"https://", b"script:"))
    )


def covered(patterns: Iterable[bytes], value: bytes) -> bool:
    return any(covers_pattern(p, value) for p in patterns)


def narrower(child: Iterable[bytes], parent: Sequence[bytes]) -> bool:
    return all(covered(parent, p) for p in child)


def valid_limit(limit: ValueLimit) -> bool:
    return (
        0 <= limit.per_tx <= limit.total <= MAX_ESCROW_LOVELACE
        and 1 <= limit.period_ms <= MAX_RECORD_INT
    )


def validate_delegation(datum: DelegationDatum) -> None:
    """Raise ``ValueError`` when the datum breaks the rules of Part 2 §5.1–§5.2."""
    problems = []
    delegator = datum.delegator
    if isinstance(delegator, PrincipalKey):
        if len(delegator.hash) != 28:
            problems.append("a principal key hash has 28 bytes")
        if delegator.organisation is not None and not 1 <= len(delegator.organisation) <= 64:
            problems.append("organisation has 1..64 bytes")
    elif isinstance(delegator, AgentDelegator) and len(delegator.id) != 32:
        problems.append("an agent delegator id has 32 bytes")
    if datum.parent is not None and len(datum.parent) != 32:
        problems.append("parent has 32 bytes")
    if len(datum.delegate) != 32 or len(datum.delegate_key) != 28:
        problems.append("delegate has 32 bytes and delegate_key 28 bytes")
    if not 1 <= len(datum.actions) <= MAX_ACTIONS:
        problems.append("1..16 action patterns")
    if any(not valid_action_pattern(a) for a in datum.actions):
        problems.append("an action pattern does not follow §5.1")
    if len(datum.resources) > MAX_RESOURCES:
        problems.append("at most 8 resource patterns")
    if any(not valid_resource_pattern(r) for r in datum.resources):
        problems.append("a resource pattern does not follow §5.1")
    if not (_valid_time(datum.not_before) and _valid_time(datum.not_after)):
        problems.append("not_before and not_after must be valid times")
    if datum.not_before >= datum.not_after:
        problems.append("not_before < not_after")
    if not 1 <= datum.depth or datum.remaining < 0 or datum.depth + datum.remaining > MAX_DEPTH:
        problems.append("depth >= 1, remaining >= 0 and depth + remaining <= 4")
    if datum.purpose is not None and len(datum.purpose) != 32:
        problems.append("purpose has 32 bytes")
    if datum.value is not None and not valid_limit(datum.value):
        problems.append("value limit: 0 <= per_tx <= total <= 10,000 AP3X, 1 <= period_ms")
    if problems:
        raise IdentityRuleError("invalid delegation: " + "; ".join(problems))

