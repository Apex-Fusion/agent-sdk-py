"""Clients for the Vector identity registry (``did:vector``).

- :class:`IdentityRegistry`: register (also subagents), adopt, update, change
  controller, suspend, unsuspend, revoke, retire, reclaim, set successor,
  start, cancel and complete recovery, and end subagents (Part 2 §3).
- :class:`Attestations`: attest, revoke, contest and withdraw (Part 2 §4).
- :class:`Delegations`: delegate and undelegate (Part 2 §5.2).
- :class:`Vaults`: open, pay and close (Part 2 §5.3).
- :class:`IdentityGateway`: DID resolution and the current record through the
  gateway's HTTPS binding (Part 1 §7.4).

Builders return an unsigned :class:`BuiltTx` with the key hashes that must
sign it; signing stays with the caller (:func:`add_signatures`). Script
parameters are deployment values from :class:`IdentityConfig`; on mainnet,
unset values take :data:`MAINNET_IDENTITY_DEPLOYMENT`.
"""

from vector_agent.identity.attestation import (
    Attestations,
    did_key,
    envelope_sig_structure,
    verify_envelope,
)
from vector_agent.identity.chain import Ledger, OgmiosKoiosLedger, SlotClock
from vector_agent.identity.config import ENV_VARS, MAINNET_IDENTITY_DEPLOYMENT, IdentityConfig, PublishedDeployment
from vector_agent.identity.context import AuthenticOutput, IdentityContext
from vector_agent.identity.delegation import Delegations, escrow_resource
from vector_agent.identity.errors import IdentityConfigError, IdentityLookupError, IdentityRuleError
from vector_agent.identity.gateway import (
    AgentView,
    DidResolution,
    DidResolutionError,
    IdentityGateway,
    ResolvedKey,
)
from vector_agent.identity.ids import (
    allowlist_proof,
    allowlist_root,
    dns_safe,
    key_hash,
    legacy_vector_did,
    parse_vector_did,
    vector_did,
    vector_id_from_seed,
    verify_allowlist_proof,
)
from vector_agent.identity.registry import (
    IdentityRegistry,
    PartySpec,
    ed25519_key,
    p256_key,
    p256_pop_message,
)
from vector_agent.identity.rules import Effective, effective
from vector_agent.identity.scripts import IdentityScripts
from vector_agent.identity.tx import DEFAULT_VALID_FOR_S, BuiltTx, add_signatures
from vector_agent.identity.types import (
    CONTROLLER_SET,
    AgentDelegator,
    AttestationDatum,
    DelegationDatum,
    EscrowDatum,
    IdentityDatum,
    Key,
    KeyHashSigner,
    KeyType,
    Link,
    OutputReference,
    Party,
    PrincipalKey,
    Role,
    ScriptSigner,
    ValueLimit,
    VaultLive,
    VaultReturned,
)
from vector_agent.identity.vault import VaultJob, Vaults

__all__ = [
    "CONTROLLER_SET",
    "DEFAULT_VALID_FOR_S",
    "ENV_VARS",
    "MAINNET_IDENTITY_DEPLOYMENT",
    "AgentDelegator",
    "AgentView",
    "AttestationDatum",
    "Attestations",
    "AuthenticOutput",
    "BuiltTx",
    "DelegationDatum",
    "Delegations",
    "DidResolution",
    "DidResolutionError",
    "Effective",
    "EscrowDatum",
    "IdentityConfig",
    "IdentityConfigError",
    "IdentityContext",
    "IdentityDatum",
    "IdentityGateway",
    "IdentityLookupError",
    "IdentityRegistry",
    "IdentityRuleError",
    "IdentityScripts",
    "Key",
    "KeyHashSigner",
    "KeyType",
    "Ledger",
    "Link",
    "OgmiosKoiosLedger",
    "OutputReference",
    "Party",
    "PartySpec",
    "PrincipalKey",
    "PublishedDeployment",
    "ResolvedKey",
    "Role",
    "ScriptSigner",
    "SlotClock",
    "ValueLimit",
    "VaultJob",
    "VaultLive",
    "VaultReturned",
    "Vaults",
    "add_signatures",
    "allowlist_proof",
    "allowlist_root",
    "did_key",
    "dns_safe",
    "ed25519_key",
    "effective",
    "envelope_sig_structure",
    "escrow_resource",
    "key_hash",
    "legacy_vector_did",
    "p256_key",
    "p256_pop_message",
    "parse_vector_did",
    "vector_did",
    "vector_id_from_seed",
    "verify_allowlist_proof",
    "verify_envelope",
]
