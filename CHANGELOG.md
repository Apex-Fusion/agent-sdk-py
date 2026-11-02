# Changelog

## 0.2.0

This release also contains the unreleased 0.1.11 changes.

### Breaking changes

- **Dependencies.** `pycardano` is now `>=0.19.2,<0.20`. `cbor2` is now `<6`: pycardano 0.19.2 fails on import with cbor2 6.x. `mcp` is now `<2`: mcp 2.x removed `streamablehttp_client`, which `VectorAgentMCP` uses, so `import vector_agent` failed with mcp 2.x. `pynacl` is now a direct dependency.
- **`import vector_agent` also imports `vector_agent.identity`.**
- **`VectorChainContext.evaluate_tx_cbor` no longer prints debug lines.**
- **Development tools.** The `dev` group pins `ruff>=0.17.3,<0.18`.
- From 0.1.11: `VectorAgentMCP` connects to the hosted server over Streamable HTTP at `/mcp` instead of SSE. Set `VECTOR_MCP_URL` to the `/mcp` URL.

### New: identity registry clients (`vector_agent.identity`)

- `IdentityRegistry`: register (also subagents), adopt a legacy record, update, change controller, suspend, unsuspend, revoke, retire, reclaim, set successor, start, cancel and complete recovery, and end subagents. `revoke` takes `invalid_from` in `[created_at − 3,600,000, lo]`, so a revocation for key compromise is possible at once after the creation.
- `Attestations`: attest (with an optional COSE_Sign1 envelope), revoke, contest and withdraw.
- `Delegations`: delegate and undelegate.
- `Vaults`: open, pay (new escrows from a vault) and close.
- `IdentityGateway`: DID resolution and the current record through the gateway's HTTPS binding.
- Builders return an unsigned transaction and every key hash that must sign it. The SDK never signs; `add_signatures` adds the caller's witnesses.
- Codecs for every on-chain type, byte-compatible with Aiken `cbor.serialise`.
- The unapplied scripts of the identity-marketplace blueprint (agents-marketplace `1643583`) and the deployed legacy registry script are embedded. The deployment values come from configuration (`VECTOR_IDENTITY_*`).

### Changed: the Self-Improvement client (`vector_agent.governance`) moves to the new Module-6 deployment

- The client builds the transactions of the Module-6 deployment that reads identity records (vector-agent-modules `91e3823`; the blueprint is embedded with a sha256 pin). Positions of the old deployment stay where they are; exit them with SDK 0.1.x.
- `Governance` (new): builders of every Module-6 transaction. They add the agent's record and its ancestors as reference inputs, set a validity range of at most one hour with `submitted_at`/`created_at` = `lo`, use the activity list (one node per agent; a first proposal inserts it), mint the `gend_` token of an endorsement through `critique_mint`, and name a proposal by its seed.
- `GovernanceClient` takes a `GovernanceDeployment` (from `VECTOR_MODULE6_*` or the deploy state) instead of script CBOR. One method per action: `submit_proposal` (lock, then create; replaces `validated_submit_proposal`), `amend_proposal`, `withdraw_proposal`, `expire_proposal`, `expire_stale_proposal`, `adopt_proposal`, `reject_proposal`, `extend_review`, `submit_critique`, `withdraw_critique`, `endorse_proposal`, `withdraw_endorsement`. `set_reference_utxos`, `set_governance_reference_inputs` and the `validated_*` variants are removed.
- `datums.py` builds the 11-field `GovernanceConfig` (`identity_hash` last), the 5-field `ProposerActivityDatum` and `GovernanceCrossRefs`, and takes 32-byte agent identifiers. The types in `governance.types` are typed codecs.
- `GovernanceIndexer` reads both layouts and links critiques and endorsements to proposals by the seed token (`proposal_token`).
- `SELF_IMPROVEMENT_*_CBOR` and `GOVERNANCE_*_CBOR` are no longer read.

### From 0.1.11

- Self-Improvement import name and `SELF_IMPROVEMENT_*` environment variables (the `GOVERNANCE_*` names stay as fallbacks).
- AP3X and dfm amount aliases.
- `VectorAgentMCP` parses the text answers of the hosted server.
