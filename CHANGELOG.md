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

### From 0.1.11

- Self-Improvement import name and `SELF_IMPROVEMENT_*` environment variables (the `GOVERNANCE_*` names stay as fallbacks).
- AP3X and dfm amount aliases.
- `VectorAgentMCP` parses the text answers of the hosted server.
