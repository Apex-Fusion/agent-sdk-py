"""An offline ledger for the identity client tests.

``World`` is a PyCardano ``ChainContext`` and an identity ``Ledger`` over an
in-memory UTxO set. It holds a test deployment of the embedded scripts (the
real legacy registry hash, a test allowlist root and a test configuration
seed), their reference-script outputs, the configuration record and a
Module-1 stand-in (an always-succeeding Plutus V3 script).

When ``aiken`` is on PATH, the transaction evaluation runs ``aiken tx simulate``
(the evaluator of the compiler that built the scripts) on the transaction and
its resolved inputs, so every build in the tests runs the real validators. A
failing script fails the build. Without ``aiken``, evaluation returns fixed
execution units and only the off-chain checks run.

The protocol parameters and the genesis values are a copy of Vector mainnet
(``fixtures/vector-mainnet-ogmios.json``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

import cbor2
from pycardano import (
    Address,
    Asset,
    AssetName,
    ExecutionUnits,
    MultiAsset,
    Network,
    PaymentSigningKey,
    PlutusV3Script,
    ScriptHash,
    Transaction,
    TransactionId,
    TransactionInput,
    TransactionOutput,
    UTxO,
    Value,
    VerificationKeyHash,
)
from pycardano.backend.base import ChainContext
from pycardano.serialization import RawCBOR

from vector_agent.chain.context import VectorChainContext
from vector_agent.identity import IdentityConfig, IdentityContext, OutputReference, SlotClock
from vector_agent.identity.constants import CONFIG_TOKEN_NAME, MAINNET_SYSTEM_START_MS
from vector_agent.identity.ids import allowlist_root, blake2b_256
from vector_agent.identity.plutus_data import encode_data
from vector_agent.identity.tx import BuiltTx

FIXTURES = Path(__file__).parent / "fixtures"
OGMIOS = json.loads((FIXTURES / "vector-mainnet-ogmios.json").read_text())
AIKEN = shutil.which("aiken")

#: ``(program 1.1.0 (lam ctx (con unit ())))``: a Plutus V3 script that accepts everything.
ALWAYS_OK_V3 = bytes.fromhex("450101002499")
ZERO_KEY_ADDRESS = Address(payment_part=VerificationKeyHash(bytes(28)), network=Network.MAINNET)
CONFIG_SEED = OutputReference(bytes([0x5E]) * 32, 3)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TAGS = {0: "spend", 1: "mint", 2: "certificate", 3: "withdrawal", 4: "vote", 5: "proposing"}


def signing_key(label: str) -> PaymentSigningKey:
    """A throwaway Ed25519 key derived from ``label``."""
    return PaymentSigningKey(hashlib.sha256(label.encode()).digest())


def public_key(key: PaymentSigningKey) -> bytes:
    return bytes(key.to_verification_key().payload)


def key_hash(key: PaymentSigningKey) -> bytes:
    return bytes(key.to_verification_key().hash().payload)


def key_address(key: PaymentSigningKey) -> Address:
    return Address(payment_part=VerificationKeyHash(key_hash(key)), network=Network.MAINNET)


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")


def _unwrap(value):
    return value.value if isinstance(value, cbor2.CBORTag) else value


class ScriptFailure(RuntimeError):
    """``aiken tx simulate`` rejected the transaction."""


class World(ChainContext):
    """An offline Vector ledger with a test deployment of the identity scripts."""

    def __init__(self, *, tip_slot: int = 6_000_000, allowlist: tuple[str, ...] = (), simulate: bool = True):
        self.tip = tip_slot
        self._pp = VectorChainContext._build_protocol_params(OGMIOS["protocolParameters"])
        self._genesis = VectorChainContext._build_genesis_params(OGMIOS["genesis"])
        self.ledger_state: dict[TransactionInput, UTxO] = {}
        self._counter = 0
        self.simulated = 0
        self.simulate_scripts = simulate and AIKEN is not None
        self.allowlist = allowlist or (bytes(32).hex(),)
        base = IdentityConfig(legacy_root=allowlist_root(self.allowlist), config_seed=CONFIG_SEED)
        scripts = base.scripts()
        self.scripts = scripts
        refs = {}
        for name in ("identity", "attestation", "delegation", "vault"):
            utxo = self.put(
                TransactionOutput(ZERO_KEY_ADDRESS, 100_000_000, script=getattr(scripts, name).plutus_script)
            )
            refs[f"{name}_ref"] = utxo_ref(utxo)
        module1_script = PlutusV3Script(ALWAYS_OK_V3)
        self.module1 = module1_hash = bytes(_script_hash(module1_script))
        refs["module1_ref"] = utxo_ref(self.put(TransactionOutput(ZERO_KEY_ADDRESS, 10_000_000, script=module1_script)))
        config_value = Value(
            2_000_000,
            MultiAsset({ScriptHash(scripts.config_policy): Asset({AssetName(CONFIG_TOKEN_NAME): 1})}),
        )
        self.config_utxo = self.put(
            TransactionOutput(scripts.config_holder.address, config_value, datum=RawCBOR(encode_data(module1_hash)))
        )
        self.config = replace(base, **refs)
        self.ctx = IdentityContext(self, self.config, clock=SlotClock(MAINNET_SYSTEM_START_MS, 1000))

    # ------------------------------------------------------------------
    # ChainContext
    # ------------------------------------------------------------------

    @property
    def protocol_param(self):
        return self._pp

    @property
    def genesis_param(self):
        return self._genesis

    @property
    def network(self) -> Network:
        return Network.MAINNET

    @property
    def epoch(self) -> int:
        return 100

    @property
    def last_block_slot(self) -> int:
        return self.tip

    def _utxos(self, address: str) -> list[UTxO]:
        return [u for u in self.ledger_state.values() if str(u.output.address) == address]

    def submit_tx_cbor(self, cbor):  # pragma: no cover - the tests apply BuiltTx instead
        raise NotImplementedError("use World.apply")

    def evaluate_tx_cbor(self, cbor) -> dict[str, ExecutionUnits]:
        raw = bytes.fromhex(cbor) if isinstance(cbor, str) else bytes(cbor)
        keys = self._redeemer_keys(raw)
        if not self.simulate_scripts:
            return {k: ExecutionUnits(1_000_000, 400_000_000) for k in keys}
        budgets = self.simulate_cbor(raw)
        return {k: ExecutionUnits(b["mem"], b["cpu"]) for k, b in zip(keys, budgets, strict=True)}

    # ------------------------------------------------------------------
    # Ledger
    # ------------------------------------------------------------------

    @property
    def context(self) -> ChainContext:
        return self

    def tip_slot(self) -> int:
        return self.tip

    def utxo(self, ref: OutputReference) -> UTxO | None:
        return self.ledger_state.get(TransactionInput(TransactionId(ref.tx_id), ref.index))

    def utxos_at(self, address: str) -> list[UTxO]:
        return self._utxos(str(address))

    def token_utxos(self, policy_id: bytes, asset_name: bytes) -> list[UTxO]:
        out = []
        for utxo in self.ledger_state.values():
            amount = utxo.output.amount
            if isinstance(amount, int):
                continue
            bundle = amount.multi_asset.get(ScriptHash(policy_id))
            if bundle and bundle.get(AssetName(asset_name), 0) > 0:
                out.append(utxo)
        return out

    # ------------------------------------------------------------------
    # Test helpers
    # ------------------------------------------------------------------

    def put(self, output: TransactionOutput) -> UTxO:
        """Add an output under a new transaction ID."""
        self._counter += 1
        tx_id = TransactionId(blake2b_256(b"world" + self._counter.to_bytes(4, "big")))
        utxo = UTxO(TransactionInput(tx_id, 0), output)
        self.ledger_state[utxo.input] = utxo
        return utxo

    def fund(self, key: PaymentSigningKey, lovelace: int = 200_000_000, count: int = 1) -> Address:
        address = key_address(key)
        for _ in range(count):
            self.put(TransactionOutput(address, lovelace))
        return address

    def advance(self, seconds: int) -> None:
        self.tip += seconds

    def apply(self, built: BuiltTx | Transaction) -> list[UTxO]:
        """Spend the inputs of a transaction and add its outputs."""
        tx = built.transaction if isinstance(built, BuiltTx) else built
        body = tx.transaction_body
        for tx_in in body.inputs:
            del self.ledger_state[tx_in]
        created = []
        for index, output in enumerate(body.outputs):
            utxo = UTxO(TransactionInput(tx.id, index), output)
            self.ledger_state[utxo.input] = utxo
            created.append(utxo)
        return created

    @staticmethod
    def _redeemer_keys(raw: bytes) -> list[str]:
        witness = cbor2.loads(raw)[1]
        redeemers = witness.get(5, {})
        if isinstance(redeemers, dict):
            pairs = [(k[0], k[1]) for k in redeemers]
        else:
            pairs = [(r[0], r[1]) for r in redeemers]
        return [f"{_TAGS[tag]}:{index}" for tag, index in pairs]

    def simulate(self, tx: BuiltTx | Transaction) -> list[dict]:
        """Run the scripts of ``tx`` with ``aiken tx simulate``; raise ScriptFailure on a rejection."""
        tx = tx.transaction if isinstance(tx, BuiltTx) else tx
        return self.simulate_cbor(tx.to_cbor())

    def simulate_cbor(self, raw: bytes) -> list[dict]:
        body = cbor2.loads(raw)[0]
        refs = []
        for key in (0, 13, 18):
            for tx_id, index in _unwrap(body.get(key, [])):
                tx_in = TransactionInput(TransactionId(tx_id), index)
                if tx_in not in refs:
                    refs.append(tx_in)
        resolved = [self.ledger_state[tx_in] for tx_in in refs]
        inputs = _head(4, len(resolved)) + b"".join(u.input.to_cbor() for u in resolved)
        outputs = _head(4, len(resolved)) + b"".join(u.output.to_cbor() for u in resolved)
        with tempfile.TemporaryDirectory(prefix="vector-identity-") as tmp:
            files = []
            for name, data in (("tx.hex", raw), ("inputs.hex", inputs), ("outputs.hex", outputs)):
                path = os.path.join(tmp, name)
                Path(path).write_text(data.hex())
                files.append(path)
            result = subprocess.run(
                [
                    AIKEN,
                    "tx",
                    "simulate",
                    *files,
                    "--zero-time",
                    str(MAINNET_SYSTEM_START_MS),
                    "--zero-slot",
                    "0",
                    "--slot-length",
                    "1000",
                ],
                capture_output=True,
                text=True,
                cwd=tmp,
                env={**os.environ, "NO_COLOR": "1"},
                check=False,
            )
        self.simulated += 1
        if result.returncode != 0:
            raise ScriptFailure(_ANSI.sub("", result.stderr)[-4000:])
        return json.loads(result.stdout)


def utxo_ref(utxo: UTxO) -> OutputReference:
    return OutputReference(bytes(utxo.input.transaction_id.payload), utxo.input.index)


def _script_hash(script: PlutusV3Script) -> bytes:
    from pycardano.plutus import script_hash

    return bytes(script_hash(script).payload)


def make_context(world: World) -> IdentityContext:
    return world.ctx
