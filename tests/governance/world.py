"""An offline ledger with a test Module-6 deployment.

``GovWorld`` extends the identity test ledger (``identity/world.py``): the
identity scripts of a test deployment, the Vector mainnet protocol parameters
and ``aiken tx simulate`` for every evaluation. On top it holds a Module-6
deployment of the embedded blueprint (applied with the test configuration
below), the reference scripts, the parameters record, the oracle record, the
cross references and the head of the activity list, as
``Module-6/scripts/deploy.py`` creates them.

Identity records are outputs at the identity address with the record token and
an ``IdentityDatum``. The Module-6 validators only read records, so the tests
put them on the ledger directly.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from identity.world import AIKEN, ZERO_KEY_ADDRESS, World, key_address, key_hash, public_key, signing_key, utxo_ref
from pycardano import (
    Asset,
    AssetName,
    MultiAsset,
    PaymentSigningKey,
    ScriptHash,
    TransactionOutput,
    UTxO,
    Value,
)
from pycardano.serialization import RawCBOR

from vector_agent.governance import (
    ActivityDatum,
    Governance,
    GovernanceContext,
    GovernanceDeployment,
    GovernanceOracleDatum,
    GovernanceParams,
)
from vector_agent.governance.scripts import SCRIPT_NAMES
from vector_agent.identity import SlotClock
from vector_agent.identity.constants import MAINNET_SYSTEM_START_MS, PURPOSE_TRANSACTION
from vector_agent.identity.ids import blake2b_256
from vector_agent.identity.scripts import enterprise_address
from vector_agent.identity.tx import BuiltTx
from vector_agent.identity.types import (
    ACTIVE,
    CONTROLLER_SET,
    ROOT,
    Hold,
    IdentityDatum,
    Key,
    KeyCredential,
    KeyType,
    OutputReference,
    Party,
    Revoked,
    Role,
    Status,
    Subagent,
    Suspended,
)

__all__ = [
    "AIKEN",
    "PARAMS",
    "GovAgent",
    "GovWorld",
    "key_address",
    "key_hash",
    "public_key",
    "revoked",
    "signing_key",
    "suspended",
    "token_value",
]

RECORD_POLICY = bytes([0x7A]) * 28
REFS_POLICY = bytes([0x7B]) * 28
PARAMS_HOLDER = bytes([0x4A]) * 28
ORACLE_HOLDER = bytes([0x4B]) * 28
TREASURY_HOLDER = bytes([0x4C]) * 28

#: ``params.default_governance_params`` of the contracts (times in POSIX ms).
PARAMS = GovernanceParams(
    min_proposal_stake=25_000_000,
    min_critique_stake=5_000_000,
    min_governance_endorsement=5_000_000,
    min_review_window=259_200_000,
    max_review_window=2_419_200_000,
    max_amendments=5,
    max_active_proposals=3,
    proposal_cooldown=86_400_000,
    proposer_reward_share=7_000,
    critic_reward_share=2_000,
    protocol_fee_rate=1_000,
    min_adoption_reward=50_000_000,
    max_adoption_reward=500_000_000,
    max_incorporated_critiques=5,
    max_treasury_request=10_000_000_000,
    emergency_stake_multiplier=5_000,
    emergency_review_window=43_200_000,
    param_execution_delay=604_800_000,
    min_prediction_pool=100_000_000,
    credibility_pool_low_threshold=500_000_000,
    credibility_pool_critical_threshold=200_000_000,
)

ACCOUNTABLE = Party(Role.ACCOUNTABLE, CONTROLLER_SET, None, 0, None, 3)


def token_value(coin: int, policy: bytes, name: bytes, quantity: int = 1) -> Value:
    return Value(coin, MultiAsset({ScriptHash(policy): Asset({AssetName(name): quantity})}))


@dataclass(frozen=True)
class GovAgent:
    """An agent with a record on the ledger. ``key`` is the controller key; the
    wallet ``address`` belongs to the same key and holds funds."""

    id: bytes
    key: PaymentSigningKey
    record: UTxO

    @property
    def did(self) -> str:
        return f"did:vector:{self.id.hex()}"

    @property
    def key_hash(self) -> bytes:
        return key_hash(self.key)

    @property
    def address(self):
        return key_address(self.key)


class GovWorld(World):
    """The identity test ledger with a Module-6 deployment."""

    def __init__(self, *, reference_scripts: bool = True, simulate: bool = True, params: GovernanceParams = PARAMS):
        super().__init__(simulate=simulate)
        base = GovernanceDeployment(
            identity_hash=self.scripts.identity.hash,
            record_token_policy=RECORD_POLICY,
            refs_token_policy=REFS_POLICY,
            governance_oracle_hash=ORACLE_HOLDER,
            governance_params_hash=PARAMS_HOLDER,
            governance_treasury_hash=TREASURY_HOLDER,
        )
        self.gov_scripts = base.scripts()
        refs = {}
        if reference_scripts:
            for name in SCRIPT_NAMES:
                script = self.gov_scripts.by_name(name).plutus_script
                refs[f"{name}_ref"] = utxo_ref(self.put(TransactionOutput(ZERO_KEY_ADDRESS, 70_000_000, script=script)))
        self.deployment = replace(base, **refs)
        self.oracle_key = signing_key("module6-oracle")
        self.deployer_key = signing_key("module6-deployer")
        self.params_utxo = self.put(
            TransactionOutput(
                enterprise_address(PARAMS_HOLDER),
                token_value(3_000_000, RECORD_POLICY, b"params"),
                datum=RawCBOR(params.to_cbor()),
            )
        )
        oracle = GovernanceOracleDatum(KeyCredential(key_hash(self.oracle_key)), TREASURY_HOLDER, True)
        self.oracle_utxo = self.put(
            TransactionOutput(
                enterprise_address(ORACLE_HOLDER),
                token_value(3_000_000, RECORD_POLICY, b"oracle"),
                datum=RawCBOR(oracle.to_cbor()),
            )
        )
        self.cross_refs_utxo = self.put(
            TransactionOutput(
                enterprise_address(ORACLE_HOLDER),
                token_value(2_000_000, REFS_POLICY, b"crossrefs"),
                datum=RawCBOR(self.gov_scripts.cross_refs.to_cbor()),
            )
        )
        head = ActivityDatum(b"", KeyCredential(key_hash(self.deployer_key)), 0, 0, b"")
        self.head_utxo = self.put(
            TransactionOutput(
                self.gov_scripts.proposal_spend.address,
                token_value(3_000_000, RECORD_POLICY, b"activity"),
                datum=RawCBOR(head.to_cbor()),
            )
        )
        self.gov_ctx = GovernanceContext(self, self.deployment, clock=SlotClock(MAINNET_SYSTEM_START_MS, 1000))
        self.gov = Governance(self.gov_ctx)

    # ------------------------------------------------------------------
    # Identity records
    # ------------------------------------------------------------------

    def record_datum(
        self,
        key: PaymentSigningKey,
        *,
        parent: bytes | None = None,
        status: Status = ACTIVE,
        transaction_keys: tuple[PaymentSigningKey, ...] = (),
        parties: tuple[Party, ...] = (ACCOUNTABLE,),
    ) -> IdentityDatum:
        return IdentityDatum(
            controller=public_key(key),
            keys=tuple(Key(KeyType.ED25519, public_key(k), PURPOSE_TRANSACTION) for k in transaction_keys),
            parties=parties,
            guardian_threshold=0,
            pending_recovery=None,
            lineage=ROOT if parent is None else Subagent(parent, 0, 1),
            subagent_epoch=0,
            name=b"agent",
            description=b"",
            framework=b"",
            endpoint=b"https://agent.example.org",
            capabilities=(b"governance",),
            created_at=0,
            status=status,
        )

    def put_record(self, agent_id: bytes, datum: IdentityDatum) -> UTxO:
        identity = self.scripts.identity
        return self.put(
            TransactionOutput(
                identity.address, token_value(10_000_000, identity.hash, agent_id), datum=RawCBOR(datum.to_cbor())
            )
        )

    def replace_record(self, agent: GovAgent, datum: IdentityDatum) -> GovAgent:
        del self.ledger_state[agent.record.input]
        return replace(agent, record=self.put_record(agent.id, datum))

    def agent(self, label: str, *, fund: bool = True, **record) -> GovAgent:
        """An agent whose controller key is ``signing_key(label)``; its wallet has funds."""
        key = signing_key(label)
        agent_id = blake2b_256(label.encode())
        utxo = self.put_record(agent_id, self.record_datum(key, **record))
        if fund:
            self.fund(key, 300_000_000, count=2)
        return GovAgent(agent_id, key, utxo)

    # ------------------------------------------------------------------
    # Positions
    # ------------------------------------------------------------------

    def created(self, built: BuiltTx, index: int = 0) -> OutputReference:
        """Apply ``built`` and return the reference of its output ``index``."""
        self.apply(built)
        return OutputReference(bytes.fromhex(built.tx_id), index)

    def lovelace_at(self, address) -> int:
        total = 0
        for utxo in self.utxos_at(str(address)):
            amount = utxo.output.amount
            total += amount if isinstance(amount, int) else amount.coin
        return total


def suspended(datum: IdentityDatum) -> IdentityDatum:
    hold = Hold(CONTROLLER_SET, 6, 0, 253_402_300_799_999)
    return replace(datum, status=Suspended((hold,)))


def revoked(datum: IdentityDatum) -> IdentityDatum:
    return replace(datum, status=Revoked(CONTROLLER_SET, 1, 0))
