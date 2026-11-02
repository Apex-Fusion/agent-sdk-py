"""Ledger reads through Ogmios and Koios, with the answer shapes of Vector mainnet."""

from __future__ import annotations

import json

import httpx
import pytest
from pycardano import AssetName, PlutusV3Script, ScriptHash

from vector_agent.exceptions import ConnectionError as VectorConnectionError
from vector_agent.identity import OgmiosKoiosLedger, OutputReference, SlotClock
from vector_agent.identity.chain import utxo_from_ogmios
from vector_agent.identity.context import datum_bytes

LEGACY = "be1a0a2912da180757ed3cd61b56bb8eab0188c19dc3c0e3912d2c01"
NAME = "4c2047697c7aa8b3399c5fecf20f2bd19ff276aaffbd0496acfd7b3e1a52545e"
RECORD = {
    "transaction": {"id": "e6992139dfb2922a175d3d614899067e6989e79e791f7b9e452af007bbec1611"},
    "index": 0,
    "address": "addr1wxlp5z3fztdpsp6ha57dvx6khw82kqvgcxwu8s8rjykjcqghprf42",
    "value": {"ada": {"lovelace": 10_000_000}, LEGACY: {NAME: 1}},
    "datum": "d87980",
}
REFERENCE = {
    "transaction": {"id": "c8d84c6d67ec67a1efe5e9c6c06d53020e05d1bb96d1c55ecb1eb7d5010c4d54"},
    "index": 1,
    "address": "addr1vyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkdl5mw",
    "value": {"ada": {"lovelace": 17_000_000}},
    "script": {"language": "plutus:v3", "cbor": "450101002499"},
}


def test_utxo_from_ogmios() -> None:
    record = utxo_from_ogmios(RECORD)
    assert record.output.amount.coin == 10_000_000
    assert record.output.amount.multi_asset[ScriptHash(bytes.fromhex(LEGACY))][AssetName(bytes.fromhex(NAME))] == 1
    assert datum_bytes(record).hex() == RECORD["datum"]
    reference = utxo_from_ogmios(REFERENCE)
    assert isinstance(reference.output.script, PlutusV3Script) and bytes(reference.output.script).hex() == "450101002499"
    assert reference.input.index == 1


def test_slot_clock() -> None:
    clock = SlotClock()
    assert clock.posix_ms(0) == 1_756_485_600_000
    assert clock.slot_at_or_before(clock.posix_ms(1_000) + 999) == 1_000



def test_token_utxos(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append((str(request.url), body))
        if request.url.host == "koios.example.org":
            assert body == {"_asset_list": [[LEGACY, NAME]], "_extended": False}
            rows = [
                {"tx_hash": RECORD["transaction"]["id"], "tx_index": 0, "is_spent": False},
                {"tx_hash": "00" * 32, "tx_index": 5, "is_spent": True},
            ]
            return httpx.Response(200, json=rows)
        assert body["method"] == "queryLedgerState/utxo"
        assert body["params"] == {"outputReferences": [{"transaction": {"id": RECORD["transaction"]["id"]}, "index": 0}]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": [RECORD, REFERENCE]})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        "vector_agent.identity.chain.httpx.post",
        lambda url, **kwargs: httpx.Client(transport=transport).post(url, **kwargs),
    )
    ledger = OgmiosKoiosLedger(ogmios_url="https://ogmios.example.org", koios_url="https://koios.example.org/api/v1/", context=object())
    found = ledger.token_utxos(bytes.fromhex(LEGACY), bytes.fromhex(NAME))
    assert [u.input.index for u in found] == [0]  # the reference output holds no such token
    assert calls[0][0] == "https://koios.example.org/api/v1/asset_utxos"


def test_ogmios_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "error": {"code": -32602, "message": "bad"}})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        "vector_agent.identity.chain.httpx.post",
        lambda url, **kwargs: httpx.Client(transport=transport).post(url, **kwargs),
    )
    ledger = OgmiosKoiosLedger(ogmios_url="https://ogmios.example.org", koios_url="https://koios.example.org", context=object())
    with pytest.raises(VectorConnectionError, match="Ogmios error"):
        ledger.utxo(OutputReference(bytes(32), 0))


def test_tip_and_address_query(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body["method"] == "queryNetwork/tip":
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": {"slot": 123, "id": "ab" * 32}})
        assert body["params"] == {"addresses": [REFERENCE["address"]]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": [REFERENCE]})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        "vector_agent.identity.chain.httpx.post",
        lambda url, **kwargs: httpx.Client(transport=transport).post(url, **kwargs),
    )
    ledger = OgmiosKoiosLedger(ogmios_url="https://ogmios.example.org", koios_url="https://koios.example.org", context=object())
    assert ledger.tip_slot() == 123
    assert len(ledger.utxos_at(REFERENCE["address"])) == 1
