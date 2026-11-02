"""The gateway client against the resolver's own vectors.

``fixtures/resolver-vectors/*.json`` are byte copies of agents-marketplace
``identity-gateway/test/vectors/*.json`` at ``1643583`` (the files last changed
in ``3c5b387``; sha256 in :data:`VECTOR_SHA256`): each request holds the DID,
the options, the HTTP status and the resolution result (Part 1 §7–§8).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import unquote

import httpx
import pytest

from vector_agent.exceptions import ConnectionError as VectorConnectionError
from vector_agent.identity import DidResolutionError, IdentityGateway

VECTORS = sorted((Path(__file__).parent / "fixtures" / "resolver-vectors").glob("*.json"))
REQUESTS = [
    (path.stem, request)
    for path in VECTORS
    for request in json.loads(path.read_text())["requests"]
]

#: sha256 of each vector file.
VECTOR_SHA256 = {
    "adopted": "b5d738d97748fd8612b8f581e6bfd01dfb9256e2984809f5caaf784446f9e3f8",
    "legacy-after-cutoff": "35ddcb0c81eb2d8c0626e96c1aa966857df78b5bea450cc0cbe8d6e7f3842f29",
    "legacy-before-cutoff": "42f08e2fdea6224a101116c81085779b78495253a48d851f736ddfa96427d08b",
    "legacy-deregistered": "fc4287ee7519f243895d9a95a1583a8a9a1bfdabc9ce65d5c98200ee721bf11e",
    "pending-versions": "81859cbd422a37ad7406c7082325296ee81060ed6b545a1409aa0a61cba73daf",
    "retired-successor": "0df3d5a2574c5f6b3251fd108c66af65e19b04849f12289bf569d4829eecb9f0",
    "revoked-invalid-from": "becb625835e156697b0671b2d30b5a73bc34711dfe656bb8d0fd20ffeedc828f",
    "root-agent": "c0819e0db5322fdbc82caacbff70a312a9637d9ea9aa5fdd922ecd30139afd00",
    "subagent": "5a1dc778ba4694ecfce63f92944df76fed5f17b37a249a1bf1c4a57f2e382377",
    "suspended-two-authors": "bd1dee7d2f9a5011269128e7402a9a588fc1db93ae2a5b7f5e975ef867fc0d59",
    "unaccountable": "dc516dd39e339d5ff7d44aeb07022371a646e2e1d90ed1a05d66ff87f04e6aeb",
}


def gateway_for(status: int, body, captured: list, content_type: str = "application/did-resolution") -> IdentityGateway:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        return httpx.Response(status, content=payload, headers={"content-type": content_type})

    return IdentityGateway("https://id.example.org/", transport=httpx.MockTransport(handler))


def test_the_vectors_are_the_pinned_copies() -> None:
    assert {path.stem: hashlib.sha256(path.read_bytes()).hexdigest() for path in VECTORS} == VECTOR_SHA256
    assert len(REQUESTS) >= 20


@pytest.mark.parametrize(("name", "request_"), REQUESTS, ids=[f"{n}-{i}" for i, (n, _) in enumerate(REQUESTS)])
def test_resolve_vector(name: str, request_: dict) -> None:
    captured: list[httpx.Request] = []
    gateway = gateway_for(request_["httpStatus"], request_["result"], captured)
    options = request_["options"]
    resolution = gateway.resolve(
        request_["did"],
        version_id=options.get("versionId"),
        version_time=options.get("versionTime"),
        expand_relative_urls=None if "expandRelativeUrls" not in options else options["expandRelativeUrls"] == "true",
    )
    sent = captured[0]
    assert sent.headers["accept"] == "application/did-resolution"
    assert sent.url.raw_path.decode().split("?")[0] == "/1.0/identifiers/" + request_["did"]
    assert {k: v for k, v in sent.url.params.items()} == options
    assert resolution.status == request_["httpStatus"]
    result = request_["result"]
    error = result["didResolutionMetadata"].get("error")
    assert resolution.error == (error["type"].rsplit("#", 1)[1] if error else None)
    assert resolution.deactivated == bool(result["didDocumentMetadata"].get("deactivated"))
    if resolution.error is None and not options:
        view = gateway.current_record(request_["did"])
        metadata = result["didDocumentMetadata"]
        assert view.effective == metadata["vectorStatus"]["effective"]
        assert view.deactivated == bool(metadata.get("deactivated"))
        assert view.origin == metadata.get("vectorOrigin")
        assert [k.key_hash for k in view.keys] == [k["id"][1:] for k in metadata.get("vectorKeys", [])]
        if result["didDocument"] and result["didDocument"].get("capabilityInvocation"):
            assert view.controller_key_hash == result["didDocument"]["capabilityInvocation"][0].rsplit("#", 1)[1]
    if resolution.error is not None:
        with pytest.raises(DidResolutionError) as raised:
            gateway.current_record(request_["did"])
        assert raised.value.status == request_["httpStatus"]


def test_current_record_of_a_vector_id() -> None:
    _, request_ = next((n, r) for n, r in REQUESTS if n == "root-agent")
    captured: list[httpx.Request] = []
    gateway = gateway_for(200, request_["result"], captured)
    vector_id = request_["did"].rsplit(":", 1)[1]
    view = gateway.current_record(vector_id)
    assert unquote(captured[0].url.raw_path.decode()) == f"/1.0/identifiers/did:vector:{vector_id}"
    assert view.vector_id == vector_id and view.effective == "active"
    assert view.record_output == f"{view.ledger['txId']}#{view.ledger['outputIndex']}"
    assert view.has_key(view.keys[1].key_hash, "transaction")
    assert view.keys[0].public_key_multibase.startswith("z6Mk")


def test_document_only() -> None:
    _, request_ = next((n, r) for n, r in REQUESTS if n == "root-agent")
    captured: list[httpx.Request] = []
    gateway = gateway_for(200, request_["result"]["didDocument"], captured, content_type="application/did")
    resolution = gateway.resolve(request_["did"], document_only=True)
    assert captured[0].headers["accept"] == "application/did"
    assert resolution.is_document and resolution.document["id"] == request_["did"]


@pytest.mark.parametrize(
    ("status", "body"),
    [(502, b"<html>bad gateway</html>"), (200, b"[]"), (404, json.dumps({"error": "not found"}).encode())],
)
def test_answers_without_a_resolution_result(status: int, body: bytes) -> None:
    gateway = gateway_for(status, body, [])
    with pytest.raises(VectorConnectionError):
        gateway.resolve("did:vector:" + "00" * 32)


def test_unreachable_gateway() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    gateway = IdentityGateway("https://id.example.org", transport=httpx.MockTransport(handler))
    with pytest.raises(VectorConnectionError, match="gateway"):
        gateway.resolve("did:vector:" + "00" * 32)
