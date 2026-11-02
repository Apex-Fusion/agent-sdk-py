"""The gateway client against the resolver's own vectors.

``fixtures/resolver-vectors/*.json`` are byte copies of agents-marketplace
``identity-gateway/test/vectors/*.json`` at ``b5d66a6``: each request holds the
DID, the options, the HTTP status and the resolution result (Part 1 §7–§8).
"""

from __future__ import annotations

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


def gateway_for(status: int, body, captured: list, content_type: str = "application/did-resolution") -> IdentityGateway:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        return httpx.Response(status, content=payload, headers={"content-type": content_type})

    return IdentityGateway("https://id.example.org/", transport=httpx.MockTransport(handler))


def test_there_are_vectors() -> None:
    assert len(VECTORS) == 11 and len(REQUESTS) >= 20


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
