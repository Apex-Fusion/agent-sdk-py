"""The identity helpers against the published identity vectors of agents-marketplace.

``fixtures/vectors/*.json`` are byte copies of ``Apex-Fusion/agents-marketplace``
``contracts/identity-marketplace/vectors/`` at commit ``67054f6``. The files last
changed in ``f68e0b6``. ``status-lists.json`` is not copied. The git blobs are:

- ``identifiers.json``: ``f09aabd9aaf11d2d1aaf4dded8ff0d9498858af0``
- ``allowlist.json``: ``53995abf2796765e7dee792328ff72a9696e3671``
- ``attestation-envelope.json``: ``cc1a6f8b442df23015b32fde1478347939bf35a2``

The test pins each copy by sha256 (:data:`VECTOR_SHA256`). The SDK must match the
vectors byte for byte:

- ``identifiers.json``: seed serialisation, vector-id, DNS-safe form and DIDs
  (Part 1 §3, §3.1, §3.2: ``docs/did-vector-method.md``).
- ``allowlist.json``: the adoption allowlist tree and its proofs
  (Part 2 §3.4: ``docs/IDENTITY_REGISTRY.md``).
- ``attestation-envelope.json``: the protected header, ``Sig_structure``,
  Ed25519 signature and COSE_Sign1 message of an attestation (Part 2 §4.2).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from itertools import pairwise
from pathlib import Path

import cbor2
import pytest
from nacl.signing import SigningKey

from vector_agent.identity.attestation import (
    did_key,
    envelope_protected_header,
    envelope_sig_structure,
    verify_envelope,
)
from vector_agent.identity.constants import LEGACY_REGISTRY_HASH
from vector_agent.identity.ids import (
    ParsedDid,
    allowlist_leaf,
    allowlist_proof,
    allowlist_root,
    dns_safe,
    key_hash,
    legacy_vector_did,
    parse_vector_did,
    serialise_seed,
    vector_did,
    vector_id_from_seed,
    verify_allowlist_proof,
)
from vector_agent.identity.types import ATT_ACTIVE, AttestationDatum

VECTORS = Path(__file__).parent / "fixtures" / "vectors"

#: sha256 of each vector file.
VECTOR_SHA256 = {
    "allowlist": "ed2c87e67652c89fc09522fafc90aede1d44540d8c51324a0405e91e9d939e3c",
    "attestation-envelope": "2cc0b2cafa446ef7a2a74a6c8561f3c800a41810adf77cf5e709e2715db67bd0",
    "identifiers": "1237da29ce208dad2c7e52c5daa45e09501ad0b33eebb112a5c6af90ed2fa6df",
}


def load(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_bytes())


IDENTIFIERS = load("identifiers")["vectors"]
ALLOWLIST = load("allowlist")
ENVELOPES = load("attestation-envelope")
TEST_KEY = ENVELOPES["testKey"]


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def hex_list(values: list[str]) -> list[bytes]:
    return [bytes.fromhex(value) for value in values]


def test_the_vectors_are_the_pinned_copies() -> None:
    copies = {path.stem: hashlib.sha256(path.read_bytes()).hexdigest() for path in VECTORS.glob("*.json")}
    assert copies == VECTOR_SHA256


@pytest.mark.parametrize("vector", IDENTIFIERS, ids=[str(i) for i in range(len(IDENTIFIERS))])
def test_identifier_vector(vector: dict) -> None:
    """Seed serialisation, vector-id, DNS-safe form and both DID forms (Part 1 §3, §3.1, §3.2)."""
    vector_id = vector["vectorId"]
    assert serialise_seed(vector["txId"], vector["outputIndex"]).hex() == vector["serialisedSeed"]
    assert vector_id_from_seed(vector["txId"], vector["outputIndex"]) == vector_id
    # RFC 4648 §6 base32 (https://www.rfc-editor.org/rfc/rfc4648#section-6), lowercase, without padding.
    assert dns_safe(vector_id) == vector["dnsSafe"]
    assert vector_did(vector_id) == vector["did"]
    assert legacy_vector_did(LEGACY_REGISTRY_HASH, vector_id) == vector["legacyDid"]
    assert parse_vector_did(vector["did"]) == ParsedDid("canonical", vector_id)
    assert parse_vector_did(vector["legacyDid"]) == ParsedDid("legacy", vector_id, policy_id=LEGACY_REGISTRY_HASH)


@pytest.mark.parametrize("tree", ALLOWLIST["trees"], ids=[slug(tree["name"]) for tree in ALLOWLIST["trees"]])
def test_allowlist_tree(tree: dict) -> None:
    """The leaves, the root and every proof of a published tree (Part 2 §3.4)."""
    ids = tree["ids"]
    root = bytes.fromhex(tree["root"])
    leaves = hex_list(tree["leaves"])
    # The file lists the leaves in strictly ascending byte order, not in the order of ``ids``.
    assert all(left < right for left, right in pairwise(leaves))
    assert sorted(allowlist_leaf(i) for i in ids) == leaves
    assert allowlist_root(ids) == root
    assert sorted(entry["id"] for entry in tree["proofs"]) == sorted(ids)
    for entry in tree["proofs"]:
        proof = hex_list(entry["proof"])
        assert allowlist_proof(ids, entry["id"]) == proof
        assert verify_allowlist_proof(root, entry["id"], proof) is True


@pytest.mark.parametrize("case", ALLOWLIST["rejections"], ids=[str(i) for i in range(len(ALLOWLIST["rejections"]))])
def test_allowlist_rejection(case: dict) -> None:
    """No published rejection verifies (Part 2 §3.4)."""
    proof = hex_list(case["proof"])
    assert verify_allowlist_proof(bytes.fromhex(case["root"]), case["id"], proof) is False, case["description"]


def attestation_datum(attestation: dict) -> AttestationDatum:
    """The datum of a vector. The fields that the envelope does not cover are neutral."""
    issuer_id = attestation["issuerId"]
    return AttestationDatum(
        subject=bytes.fromhex(attestation["subject"]),
        issuer=bytes.fromhex(attestation["issuer"]),
        issuer_id=None if issuer_id is None else bytes.fromhex(issuer_id),
        att_type=attestation["attType"],
        format=attestation["format"],
        profile=None,
        digest=bytes.fromhex(attestation["digest"]),
        locator=None,
        envelope_sig=None,
        issued_at=attestation["issuedAt"],
        valid_from=None,
        valid_until=None,
        solicited=False,
        status=ATT_ACTIVE,
        contested=None,
        links=(),
    )


def test_envelope_test_key() -> None:
    """The test key is RFC 8032 §7.1 TEST 1 (https://www.rfc-editor.org/rfc/rfc8032#section-7.1)."""
    public_key = bytes(SigningKey(bytes.fromhex(TEST_KEY["secretKey"])).verify_key)
    assert public_key.hex() == TEST_KEY["publicKey"]
    assert key_hash(public_key) == ENVELOPES["issuerKeyHash"]


@pytest.mark.parametrize("vector", ENVELOPES["vectors"], ids=[slug(vector["name"]) for vector in ENVELOPES["vectors"]])
def test_envelope_vector(vector: dict) -> None:
    """The protected header, ``Sig_structure``, signature and COSE_Sign1 message of a vector (Part 2 §4.2).

    - The protected header uses RFC 8949 §4.2.1 core deterministic encoding
      (https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1).
    - ``Sig_structure = ["Signature1", protected, h'', digest]`` is RFC 9052 §4.4
      (https://www.rfc-editor.org/rfc/rfc9052#section-4.4).
    - COSE_Sign1 is RFC 9052 §4.2 (https://www.rfc-editor.org/rfc/rfc9052#section-4.2).
    - Ed25519 signatures are deterministic (RFC 8032 §5.1.6,
      https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6). Thus the signature with the
      RFC 8032 §7.1 TEST 1 secret key (https://www.rfc-editor.org/rfc/rfc8032#section-7.1)
      equals the published signature.
    """
    datum = attestation_datum(vector["attestation"])
    protected = envelope_protected_header(datum)
    structure = envelope_sig_structure(datum)
    assert protected.hex() == vector["protectedHeader"]["hex"]
    assert structure.hex() == vector["sigStructure"]["hex"]

    signature = bytes.fromhex(vector["signature"])
    assert SigningKey(bytes.fromhex(TEST_KEY["secretKey"])).sign(structure).signature == signature
    signed = replace(datum, envelope_sig=signature)
    assert verify_envelope(signed) is True
    digest = bytearray(datum.digest)
    digest[0] ^= 0x01
    assert verify_envelope(replace(signed, digest=bytes(digest))) is False

    assert key_hash(datum.issuer) == ENVELOPES["issuerKeyHash"]
    if datum.issuer_id is None:
        assert did_key(datum.issuer) == vector["issuerDid"]
    else:
        assert vector_did(datum.issuer_id.hex()) == vector["issuerDid"]

    # COSE_Sign1 (RFC 9052 §4.2): tag 18 over [protected bstr, unprotected {}, payload bstr, signature bstr].
    # The SDK has no COSE_Sign1 encoder, so the test assembles the message from the SDK's protected header.
    message = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, datum.digest, signature]))
    assert message.hex() == vector["coseSign1"]
