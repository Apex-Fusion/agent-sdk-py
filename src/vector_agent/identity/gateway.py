"""DID resolution through the gateway's HTTPS binding (Part 1 §7.4).

``GET {gateway}/1.0/identifiers/{did}`` as defined by DID Resolution v1.0
(https://www.w3.org/TR/did-resolution/). Options are query parameters. The
resolver percent-decodes the path once, so the DID is sent percent-encoded
with ``:`` kept.

HTTP statuses (Part 1 §7.4): 200 found, 410 deactivated, 400 ``INVALID_DID``
or ``INVALID_OPTIONS``, 404 ``NOT_FOUND``, 406 ``REPRESENTATION_NOT_SUPPORTED``,
501 ``METHOD_NOT_SUPPORTED`` or ``FEATURE_NOT_SUPPORTED``, 500
``INTERNAL_ERROR``. Every error carries a resolution result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Self
from urllib.parse import quote

import httpx

from vector_agent.exceptions import ConnectionError as VectorConnectionError
from vector_agent.exceptions import VectorError
from vector_agent.identity.constants import DEFAULT_GATEWAY_URL
from vector_agent.identity.ids import is_vector_id, parse_vector_did, vector_did

__all__ = ["AgentView", "DidResolution", "DidResolutionError", "IdentityGateway", "ResolvedKey"]

RESOLUTION_MEDIA_TYPE = "application/did-resolution"
DOCUMENT_MEDIA_TYPE = "application/did"
_MAX_BODY = 1 << 20


class DidResolutionError(VectorError):
    """The resolver answered with a DID Resolution error (for example ``NOT_FOUND``)."""

    def __init__(self, error: str, title: str, status: int) -> None:
        super().__init__(f"{error}: {title} (HTTP {status})")
        self.error = error
        self.title = title
        self.status = status


@dataclass(frozen=True)
class DidResolution:
    """One answer of the HTTPS binding: the HTTP status and the JSON body."""

    status: int
    body: dict
    content_type: str = RESOLUTION_MEDIA_TYPE

    @property
    def is_document(self) -> bool:
        """True when the body is a DID document only (``Accept: application/did``)."""
        media_type = self.content_type.split(";", 1)[0].strip().lower()
        return media_type == DOCUMENT_MEDIA_TYPE and "didResolutionMetadata" not in self.body

    @property
    def document(self) -> dict | None:
        return self.body if self.is_document else self.body.get("didDocument")

    @property
    def metadata(self) -> dict:
        return {} if self.is_document else self.body.get("didDocumentMetadata") or {}

    @property
    def resolution_metadata(self) -> dict:
        return {} if self.is_document else self.body.get("didResolutionMetadata") or {}

    @property
    def error(self) -> str | None:
        """The error name, for example ``NOT_FOUND``; None for a found DID."""
        error = self.resolution_metadata.get("error")
        if not isinstance(error, dict):
            return None
        return str(error.get("type", "")).rsplit("#", 1)[-1] or "UNKNOWN_ERROR"

    @property
    def deactivated(self) -> bool:
        return bool(self.metadata.get("deactivated"))

    def raise_for_error(self) -> DidResolution:
        if self.error is not None:
            title = str(self.resolution_metadata["error"].get("title", ""))
            raise DidResolutionError(self.error, title, self.status)
        return self


@dataclass(frozen=True)
class ResolvedKey:
    """A listed key of the resolved view: ``vectorKeys`` with its document entry."""

    key_hash: str
    type: str
    purposes: tuple[str, ...]
    public_key_multibase: str | None = None


@dataclass(frozen=True)
class AgentView:
    """The current record of an agent, as the resolver shows it without options."""

    did: str
    vector_id: str
    effective: str
    effective_reason: str | None
    status: str
    deactivated: bool
    origin: str | None
    version_id: str | None
    controller_key_hash: str | None
    keys: tuple[ResolvedKey, ...]
    parties: tuple[dict, ...]
    profile: dict
    parent: dict | None
    recovery: dict | None
    ledger: dict | None
    pending: tuple[str, ...]
    resolution: DidResolution = field(repr=False)

    @property
    def record_output(self) -> str | None:
        """``<tx id>#<index>`` of the record output that the base version owns."""
        if not self.ledger or "outputIndex" not in self.ledger:
            return None
        return f"{self.ledger['txId']}#{self.ledger['outputIndex']}"

    def has_key(self, key_hash: str, purpose: str) -> bool:
        return any(k.key_hash == key_hash and purpose in k.purposes for k in self.keys)

    @classmethod
    def from_resolution(cls, resolution: DidResolution, did: str) -> AgentView:
        metadata = resolution.metadata
        document = resolution.document or {}
        status = metadata.get("vectorStatus") or {}
        methods = {m.get("id", "").rsplit("#", 1)[-1]: m for m in document.get("verificationMethod", [])}
        keys = []
        for entry in metadata.get("vectorKeys", []):
            key_hash = str(entry.get("id", "")).rsplit("#", 1)[-1]
            keys.append(
                ResolvedKey(
                    key_hash=key_hash,
                    type=str(entry.get("type", "")),
                    purposes=tuple(entry.get("purposes", [])),
                    public_key_multibase=methods.get(key_hash, {}).get("publicKeyMultibase"),
                )
            )
        invocation = document.get("capabilityInvocation") or []
        controller = str(invocation[0]).rsplit("#", 1)[-1] if invocation else None
        canonical = str(metadata.get("canonicalId", did))
        parsed = parse_vector_did(canonical) or parse_vector_did(did)
        return cls(
            did=did,
            vector_id=parsed.vector_id if parsed else "",
            effective=str(status.get("effective", "")),
            effective_reason=status.get("effectiveReason"),
            status=str(status.get("status", "")),
            deactivated=resolution.deactivated,
            origin=metadata.get("vectorOrigin"),
            version_id=metadata.get("versionId"),
            controller_key_hash=controller,
            keys=tuple(keys),
            parties=tuple(metadata.get("vectorParties", [])),
            profile=dict(metadata.get("vectorProfile") or {}),
            parent=metadata.get("vectorParent"),
            recovery=metadata.get("vectorRecovery"),
            ledger=metadata.get("vectorLedger"),
            pending=tuple(metadata.get("vectorPending", [])),
            resolution=resolution,
        )


class IdentityGateway:
    """Client of the identity gateway (default ``https://id.vector.apexfusion.org``)."""

    def __init__(
        self,
        base_url: str = DEFAULT_GATEWAY_URL,
        *,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout, transport=transport, follow_redirects=False)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def resolve(
        self,
        did: str,
        *,
        version_id: str | int | None = None,
        version_time: str | None = None,
        expand_relative_urls: bool | None = None,
        document_only: bool = False,
    ) -> DidResolution:
        """Resolve ``did``. DID errors come back as a result; check :attr:`DidResolution.error`.

        Raises :class:`vector_agent.exceptions.ConnectionError` when the gateway
        cannot be reached or does not answer with JSON.
        """
        params: dict[str, str] = {}
        if version_id is not None:
            params["versionId"] = str(version_id)
        if version_time is not None:
            params["versionTime"] = version_time
        if expand_relative_urls is not None:
            params["expandRelativeUrls"] = "true" if expand_relative_urls else "false"
        accept = DOCUMENT_MEDIA_TYPE if document_only else RESOLUTION_MEDIA_TYPE
        url = f"{self.base_url}/1.0/identifiers/{quote(did, safe=':')}"
        try:
            response = self._client.get(url, params=params, headers={"Accept": accept})
        except httpx.HTTPError as exc:
            raise VectorConnectionError(f"identity gateway request failed: {exc}") from exc
        if len(response.content) > _MAX_BODY:
            raise VectorConnectionError("identity gateway answer is larger than 1 MiB")
        try:
            body = response.json()
        except ValueError:
            raise VectorConnectionError(
                f"identity gateway answered HTTP {response.status_code} without JSON"
            ) from None
        if not isinstance(body, dict):
            raise VectorConnectionError("identity gateway answer is not a JSON object")
        content_type = response.headers.get("content-type", RESOLUTION_MEDIA_TYPE)
        resolution = DidResolution(response.status_code, body, content_type)
        if not resolution.is_document and "didResolutionMetadata" not in body:
            raise VectorConnectionError(
                f"identity gateway answered HTTP {response.status_code} without a resolution result"
            )
        return resolution

    def current_record(self, agent: str) -> AgentView:
        """The resolver's view of ``agent`` (a vector-id or a DID) without version options.

        Raises :class:`DidResolutionError` for a DID error. A deactivated DID
        (HTTP 410) is not an error: the view has ``deactivated`` set.
        """
        did = vector_did(agent) if is_vector_id(agent) else agent
        resolution = self.resolve(did).raise_for_error()
        return AgentView.from_resolution(resolution, did)
