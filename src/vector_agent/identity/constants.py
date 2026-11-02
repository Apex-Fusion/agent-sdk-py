"""Constants of the identity registry (Part 1 §4–§5, Part 2 §2–§6, Appendix A)."""

from __future__ import annotations

from types import MappingProxyType

from vector_agent.identity.types import Role

# Key purposes (Part 1 §5).
PURPOSE_AUTHENTICATION = 1
PURPOSE_ASSERTION = 2
PURPOSE_TRANSACTION = 8
PURPOSE_DELEGATION = 16
ED25519_PURPOSES = 27
P256_PURPOSES = 3

# Party rights (Part 1 §5).
RIGHT_SUSPEND = 1
RIGHT_REVOKE = 2
RIGHT_RECOVER = 4

#: The highest rights of each role.
ROLE_MAX_RIGHTS = MappingProxyType(
    {
        Role.ACCOUNTABLE: RIGHT_SUSPEND | RIGHT_REVOKE,
        Role.RESPONSIBLE: RIGHT_SUSPEND,
        Role.PROVIDER: RIGHT_SUSPEND,
        Role.DISTRIBUTOR: 0,
        Role.GUARDIAN: RIGHT_RECOVER,
    }
)

# Time (POSIX milliseconds).
MAX_RANGE_MS = 3_600_000
MAX_TIME_MS = 253_402_300_799_999
MAX_RECORD_INT = (1 << 63) - 1
DAY_MS = 86_400_000
DAYS_7_MS = 7 * DAY_MS
DAYS_30_MS = 30 * DAY_MS
DAYS_90_MS = 90 * DAY_MS
DAYS_366_MS = 366 * DAY_MS

# Record limits (Part 1 §5, Part 2 §3.3).
MAX_DEPTH = 4
MAX_KEYS = 8
MAX_PARTIES = 8
MAX_HOLDS = 10
MAX_CAPABILITIES = 16
NAME_MAX_BYTES = 64
DESCRIPTION_MAX_BYTES = 256
FRAMEWORK_MAX_BYTES = 64
ENDPOINT_MAX_BYTES = 256
CAPABILITY_MAX_BYTES = 64
ORGANISATION_MAX_BYTES = 64

# Attestation limits (Part 2 §4).
MAX_LINKS = 4
MAX_LINK_REL = 3
LOCATOR_MAX_BYTES = 256
ANCHOR_URI_MAX_BYTES = 256
MAX_CONTENT_FORMAT = 65_535
ATTESTATION_TYPES = frozenset({0, 1, 2, 3, 4, 5, 15})

# Delegation limits (Part 2 §5.2).
MAX_ACTIONS = 16
MAX_RESOURCES = 8
HIRE_ACTION = "marketplace.hire.v1"

# Amounts (base units; 1 AP3X = 1,000,000).
MIN_RECORD_LOVELACE = 10_000_000
MIN_ATTESTATION_LOVELACE = 5_000_000
MAX_ESCROW_LOVELACE = 10_000_000_000
LEGACY_OWNER_CHANGE_LOVELACE = 10_000_000

# Reason codes (Part 2 Appendix A).
REASON_UNSPECIFIED = 0
REASON_KEY_COMPROMISE = 1
REASON_AFFILIATION_CHANGED = 3
REASON_SUPERSEDED = 4
REASON_CESSATION_OF_OPERATION = 5
REASON_HOLD = 6
REASON_PRIVILEGE_WITHDRAWN = 9
REASON_DISPUTE_VERDICT = 64
REASON_LEGAL_ORDER = 65
REASON_PROVIDER_WITHDRAWN = 67
REASON_SECURITY_INVESTIGATION = 68
SUSPEND_REASONS = frozenset({0, 6, 9, 64, 65, 67, 68})
REVOKE_REASONS = frozenset({0, 1, 3, 4, 5, 9, 64, 65})

# Legacy registry (Part 1 §4, Part 2 §2).
LEGACY_REGISTRY_HASH = "be1a0a2912da180757ed3cd61b56bb8eab0188c19dc3c0e3912d2c01"
LEGACY_REGISTRY_ADDRESS = "addr1wxlp5z3fztdpsp6ha57dvx6khw82kqvgcxwu8s8rjykjcqghprf42"

#: Token name of the configuration record (UTF-8 ``identity-config``, Part 2 §3.8).
CONFIG_TOKEN_NAME = b"identity-config"

# Vector mainnet (Part 1 §4): system start 2025-08-29T16:40:00Z, one slot per second.
MAINNET_SYSTEM_START_MS = 1_756_485_600_000
MAINNET_SLOT_LENGTH_MS = 1_000
MAINNET_NETWORK_MAGIC = 764_824_073

# Default public endpoints.
DEFAULT_GATEWAY_URL = "https://id.vector.apexfusion.org"
DEFAULT_OGMIOS_URL = "https://ogmios.vector.mainnet.apexfusion.org"
DEFAULT_KOIOS_URL = "https://v2.koios.vector.mainnet.apexfusion.org/api/v1"
