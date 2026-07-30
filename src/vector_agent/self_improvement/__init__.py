"""Self-Improvement module (Game 6) - preferred import name.

``vector_agent.governance`` remains available as a compatibility alias;
the classes are identical.
"""

from vector_agent.governance import blueprint, client, datums, indexer, types  # noqa: F401
from vector_agent.governance.client import GovernanceClient as SelfImprovementClient
from vector_agent.governance.indexer import GovernanceIndexer as SelfImprovementIndexer

__all__ = [
    "SelfImprovementClient",
    "SelfImprovementIndexer",
    "blueprint",
    "client",
    "datums",
    "indexer",
    "types",
]
