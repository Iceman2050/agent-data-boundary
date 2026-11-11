"""agent-data-boundary: cross-store personal-data lifecycle testing for agent systems.

Inventories configured local data stores, scans them with a versioned PII
detector, maps declared vs observed data flows, validates retention, and
verifies subject deletion per location (VERIFIED / UNVERIFIED / INACCESSIBLE).
Local files only. No network access.
"""
__version__ = "0.1.0"
