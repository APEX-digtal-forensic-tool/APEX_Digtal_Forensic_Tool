"""APEX Forensic Core Engine Phase 1 foundation."""

import os

from apex_forensic.constants import ENGINE_VERSION, SCHEMA_VERSION

# Opt out before any optional ML dependency initializes native telemetry.
# A local forensic session must not disclose usage or device identifiers.
os.environ["ORT_DISABLE_TELEMETRY"] = "1"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"

__all__ = ["ENGINE_VERSION", "SCHEMA_VERSION"]
