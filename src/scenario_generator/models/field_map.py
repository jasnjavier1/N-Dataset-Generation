from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(slots=True)
class FieldMap:
    """Declarative mapping from canonical event fields to target field names."""

    adapter_name: str
    version: str = "1.0"
    target_type: str = ""  # e.g., "identity_signin", "audit_activity"
    description: str = ""
    columns: Mapping[str, str] = field(default_factory=dict)
    required_canonical_fields: tuple[str, ...] = field(default_factory=tuple)
    defaults: Mapping[str, object] = field(default_factory=dict)
    # Future-ready normalization metadata
    #transforms: Mapping[str, str] = field(default_factory=dict)