"""Origin tracking for text handled by the Sentinel prototype.

Web-derived content is untrusted by default. Transformations and combinations
preserve taint: combining trusted and untrusted values produces untrusted data.
This module is metadata plumbing, not a sandbox or an authentication system.
Only trusted ingestion code should construct trusted Provenance records.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class TrustLabel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Provenance:
    """Immutable trust label and lineage metadata for a piece of data."""

    label: TrustLabel
    source: str
    lineage: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.label, TrustLabel):
            raise TypeError("label must be a TrustLabel")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("source must be a non-empty string")
        if isinstance(self.lineage, str) or not isinstance(self.lineage, tuple):
            raise TypeError("lineage must be a tuple of operation names")
        if any(not isinstance(item, str) or not item.strip() for item in self.lineage):
            raise ValueError("lineage entries must be non-empty strings")


@dataclass(frozen=True)
class TrackedText:
    """Text plus immutable provenance; transformations cannot upgrade trust."""

    value: str
    provenance: Provenance

    def __post_init__(self) -> None:
        if not isinstance(self.value, str):
            raise TypeError("TrackedText value must be a string")
        if not isinstance(self.provenance, Provenance):
            raise TypeError("provenance must be a Provenance instance")

    @classmethod
    def from_web(cls, value: str, source_url: str) -> "TrackedText":
        """Create untrusted text at the web-ingestion boundary."""
        return cls(value, Provenance(TrustLabel.UNTRUSTED, source_url))

    @classmethod
    def from_trusted_source(cls, value: str, source: str) -> "TrackedText":
        """Create trusted text; call only from a trusted application boundary."""
        return cls(value, Provenance(TrustLabel.TRUSTED, source))

    @property
    def is_trusted(self) -> bool:
        return self.provenance.label is TrustLabel.TRUSTED

    def mark_untrusted(self, reason: str) -> "TrackedText":
        """Conservatively lower trust; there is intentionally no promotion API."""
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be a non-empty string")
        return TrackedText(
            self.value,
            Provenance(
                TrustLabel.UNTRUSTED,
                self.provenance.source,
                self.provenance.lineage + (f"mark_untrusted:{reason.strip()}",),
            ),
        )

    def transform(
        self,
        operation: str,
        function: Callable[[str], str],
    ) -> "TrackedText":
        """Apply a text transformation while preserving its trust label."""
        if not isinstance(operation, str) or not operation.strip():
            raise ValueError("operation must be a non-empty string")
        if not callable(function):
            raise TypeError("function must be callable")
        transformed = function(self.value)
        if not isinstance(transformed, str):
            raise TypeError("text transformation must return a string")
        return TrackedText(
            transformed,
            Provenance(
                self.provenance.label,
                self.provenance.source,
                self.provenance.lineage + (operation.strip(),),
            ),
        )

    def combine(
        self,
        other: "TrackedText",
        separator: str = "",
        operation: str = "combine",
    ) -> "TrackedText":
        """Combine text; untrusted input taints the complete result."""
        if not isinstance(other, TrackedText):
            raise TypeError("other must be TrackedText")
        if not isinstance(separator, str):
            raise TypeError("separator must be a string")
        if not isinstance(operation, str) or not operation.strip():
            raise ValueError("operation must be a non-empty string")

        label = (
            TrustLabel.UNTRUSTED
            if TrustLabel.UNTRUSTED in {self.provenance.label, other.provenance.label}
            else TrustLabel.TRUSTED
        )
        sources = tuple(dict.fromkeys((self.provenance.source, other.provenance.source)))
        lineage = self.provenance.lineage + other.provenance.lineage + (operation.strip(),)
        return TrackedText(
            self.value + separator + other.value,
            Provenance(label, "combined:" + "|".join(sources), lineage),
        )
