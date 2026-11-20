"""Request models and validation for the release planner.

The service plans an ordering of whole-zone cutovers.  In every state DNS is
evaluated as an authoritative, cache-less resolver would see it: each zone is
either entirely on its old data or entirely on its new data.  There is no
partial propagation inside a zone and no TTL cache that could mask a broken
intermediate state.

Only A and CNAME records are supported.  CNAME chains are followed across the
submitted zones.  A chain that leaves the submitted zones is *not* assumed to
work: we hold no authoritative data for it, so it is reported as an
unresolvable target (add the external zone as an unchanged zone, i.e. with
``records == new_records``, to model it explicitly).
"""

from __future__ import annotations

import ipaddress
import re
from typing import ClassVar, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

# Conservative DNS name check: 1-63 char labels, dot separators, optional
# trailing root dot.  Wildcards and escape sequences are rejected because the
# planner reasons about concrete CNAME chains and cannot give a sound answer
# for pattern records.
_LABEL = r"(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
_NAME_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}\.?$")
MAX_NAME_LENGTH = 253

MAX_ZONES = 8
MAX_RECORDS_PER_ZONE = 256
MAX_REQUIRED_DOMAINS = 64


def normalize_name(name: str) -> str:
    """Canonical comparison form: lowercase, no trailing root dot."""
    return name.rstrip(".").lower()


def validate_name(name: str, what: str) -> str:
    """Validate a DNS name and return its canonical form."""
    if len(name.rstrip(".")) > MAX_NAME_LENGTH or not _NAME_RE.match(name):
        raise ValueError(f"invalid {what}: {name!r}")
    return normalize_name(name)


def validate_wildcard_owner(name: str, what: str) -> str:
    """Validate a record owner name that may be a wildcard.

    Only a single leftmost ``*`` label makes the record a wildcard
    (``*.example.com``); anything else containing ``*`` (``*.*.x``,
    ``web*.x``, ``web.*.x``) is rejected.  The remainder must be a valid
    concrete name, and the canonical form keeps the ``*.`` prefix.
    """
    if len(name.rstrip(".")) > MAX_NAME_LENGTH:
        raise ValueError(f"invalid {what}: {name!r}")
    if name.startswith("*."):
        rest = name[2:]
        if "*" in rest:
            raise ValueError(
                f"invalid {what}: {name!r}; a wildcard record allows only a "
                "single leftmost '*' label"
            )
        return "*." + validate_name(rest, what)
    if "*" in name:
        raise ValueError(
            f"invalid {what}: {name!r}; a wildcard record allows only a "
            "single leftmost '*' label"
        )
    return validate_name(name, what)


def in_zone(name: str, zone: str) -> bool:
    """True if ``name`` is ``zone`` itself or a subdomain of it."""
    return name == zone or name.endswith("." + zone)


def zone_covering(name: str, zone_names: list[str]) -> tuple[str, int] | None:
    """Return ``(owning zone, input index)`` for ``name``, or None."""
    best: tuple[str, int] | None = None
    for idx, z in enumerate(zone_names):
        if in_zone(name, z) and (best is None or len(z) > len(best[0])):
            best = (z, idx)
    return best


class Record(BaseModel):
    name: str
    type: Literal["A", "CNAME"]
    value: str
    # TTL is accepted for documentation/round-tripping but deliberately has no
    # effect: the plan is evaluated without caching.
    ttl: int = Field(default=300, ge=0, le=2_147_483_647)

    # /plan reasons about concrete names only; the wildcard-check endpoint
    # uses the WildcardRecord subclass which also accepts "*.name" owners.
    _allow_wildcard: ClassVar[bool] = False

    @field_validator("type", mode="before")
    @classmethod
    def _normalise_type(cls, v: object) -> object:
        return v.strip().upper() if isinstance(v, str) else v

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if cls._allow_wildcard:
            return validate_wildcard_owner(v, "DNS owner name")
        return validate_name(v, "DNS owner name")

    @model_validator(mode="after")
    def _valid_value(self) -> "Record":
        if self.type == "A":
            try:
                ipaddress.IPv4Address(self.value)
            except ValueError:
                raise ValueError(
                    f"A record for {self.name!r} must be an IPv4 address, "
                    f"got {self.value!r}"
                )
            self.value = str(ipaddress.IPv4Address(self.value))
        else:
            self.value = validate_name(
                self.value, f"CNAME target of {self.name!r}"
            )
        return self


def check_zone_rrset(field: str, records: list[Record], zone_name: str) -> None:
    """Enforce authoritative-DNS invariants on one zone-state's RRsets."""
    owned: dict[str, tuple[str, set[str]]] = {}
    for rec in records:
        if not in_zone(rec.name, zone_name):
            raise ValueError(
                f"{field}: {rec.name!r} is not owned by zone {zone_name!r} "
                "(zones must be self-contained)"
            )
        if rec.name == zone_name and rec.type == "CNAME":
            raise ValueError(
                f"{field}: CNAME at the zone apex {zone_name!r} is not "
                "valid in authoritative DNS (the apex holds SOA/NS)"
            )
        previous = owned.get(rec.name)
        if previous is not None and previous[0] != rec.type:
            raise ValueError(
                f"{field}: {rec.name!r} has both A and CNAME records, "
                "which authoritative DNS forbids"
            )
        targets = previous[1] if previous else set()
        if rec.type == "CNAME":
            targets.add(rec.value)
            if len(targets) > 1:
                raise ValueError(
                    f"{field}: {rec.name!r} has conflicting CNAME targets"
                )
        owned[rec.name] = (rec.type, targets)

    # A name holding a CNAME cannot also have names below it.
    cnames = [n for n, (t, _targets) in owned.items() if t == "CNAME"]
    for cname in cnames:
        suffix = "." + cname
        if any(other != cname and other.endswith(suffix) for other in owned):
            raise ValueError(
                f"{field}: {cname!r} is a CNAME but also has names below "
                "it; authoritative DNS forbids that"
            )


class Zone(BaseModel):
    """One authoritative zone described by its current and next state.

    ``records`` is the zone as it exists now; ``new_records`` is the zone
    after this zone's whole-zone cutover.  A zone with identical old and new
    data models an unchanged zone that is still authoritative for the names
    in it (useful when such a zone is a CNAME target).  All owner names must
    belong to the zone, which is what makes "who owns name X" unambiguous.
    """

    name: str
    records: list[Record] = Field(default_factory=list, max_length=MAX_RECORDS_PER_ZONE)
    new_records: list[Record] = Field(
        default_factory=list, max_length=MAX_RECORDS_PER_ZONE
    )

    @field_validator("name")
    @classmethod
    def _valid_zone(cls, v: str) -> str:
        return validate_name(v, "zone name")

    @model_validator(mode="after")
    def _check_zone_records(self) -> "Zone":
        check_zone_rrset("records", self.records, self.name)
        check_zone_rrset("new_records", self.new_records, self.name)
        return self


class PlanRequest(BaseModel):
    zones: list[Zone] = Field(min_length=1, max_length=MAX_ZONES)
    required_domains: list[str] = Field(
        min_length=1, max_length=MAX_REQUIRED_DOMAINS
    )

    @field_validator("required_domains")
    @classmethod
    def _valid_domains(cls, v: list[str]) -> list[str]:
        out = [validate_name(name, "required domain") for name in v]
        if len(set(out)) != len(out):
            raise ValueError("required_domains contains duplicates")
        return out

    @model_validator(mode="after")
    def _check_topology(self) -> "PlanRequest":
        names = [z.name for z in self.zones]
        if len(set(names)) != len(names):
            raise ValueError("duplicate zone names")
        for a in names:
            for b in names:
                if a != b and in_zone(a, b):
                    raise ValueError(
                        f"zones must be non-nested: {a!r} is inside {b!r}"
                    )
        for domain in self.required_domains:
            if zone_covering(domain, names) is None:
                raise ValueError(
                    f"required domain {domain!r} is not inside any submitted "
                    "zone; the planner only has authoritative data for the "
                    "submitted zones"
                )
        return self


# --------------------------------------------------------------------------- #
# Wildcard-change check
# --------------------------------------------------------------------------- #


class WildcardRecord(Record):
    """An A/CNAME record whose owner name may be a wildcard.

    The wildcard form is restricted to a single leftmost ``*`` label
    (``*.example.com``); CNAME targets stay concrete names, exactly as in
    the base record.
    """

    _allow_wildcard: ClassVar[bool] = True


class CheckZone(BaseModel):
    """The zone being edited: its current snapshot and the planned one.

    Same invariants as :class:`Zone`, but owner names may be wildcards.
    """

    name: str
    records: list[WildcardRecord] = Field(
        default_factory=list, max_length=MAX_RECORDS_PER_ZONE
    )
    new_records: list[WildcardRecord] = Field(
        default_factory=list, max_length=MAX_RECORDS_PER_ZONE
    )

    @field_validator("name")
    @classmethod
    def _valid_zone(cls, v: str) -> str:
        return validate_name(v, "zone name")

    @model_validator(mode="after")
    def _check_zone_records(self) -> "CheckZone":
        check_zone_rrset("records", self.records, self.name)
        check_zone_rrset("new_records", self.new_records, self.name)
        return self


class PeerZone(BaseModel):
    """An unchanged zone submitted so CNAME chains into it can be followed.

    Peer zones do not change, so they carry a single record set; the check
    only compares answers for names inside the changing zone.
    """

    name: str
    records: list[WildcardRecord] = Field(
        default_factory=list, max_length=MAX_RECORDS_PER_ZONE
    )

    @field_validator("name")
    @classmethod
    def _valid_zone(cls, v: str) -> str:
        return validate_name(v, "zone name")

    @model_validator(mode="after")
    def _check_zone_records(self) -> "PeerZone":
        check_zone_rrset("records", self.records, self.name)
        return self

    @property
    def new_records(self) -> list[WildcardRecord]:
        # Unchanged zone: both resolution states see the same records.
        return self.records


class WildcardCheckRequest(BaseModel):
    """Before/after snapshots of one authoritative zone (plus static peers)."""

    zone: CheckZone
    peer_zones: list[PeerZone] = Field(
        default_factory=list, max_length=MAX_ZONES - 1
    )

    @model_validator(mode="after")
    def _check_topology(self) -> "WildcardCheckRequest":
        names = [self.zone.name] + [p.name for p in self.peer_zones]
        if len(set(names)) != len(names):
            raise ValueError("duplicate zone names")
        for a in names:
            for b in names:
                if a != b and in_zone(a, b):
                    raise ValueError(
                        f"zones must be non-nested: {a!r} is inside {b!r}"
                    )
        return self
