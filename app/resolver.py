"""Cache-less authoritative resolution over the submitted zones.

A "state" is the set of zone indexes already cut over to their new records.
Every lookup reflects exactly that state: no TTLs, no negative caching, no
partial zone contents.  Each unresolved chain is classified so that a duty
operator can tell a missing record apart from a CNAME cycle:

* ``missing_record`` - the chain reaches a name that has no A/CNAME RRset in
  its authoritative zone (``NODATA`` if the name exists, ``NXDOMAIN`` if it
  does not);
* ``cname_loop`` - the chain revisits a name;
* ``external_target`` - the chain leaves the submitted zones, so we hold no
  authoritative data for it;
* ``chain_too_long`` - more than ``MAX_CNAME_HOPS`` aliases.

Wildcard records (only the wildcard-check endpoint submits them) follow the
RFC 4592 closest-encloser rule, restricted to A/CNAME:

* a name with no records of its own but with records below it (an empty
  non-terminal) still exists, so it never falls through to a wildcard;
* a wildcard is consulted only when the query name does not exist, and only
  the wildcard directly below the *closest existing ancestor* matches;
* an existing but empty wildcard answers NODATA rather than NXDOMAIN;
* every CNAME hop re-runs this lookup.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from .models import CheckZone, PeerZone, Record, Zone, zone_covering

MAX_CNAME_HOPS = 32

Outcome = Literal["cname", "a", "nodata", "nxdomain", "external", "loop", "too_long"]
FailureCategory = Literal[
    "missing_record", "cname_loop", "external_target", "chain_too_long"
]

# Anything the resolver can be built over: /plan zones, the changing zone of
# the wildcard check, or a static peer zone.
ZoneLike = Zone | CheckZone | PeerZone


@dataclass
class TraceEntry:
    name: str
    zone: str | None
    outcome: Outcome
    target: str | None = None
    addresses: list[str] = field(default_factory=list)
    # Owner name of the wildcard record that synthesised this hop, if any.
    wildcard: str | None = None


@dataclass
class Resolution:
    domain: str
    addresses: list[str]
    trace: list[TraceEntry]
    category: FailureCategory | None = None
    detail: str | None = None
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.category is None

    def chain_text(self) -> str:
        parts = [self.domain]
        for entry in self.trace:
            if entry.outcome == "cname":
                via = f"（命中通配 {entry.wildcard}）" if entry.wildcard else ""
                parts.append(f" --CNAME{via}--> {entry.target}")
            elif entry.outcome == "loop":
                parts.append(f" => 回到 {entry.name}，成环")
            elif entry.outcome == "nodata":
                if entry.wildcard:
                    parts.append(f" => 无记录（NODATA，空通配 {entry.wildcard}）")
                else:
                    parts.append(" => 无记录（NODATA）")
            elif entry.outcome == "nxdomain":
                parts.append(" => 无记录（NXDOMAIN）")
            elif entry.outcome == "external":
                parts.append(" => 不在已提交的权威区内，无数据")
            elif entry.outcome == "too_long":
                parts.append(" => CNAME 链过长")
            elif entry.outcome == "a":
                via = f"（命中通配 {entry.wildcard}）" if entry.wildcard else ""
                parts.append(" => A " + ", ".join(entry.addresses) + via)
        return "".join(parts)


def _record_map(records: list[Record]) -> dict[str, list[Record]]:
    out: dict[str, list[Record]] = {}
    for rec in records:
        out.setdefault(rec.name, []).append(rec)
    return out


class Resolver:
    def __init__(self, zones: Sequence[ZoneLike]) -> None:
        self.zones = list(zones)
        self.zone_names = [z.name for z in self.zones]
        self._old = [_record_map(z.records) for z in self.zones]
        self._new = [_record_map(z.new_records) for z in self.zones]
        self._exists_old = [
            self._existing_names(z.name, data) for z, data in zip(self.zones, self._old)
        ]
        self._exists_new = [
            self._existing_names(z.name, data) for z, data in zip(self.zones, self._new)
        ]

    @staticmethod
    def _existing_names(
        zone_name: str, data: dict[str, list[Record]]
    ) -> frozenset[str]:
        """Names that exist in one zone state.

        A name exists if it owns records, if it is the apex, or if any record
        owner sits below it (empty non-terminal).  Wildcard owners count like
        any other name, so ``*.a.example.com`` makes ``a.example.com`` exist.
        """
        names = {zone_name}
        for owner in data:
            name = owner
            while name not in names:
                names.add(name)
                if name == zone_name:
                    break
                name = name.split(".", 1)[1] if "." in name else zone_name
        return frozenset(names)

    def _zone_data(self, idx: int, released: frozenset[int]) -> dict[str, list[Record]]:
        return self._new[idx] if idx in released else self._old[idx]

    def _zone_exists(self, idx: int, released: frozenset[int]) -> frozenset[str]:
        return self._exists_new[idx] if idx in released else self._exists_old[idx]

    def _lookup(
        self, name: str, released: frozenset[int]
    ) -> tuple[str | None, list[Record], bool, str | None]:
        """Return (zone, records, whether name exists, matched wildcard).

        With no exact match and no empty-non-terminal match, the name does
        not exist: find its closest existing ancestor and answer with the
        wildcard record directly below it, if that wildcard exists.
        """
        owner = zone_covering(name, self.zone_names)
        if owner is None:
            return None, [], False, None
        zone_name, idx = owner
        data = self._zone_data(idx, released)
        records = data.get(name, [])
        if records:
            return zone_name, records, True, None
        exists = self._zone_exists(idx, released)
        if name in exists:
            # The apex always exists (SOA/NS); a name with records below it
            # is an empty non-terminal.  Both answer NODATA, never wildcard.
            return zone_name, [], True, None
        # The name does not exist: walk up to the closest existing ancestor
        # (the apex always exists, so the walk terminates) and try the
        # wildcard directly below it.
        ancestor = name
        while ancestor not in exists:
            ancestor = ancestor.split(".", 1)[1] if "." in ancestor else zone_name
        wildcard_name = "*." + ancestor
        wrecords = data.get(wildcard_name, [])
        if wrecords:
            return zone_name, wrecords, True, wildcard_name
        if wildcard_name in exists:
            # The wildcard name exists but holds no A/CNAME RRset: an empty
            # wildcard answers NODATA, not NXDOMAIN.
            return zone_name, [], True, wildcard_name
        return zone_name, [], False, None

    def resolve(self, domain: str, released: frozenset[int]) -> Resolution:
        trace: list[TraceEntry] = []
        visited: set[str] = set()
        name = domain
        for _ in range(MAX_CNAME_HOPS + 1):
            if name in visited:
                loop_zone, _recs, _exists, _wild = self._lookup(name, released)
                trace.append(TraceEntry(name=name, zone=loop_zone, outcome="loop"))
                return Resolution(
                    domain=domain,
                    addresses=[],
                    trace=trace,
                    category="cname_loop",
                    message=f"{domain} 的 CNAME 链成环，无法解析出 IPv4 地址",
                )
            visited.add(name)

            zone_name, records, exists, wildcard = self._lookup(name, released)
            if zone_name is None:
                trace.append(TraceEntry(name=name, zone=None, outcome="external"))
                return Resolution(
                    domain=domain,
                    addresses=[],
                    trace=trace,
                    category="external_target",
                    message=(
                        f"{domain} 的解析链到达 {name}，该名称不在任何已提交的"
                        "权威区内，无法确认其 IPv4 地址"
                    ),
                )
            if not records:
                outcome: Outcome = "nodata" if exists else "nxdomain"
                trace.append(
                    TraceEntry(
                        name=name, zone=zone_name, outcome=outcome, wildcard=wildcard
                    )
                )
                if wildcard is not None:
                    reason = (
                        f"通配记录 {wildcard} 为空（存在但没有 A/CNAME 记录，"
                        "NODATA）"
                    )
                elif exists:
                    reason = "该名称存在但没有 A/CNAME 记录（NODATA）"
                else:
                    reason = "该名称不存在（NXDOMAIN）"
                return Resolution(
                    domain=domain,
                    addresses=[],
                    trace=trace,
                    category="missing_record",
                    detail=outcome,
                    message=f"{domain} 的解析链在 {name} 断开：区 {zone_name} 中{reason}",
                )

            cname = next((r for r in records if r.type == "CNAME"), None)
            if cname is not None:
                trace.append(
                    TraceEntry(
                        name=name,
                        zone=zone_name,
                        outcome="cname",
                        target=cname.value,
                        wildcard=wildcard,
                    )
                )
                name = cname.value
                continue

            addresses = sorted({r.value for r in records if r.type == "A"})
            trace.append(
                TraceEntry(
                    name=name,
                    zone=zone_name,
                    outcome="a",
                    addresses=addresses,
                    wildcard=wildcard,
                )
            )
            return Resolution(domain=domain, addresses=addresses, trace=trace)

        trace.append(TraceEntry(name=name, zone=None, outcome="too_long"))
        return Resolution(
            domain=domain,
            addresses=[],
            trace=trace,
            category="chain_too_long",
            message=f"{domain} 的 CNAME 链超过 {MAX_CNAME_HOPS} 跳，视为不可解析",
        )

    def resolve_all(
        self, domains: list[str], released: frozenset[int]
    ) -> list[Resolution]:
        return [self.resolve(d, released) for d in domains]
