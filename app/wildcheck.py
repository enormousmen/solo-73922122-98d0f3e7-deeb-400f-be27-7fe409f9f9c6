"""Pre-change check for wildcard record edits.

Before a duty officer edits wildcard records, they need to know whether
*unregistered* hostnames will get different answers.  This module compares
one authoritative zone's current A/CNAME snapshot against the planned one
and answers exactly that, reusing the planner's cache-less resolution
(no TTLs, 32-hop CNAME limit, out-of-zone targets are unconfirmable).

Why a finite candidate set is sufficient
----------------------------------------
The zone contains infinitely many potential query names, but only finitely
many distinct answers exist.  In one snapshot a concrete query name either

* exists (record owner, empty non-terminal, or the apex) and is answered
  from its own data, or
* does not exist, in which case its answer depends only on its *closest
  existing ancestor* (the wildcard directly below it, if any).

So the pair (status in old snapshot, status in new snapshot) fixes both
answers, and that pair is shared by every name that falls off the tree at
the same point.  Checking

1. every concrete name that exists in either snapshot, and
2. one synthetic probe (a fresh child label, absent from both snapshots)
   under every existing concrete name,

covers every legal concrete query name in the zone: any other name shares
its (closest-existing-ancestor-old, closest-existing-ancestor-new) pair
with one of the probes and therefore resolves identically on both sides.
Wildcard owner names themselves are not legal concrete query names and are
never used as candidates.
"""

from __future__ import annotations

from typing import Any

from .models import WildcardCheckRequest, WildcardRecord
from .resolver import Resolution, Resolver
from .service import CATEGORY_LABELS, resolution_json

CHANGE_LABELS = {
    "addresses_changed": "IPv4 地址集合改变",
    "resolution_lost": "变更前可解析，变更后失败",
    "resolution_gained": "变更前失败，变更后可解析",
    "failure_type_changed": "失败类型改变",
}

STATUS_MEANINGS = {
    "equivalent": "变更前后所有名称的应答一致",
    "different": "变更前后存在应答不同的名称",
}

ASSUMPTIONS = [
    "只比较变更区内合法具体名称的应答；通配记录名本身不作为查询名。",
    "通配记录只允许记录名最左侧一个 * 标签；CNAME 目标必须是具体名称。",
    "自身无记录但下方有记录的名称（空非终端）视为存在，不会触发通配。",
    "只有查询名不存在时，才用最近一个已存在祖先下的通配记录合成应答；"
    "每一跳 CNAME 都按此重新查找。",
    "解析不经过缓存；CNAME 链最多 32 跳；链离开已提交的区即视为无法确认"
    "（可把相关区放进 peer_zones 纳入推演）。",
    "只比较最终应答的 IPv4 地址集合或失败类型（区分 NXDOMAIN/NODATA），"
    "不比较中间链路；peer_zones 内名称的应答变化不在核查范围。",
]


def _existing_names(
    zone_name: str, records: list[WildcardRecord]
) -> frozenset[str]:
    """Names that exist in one snapshot: owners, empty non-terminals, apex."""
    names = {zone_name}
    for rec in records:
        name = rec.name
        while name not in names:
            names.add(name)
            if name == zone_name:
                break
            name = name.split(".", 1)[1] if "." in name else zone_name
    return frozenset(names)


def _probe_label(parent: str, taken: frozenset[str]) -> str:
    """A deterministic child label of ``parent`` absent from both snapshots.

    ``taken`` is ancestor-closed (it contains every ancestor of every
    existing name), so ``<label>.<parent>`` not being in it also guarantees
    nothing exists below the probe name.
    """
    label = "wildcard-probe"
    n = 2
    while f"{label}.{parent}" in taken:
        label = f"wildcard-probe-{n}"
        n += 1
    return label


def candidate_names(
    zone_name: str,
    old: list[WildcardRecord],
    new: list[WildcardRecord],
) -> tuple[list[str], frozenset[str]]:
    """Sorted concrete query names covering every possible answer change.

    Returns the candidates plus the union of existing names in both
    snapshots (used to tell registered names from synthetic probes).
    """
    known = _existing_names(zone_name, old) | _existing_names(zone_name, new)
    concrete = {n for n in known if not n.startswith("*.")}
    candidates = set(concrete)
    for base in concrete:
        candidates.add(f"{_probe_label(base, known)}.{base}")
    return sorted(candidates), known


def _signature(res: Resolution) -> tuple:
    """The compared answer: IPv4 address set, or failure type."""
    if res.ok:
        return ("ok", tuple(res.addresses))
    return ("fail", res.category, res.detail)


def _change_kind(before: Resolution, after: Resolution) -> str:
    if before.ok and after.ok:
        return "addresses_changed"
    if before.ok:
        return "resolution_lost"
    if after.ok:
        return "resolution_gained"
    return "failure_type_changed"


def build_wildcard_check(request: WildcardCheckRequest) -> dict[str, Any]:
    zone = request.zone
    # The changing zone sits at index 0: ``released=set()`` is the old
    # snapshot, ``released={0}`` the new one; peers never change.
    resolver = Resolver([zone, *request.peer_zones])
    before_state: frozenset[int] = frozenset()
    after_state: frozenset[int] = frozenset({0})

    candidates, known = candidate_names(zone.name, zone.records, zone.new_records)
    differences: list[tuple[str, Resolution, Resolution]] = []
    for name in candidates:
        before = resolver.resolve(name, before_state)
        after = resolver.resolve(name, after_state)
        if _signature(before) != _signature(after):
            differences.append((name, before, after))

    base: dict[str, Any] = {
        "mode": "authoritative_no_cache",
        "zone": zone.name,
        "candidates_checked": len(candidates),
        "differences_found": len(differences),
        "assumptions": ASSUMPTIONS,
    }

    if not differences:
        return {
            **base,
            "status": "equivalent",
            "status_meaning": STATUS_MEANINGS["equivalent"],
            "message": (
                f"在 {len(candidates)} 个候选名称（覆盖区内全部已存在名称及每个"
                "通配匹配类的代表名）上，变更前后的 IPv4 地址集合与失败类型完全"
                "一致；未登记主机名的应答不会变化。"
            ),
        }

    name, before, after = differences[0]
    kind = _change_kind(before, after)
    synthetic = name not in known
    counterexample = {
        "name": name,
        "name_kind": "synthetic_probe" if synthetic else "existing_name",
        "name_note": (
            "该名称是合成的代表名：同一最近已存在祖先下的所有未登记名称，"
            "应答与此完全相同。"
            if synthetic
            else None
        ),
        "change": kind,
        "change_label": CHANGE_LABELS[kind],
        "before": resolution_json(before),
        "after": resolution_json(after),
    }
    return {
        **base,
        "status": "different",
        "status_meaning": STATUS_MEANINGS["different"],
        "message": (
            f"变更前后有 {len(differences)} 个候选名称的应答不同（共核查 "
            f"{len(candidates)} 个）。反例：{name}（{CHANGE_LABELS[kind]}）。"
            "下方给出该名称变更前后的完整解析链；命中通配记录的跳已在 chain "
            "与 trace 中标注。"
        ),
        "counterexample": counterexample,
    }


__all__ = [
    "CATEGORY_LABELS",
    "build_wildcard_check",
    "candidate_names",
]
