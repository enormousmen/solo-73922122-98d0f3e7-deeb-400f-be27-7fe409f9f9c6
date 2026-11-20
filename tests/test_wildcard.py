"""Tests for /wildcard-check: wildcard semantics, equivalence, validation."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.models import CheckZone, WildcardCheckRequest
from app.resolver import Resolver
from app.wildcheck import build_wildcard_check, candidate_names

client = TestClient(app)


def rec(name: str, rtype: str, value: str) -> dict[str, str]:
    return {"name": name, "type": rtype, "value": value}


def check(
    old: list[dict], new: list[dict] | None = None, peers: list[dict] | None = None
) -> dict:
    payload: dict = {
        "zone": {
            "name": "example.com",
            "records": old,
            "new_records": old if new is None else new,
        }
    }
    if peers:
        payload["peer_zones"] = peers
    return build_wildcard_check(WildcardCheckRequest.model_validate(payload))


def resolver_for(records: list[dict], zone_name: str = "example.com") -> Resolver:
    zone = CheckZone.model_validate(
        {"name": zone_name, "records": records, "new_records": records}
    )
    return Resolver([zone])


# --------------------------------------------------------------------------- #
# Wildcard resolution semantics (resolver level)
# --------------------------------------------------------------------------- #


def test_unregistered_name_matches_wildcard() -> None:
    r = resolver_for([rec("*.example.com", "A", "10.0.0.1")])
    res = r.resolve("anything.example.com", frozenset())
    assert res.ok and res.addresses == ["10.0.0.1"]
    assert res.trace[0].wildcard == "*.example.com"
    assert "（命中通配 *.example.com）" in res.chain_text()


def test_registered_name_shadows_wildcard() -> None:
    """Only a non-existent query name falls through to the wildcard."""
    r = resolver_for(
        [
            rec("*.example.com", "A", "10.0.0.1"),
            rec("www.example.com", "A", "10.0.0.9"),
        ]
    )
    res = r.resolve("www.example.com", frozenset())
    assert res.addresses == ["10.0.0.9"]
    assert res.trace[0].wildcard is None


def test_empty_non_terminal_blocks_wildcard() -> None:
    """A name with no records but with records below it still exists."""
    r = resolver_for(
        [
            rec("*.example.com", "A", "10.0.0.1"),
            rec("deep.ent.example.com", "A", "10.0.0.5"),
        ]
    )
    res = r.resolve("ent.example.com", frozenset())
    assert not res.ok
    assert res.category == "missing_record"
    assert res.detail == "nodata"
    assert res.trace[0].wildcard is None


def test_closest_existing_ancestor_selects_wildcard() -> None:
    r = resolver_for(
        [
            rec("*.example.com", "A", "10.0.0.1"),
            rec("*.b.example.com", "A", "10.0.0.2"),
        ]
    )
    # b.example.com exists (it is the wildcard's parent), so *.b wins there...
    assert r.resolve("x.b.example.com", frozenset()).addresses == ["10.0.0.2"]
    # ...even for names several labels below it...
    assert r.resolve("x.y.b.example.com", frozenset()).addresses == ["10.0.0.2"]
    # ...while names elsewhere fall to the apex wildcard.
    assert r.resolve("x.c.example.com", frozenset()).addresses == ["10.0.0.1"]


def test_no_wildcard_at_ancestor_is_nxdomain() -> None:
    r = resolver_for([rec("deep.ent.example.com", "A", "10.0.0.5")])
    res = r.resolve("nope.ent.example.com", frozenset())
    assert res.detail == "nxdomain"


def test_every_cname_hop_rechecks_wildcards() -> None:
    """A wildcard CNAME target may itself only resolve via another wildcard."""
    r = resolver_for(
        [
            rec("*.example.com", "CNAME", "svc.b.example.com"),
            rec("*.b.example.com", "A", "10.0.0.9"),
        ]
    )
    res = r.resolve("foo.example.com", frozenset())
    assert res.ok and res.addresses == ["10.0.0.9"]
    assert [t.wildcard for t in res.trace] == ["*.example.com", "*.b.example.com"]
    assert res.chain_text() == (
        "foo.example.com --CNAME（命中通配 *.example.com）--> svc.b.example.com"
        " => A 10.0.0.9（命中通配 *.b.example.com）"
    )


def test_wildcard_cname_self_loop_is_a_loop() -> None:
    r = resolver_for([rec("*.example.com", "CNAME", "x.example.com")])
    res = r.resolve("foo.example.com", frozenset())
    assert res.category == "cname_loop"


def test_wildcard_cname_leaving_zones_is_external() -> None:
    r = resolver_for([rec("*.example.com", "CNAME", "www.external.org")])
    res = r.resolve("foo.example.com", frozenset())
    assert res.category == "external_target"


def test_chain_longer_than_32_hops_still_capped() -> None:
    records = [
        rec(f"n{i}.example.com", "CNAME", f"n{i + 1}.example.com") for i in range(40)
    ] + [rec("n40.example.com", "A", "10.0.0.1")]
    r = resolver_for(records)
    assert r.resolve("n0.example.com", frozenset()).category == "chain_too_long"


# --------------------------------------------------------------------------- #
# Candidate enumeration
# --------------------------------------------------------------------------- #


def test_candidates_cover_existing_names_and_probes() -> None:
    zone = CheckZone.model_validate(
        {
            "name": "example.com",
            "records": [
                rec("*.example.com", "A", "10.0.0.1"),
                rec("www.example.com", "A", "10.0.0.9"),
            ],
            "new_records": [],
        }
    )
    candidates, known = candidate_names(
        "example.com", zone.records, zone.new_records
    )
    # Wildcard owners are not legal concrete query names.
    assert "*.example.com" not in candidates
    # Existing concrete names are candidates.
    assert {"example.com", "www.example.com"} <= set(candidates)
    # One synthetic probe per existing concrete name.
    assert "wildcard-probe.example.com" in candidates
    assert "wildcard-probe.www.example.com" in candidates
    assert all(not c.startswith("*.") for c in candidates)
    assert known == frozenset(
        {"example.com", "www.example.com", "*.example.com"}
    )


def test_probe_label_avoids_collisions() -> None:
    zone = CheckZone.model_validate(
        {
            "name": "example.com",
            "records": [
                rec("wildcard-probe.example.com", "A", "10.0.0.1"),
                rec("wildcard-probe-2.example.com", "A", "10.0.0.2"),
            ],
            "new_records": [],
        }
    )
    candidates, _ = candidate_names("example.com", zone.records, zone.new_records)
    assert "wildcard-probe-3.example.com" in candidates


# --------------------------------------------------------------------------- #
# Equivalence and counterexamples
# --------------------------------------------------------------------------- #


def test_identical_snapshots_are_equivalent() -> None:
    out = check([rec("*.example.com", "A", "10.0.0.1")])
    assert out["status"] == "equivalent"
    assert out["differences_found"] == 0
    assert "counterexample" not in out or out["counterexample"] is None


def test_ttl_only_change_is_equivalent() -> None:
    old = [{"name": "*.example.com", "type": "A", "value": "10.0.0.1", "ttl": 300}]
    new = [{"name": "*.example.com", "type": "A", "value": "10.0.0.1", "ttl": 60}]
    assert check(old, new)["status"] == "equivalent"


def test_wildcard_added_is_resolution_gained() -> None:
    out = check([rec("www.example.com", "A", "10.0.0.9")],
                [rec("www.example.com", "A", "10.0.0.9"),
                 rec("*.example.com", "A", "10.0.0.1")])
    assert out["status"] == "different"
    ce = out["counterexample"]
    assert ce["name"] == "wildcard-probe.example.com"
    assert ce["name_kind"] == "synthetic_probe"
    assert ce["change"] == "resolution_gained"
    assert ce["before"]["detail"] == "nxdomain"
    assert ce["after"]["resolved"] is True
    assert ce["after"]["addresses"] == ["10.0.0.1"]
    assert ce["after"]["trace"][0]["wildcard"] == "*.example.com"


def test_wildcard_removed_is_resolution_lost() -> None:
    out = check([rec("*.example.com", "A", "10.0.0.1")], [])
    assert out["status"] == "different"
    ce = out["counterexample"]
    assert ce["change"] == "resolution_lost"
    assert ce["before"]["resolved"] is True
    assert ce["after"]["category"] == "missing_record"
    assert ce["after"]["detail"] == "nxdomain"
    assert ce["after"]["chain"].endswith("=> 无记录（NXDOMAIN）")


def test_wildcard_address_change_is_addresses_changed() -> None:
    out = check([rec("*.example.com", "A", "10.0.0.1")],
                [rec("*.example.com", "A", "10.0.0.2")])
    ce = out["counterexample"]
    assert ce["change"] == "addresses_changed"
    assert ce["before"]["addresses"] == ["10.0.0.1"]
    assert ce["after"]["addresses"] == ["10.0.0.2"]


def test_nodata_to_nxdomain_is_failure_type_changed() -> None:
    """Removing the only record below a name turns NODATA into NXDOMAIN."""
    out = check([rec("zzz.ent.example.com", "A", "10.0.0.5")], [])
    ce = out["counterexample"]
    assert ce["name"] == "ent.example.com"
    assert ce["name_kind"] == "existing_name"
    assert ce["change"] == "failure_type_changed"
    assert ce["before"]["detail"] == "nodata"
    assert ce["after"]["detail"] == "nxdomain"


def test_registering_name_with_matching_wildcard_answer_is_equivalent() -> None:
    """Pinning a name to the address the wildcard would give changes nothing,
    provided the subtree below it keeps a matching wildcard too."""
    old = [rec("*.example.com", "A", "10.30.0.10")]
    new = [
        rec("*.example.com", "A", "10.30.0.10"),
        rec("www.example.com", "A", "10.30.0.10"),
        rec("*.www.example.com", "A", "10.30.0.10"),
    ]
    assert check(old, new)["status"] == "equivalent"


def test_registering_name_without_subtree_wildcard_breaks_deeper_names() -> None:
    """The subtle case the check exists for: after registering www, names
    like x.www.example.com stop matching *.example.com and go NXDOMAIN."""
    old = [rec("*.example.com", "A", "10.30.0.10")]
    new = [
        rec("*.example.com", "A", "10.30.0.10"),
        rec("www.example.com", "A", "10.30.0.10"),
    ]
    out = check(old, new)
    assert out["status"] == "different"
    ce = out["counterexample"]
    assert ce["name"] == "wildcard-probe.www.example.com"
    assert ce["change"] == "resolution_lost"
    assert ce["before"]["addresses"] == ["10.30.0.10"]
    assert ce["after"]["detail"] == "nxdomain"


def test_wildcard_cname_retarget_through_peer_zone() -> None:
    peers = [
        {
            "name": "svc.example.net",
            "records": [
                rec("lb.svc.example.net", "A", "10.40.0.10"),
                rec("lb2.svc.example.net", "A", "10.40.0.20"),
            ],
        }
    ]
    out = check(
        [rec("*.example.com", "CNAME", "lb.svc.example.net")],
        [rec("*.example.com", "CNAME", "lb2.svc.example.net")],
        peers,
    )
    assert out["status"] == "different"
    ce = out["counterexample"]
    assert ce["change"] == "addresses_changed"
    assert ce["before"]["chain"] == (
        "wildcard-probe.example.com --CNAME（命中通配 *.example.com）-->"
        " lb.svc.example.net => A 10.40.0.10"
    )
    assert ce["after"]["addresses"] == ["10.40.0.20"]
    # The peer zone name appears in the trace with its own zone label.
    assert ce["before"]["trace"][1]["zone"] == "svc.example.net"


def test_wildcard_cname_to_external_zone_changes_failure_type() -> None:
    out = check(
        [rec("*.example.com", "A", "10.0.0.1")],
        [rec("*.example.com", "CNAME", "www.external.org")],
    )
    ce = out["counterexample"]
    assert ce["change"] == "resolution_lost"
    assert ce["after"]["category"] == "external_target"


def test_new_wildcard_cname_loop_changes_failure_type() -> None:
    out = check(
        [rec("*.example.com", "A", "10.0.0.1")],
        [rec("*.example.com", "CNAME", "x.example.com")],
    )
    ce = out["counterexample"]
    assert ce["change"] == "resolution_lost"
    assert ce["after"]["category"] == "cname_loop"


def test_counterexample_is_deterministic() -> None:
    old = [rec("*.example.com", "A", "10.0.0.1")]
    new = [rec("*.example.com", "A", "10.0.0.2")]
    first = check(old, new)["counterexample"]["name"]
    second = check(old, new)["counterexample"]["name"]
    assert first == second


def test_multiple_differences_report_first_sorted_candidate() -> None:
    out = check(
        [rec("www.example.com", "A", "10.0.0.9"),
         rec("api.example.com", "A", "10.0.0.8")],
        [rec("www.example.com", "A", "10.0.1.9"),
         rec("api.example.com", "A", "10.0.1.8")],
    )
    assert out["differences_found"] == 2
    assert out["counterexample"]["name"] == "api.example.com"


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def payload(zone: dict, peers: list[dict] | None = None) -> dict:
    out = {"zone": zone}
    if peers:
        out["peer_zones"] = peers
    return out


def zone(old: list[dict], new: list[dict] | None = None) -> dict:
    return {"name": "example.com", "records": old,
            "new_records": old if new is None else new}


def test_rejects_double_wildcard() -> None:
    with pytest.raises(ValidationError, match="leftmost"):
        WildcardCheckRequest.model_validate(
            payload(zone([rec("*.*.example.com", "A", "10.0.0.1")]))
        )


def test_rejects_partial_wildcard_label() -> None:
    with pytest.raises(ValidationError, match="leftmost"):
        WildcardCheckRequest.model_validate(
            payload(zone([rec("web*.example.com", "A", "10.0.0.1")]))
        )


def test_rejects_wildcard_not_in_leftmost_position() -> None:
    with pytest.raises(ValidationError, match="leftmost"):
        WildcardCheckRequest.model_validate(
            payload(zone([rec("web.*.example.com", "A", "10.0.0.1")]))
        )


def test_rejects_lone_star() -> None:
    with pytest.raises(ValidationError):
        WildcardCheckRequest.model_validate(
            payload(zone([rec("*", "A", "10.0.0.1")]))
        )


def test_rejects_wildcard_cname_target() -> None:
    """CNAME targets stay concrete names even on wildcard records."""
    with pytest.raises(ValidationError, match="CNAME target"):
        WildcardCheckRequest.model_validate(
            payload(zone([rec("*.example.com", "CNAME", "*.elsewhere.com")]))
        )


def test_rejects_wildcard_zone_name() -> None:
    with pytest.raises(ValidationError):
        WildcardCheckRequest.model_validate(
            {"zone": {"name": "*.example.com", "records": [], "new_records": []}}
        )


def test_rejects_a_and_cname_at_same_wildcard() -> None:
    with pytest.raises(ValidationError, match="both A and CNAME"):
        WildcardCheckRequest.model_validate(
            payload(zone([
                rec("*.example.com", "A", "10.0.0.1"),
                rec("*.example.com", "CNAME", "www.example.com"),
            ]))
        )


def test_rejects_conflicting_wildcard_cname_targets() -> None:
    with pytest.raises(ValidationError, match="conflicting CNAME"):
        WildcardCheckRequest.model_validate(
            payload(zone([
                rec("*.example.com", "CNAME", "a.example.com"),
                rec("*.example.com", "CNAME", "b.example.com"),
            ]))
        )


def test_rejects_record_outside_zone() -> None:
    with pytest.raises(ValidationError, match="not owned by zone"):
        WildcardCheckRequest.model_validate(
            payload(zone([rec("*.other.com", "A", "10.0.0.1")]))
        )


def test_rejects_nested_peer_zone() -> None:
    with pytest.raises(ValidationError, match="non-nested"):
        WildcardCheckRequest.model_validate(
            payload(zone([]), peers=[{"name": "sub.example.com", "records": []}])
        )


def test_accepts_deep_wildcard() -> None:
    request = WildcardCheckRequest.model_validate(
        payload(zone([rec("*.a.b.example.com", "A", "10.0.0.1")]))
    )
    assert request.zone.records[0].name == "*.a.b.example.com"


def test_accepts_trailing_dot_and_mixed_case_wildcard() -> None:
    request = WildcardCheckRequest.model_validate(
        payload(zone([rec("*.Example.COM.", "A", "10.0.0.1")]))
    )
    assert request.zone.records[0].name == "*.example.com"


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #


def test_wildcard_check_endpoint_equivalent() -> None:
    body = payload(zone([rec("*.example.com", "A", "10.0.0.1")]))
    response = client.post("/wildcard-check", json=body)
    assert response.status_code == 200
    out = response.json()
    assert out["status"] == "equivalent"
    assert out["zone"] == "example.com"
    assert "counterexample" not in out  # excluded when None


def test_wildcard_check_endpoint_difference() -> None:
    body = payload(zone([rec("*.example.com", "A", "10.0.0.1")], []))
    response = client.post("/wildcard-check", json=body)
    assert response.status_code == 200
    out = response.json()
    assert out["status"] == "different"
    ce = out["counterexample"]
    assert ce["name_kind"] == "synthetic_probe"
    assert "命中通配 *.example.com" in ce["before"]["chain"]
    assert ce["before"]["trace"][0]["wildcard"] == "*.example.com"


def test_wildcard_check_endpoint_validation_error_is_422() -> None:
    body = payload(zone([rec("*.*.example.com", "A", "10.0.0.1")]))
    assert client.post("/wildcard-check", json=body).status_code == 422


def test_plan_still_rejects_wildcards() -> None:
    body = {
        "zones": [{
            "name": "example.com",
            "records": [rec("*.example.com", "A", "10.0.0.1")],
            "new_records": [rec("*.example.com", "A", "10.0.0.1")],
        }],
        "required_domains": ["www.example.com"],
    }
    assert client.post("/plan", json=body).status_code == 422


def test_openapi_documents_wildcard_endpoint() -> None:
    spec = client.get("/openapi.json").json()
    assert "/wildcard-check" in spec["paths"]
    assert "/plan" in spec["paths"]
