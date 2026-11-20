"""Run the bundled scenarios through the services without a server.

Usage (from the repository root)::

    python examples/demo.py

It prints a short, human-readable summary of each response.  Start the service
with ``docker compose up --build`` and use ``examples/*.json`` with curl for the
HTTP examples in README.md.  Files whose payload has a top-level ``zone`` key
are wildcard-check requests; the rest are /plan requests.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.models import PlanRequest, WildcardCheckRequest  # noqa: E402
from app.service import build_plan  # noqa: E402
from app.wildcheck import build_wildcard_check  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent


def summarise(name: str, out: dict) -> None:
    print(f"=== {name} -> {out['status']}")
    print(out["message"])
    if out["order"]:
        for step in out["steps"]:
            print(
                f"  {step['step']}. {step['zone']}: "
                f"{step['addresses_before']} -> {step['addresses_after']}"
            )
    if out["fault_chains"]:
        for chain in out["fault_chains"]:
            print(f"  故障[{chain['category_label']}] {chain['chain']}")
    if out["blocked_zones"]:
        print(f"  安全前缀: {out['safe_prefix'] or '（无）'}")
        for blocked in out["blocked_zones"]:
            labels = "/".join(c["label"] for c in blocked["categories"])
            print(f"  若无安全顺序时先发布 {blocked['zone']} -> {labels}")
            for failure in blocked["failures"]:
                print(f"      {failure['chain']}")
    print()


def summarise_check(name: str, out: dict) -> None:
    print(f"=== {name} -> {out['status']}")
    print(out["message"])
    counterexample = out.get("counterexample")
    if counterexample:
        print(
            f"  反例: {counterexample['name']}"
            f"（{counterexample['change_label']}）"
        )
        print(f"    变更前: {counterexample['before']['chain']}")
        print(f"    变更后: {counterexample['after']['chain']}")
    print()


def main() -> None:
    for path in sorted(HERE.glob("0*.json")):
        payload = json.loads(path.read_text())
        if "zone" in payload:
            request = WildcardCheckRequest.model_validate(payload)
            summarise_check(path.name, build_wildcard_check(request))
        else:
            request = PlanRequest.model_validate(payload)
            summarise(path.name, build_plan(request))


if __name__ == "__main__":
    main()
