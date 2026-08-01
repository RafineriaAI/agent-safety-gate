"""An ROI model that refuses to flatter: your inputs, both sides of the ledger.

    python tools/roi_model.py \
        --incidents-per-year 4 --hours-per-reconstruction 6 \
        --audit-requests-per-year 2 --hours-saved-per-audit 8 \
        --hourly-cost 90 \
        --setup-hours 2 --policy-hours-per-month 1 \
        --approvals-per-week 5 --minutes-per-approval 2

    python tools/roi_model.py --example   # fictional inputs, loudly labelled

This prints arithmetic on numbers **you** supply. It has no defaults, because a
default here would be a marketing number wearing a seatbelt. The one honest
service it performs beyond multiplication is refusing to hide the cost side:
setup, policy maintenance and the approvals the gate itself adds are subtracted
before anything is called a saving.

What it cannot tell you, no matter what you type in: whether an incident the
gate would have blocked was going to happen, and what it would have cost. That
number dominates every real ROI story about safety tooling, and it is exactly
the number nobody has. This model leaves it out rather than inventing it, so
treat the output as the *recoverable-time floor*, not the value of the tool.
"""

from __future__ import annotations

import argparse
import sys

EXAMPLE = {
    "incidents_per_year": 4.0,
    "hours_per_reconstruction": 6.0,
    "audit_requests_per_year": 2.0,
    "hours_saved_per_audit": 8.0,
    "hourly_cost": 90.0,
    "setup_hours": 2.0,
    "policy_hours_per_month": 1.0,
    "approvals_per_week": 5.0,
    "minutes_per_approval": 2.0,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--example",
        action="store_true",
        help="run with fictional example inputs, clearly labelled as such",
    )
    for name, helptext in [
        ("incidents-per-year", "'why did the agent do X' investigations per year"),
        ("hours-per-reconstruction", "hours one takes today, from scattered logs"),
        ("audit-requests-per-year", "audits/customer reviews asking for evidence"),
        (
            "hours-saved-per-audit",
            "hours a records file saves per audit, your estimate",
        ),
        ("hourly-cost", "loaded cost of the person doing the above"),
        ("setup-hours", "one-off: wiring the gate and writing the first policy"),
        ("policy-hours-per-month", "keeping the policy current"),
        ("approvals-per-week", "blocked calls a human will approve per week"),
        ("minutes-per-approval", "minutes one approval costs that human"),
    ]:
        parser.add_argument(f"--{name}", type=float, default=None, help=helptext)
    args = parser.parse_args(argv)

    values = {
        key.replace("-", "_"): getattr(args, key.replace("-", "_")) for key in EXAMPLE
    }
    missing = [key for key, value in values.items() if value is None]
    if args.example:
        values = dict(EXAMPLE)
        print("EXAMPLE INPUTS - fictional, for illustrating the arithmetic only.")
        print("Replace every one of them with your own numbers.\n")
    elif missing:
        print(
            "This model has no defaults on purpose: a default would be a claim.\n"
            "Missing: "
            + ", ".join("--" + key.replace("_", "-") for key in missing)
            + "\nOr run with --example to see the arithmetic on fictional inputs.",
            file=sys.stderr,
        )
        return 2

    v = values
    recon_hours = v["incidents_per_year"] * v["hours_per_reconstruction"]
    audit_hours = v["audit_requests_per_year"] * v["hours_saved_per_audit"]
    benefit_hours = recon_hours + audit_hours

    approval_hours = v["approvals_per_week"] * 52 * v["minutes_per_approval"] / 60
    maintenance_hours = v["policy_hours_per_month"] * 12
    cost_hours_year1 = approval_hours + maintenance_hours + v["setup_hours"]
    cost_hours_ongoing = approval_hours + maintenance_hours

    def money(hours: float) -> float:
        return hours * float(v["hourly_cost"])

    print("Assumptions (yours, echoed back):")
    for key in EXAMPLE:
        print(f"  {key.replace('_', ' '):26} {v[key]:g}")
    print()
    print("Recoverable time, per year:")
    print(
        f"  incident reconstruction   {recon_hours:7.1f} h  ({money(recon_hours):,.0f})"
    )
    print(
        f"  audit evidence            {audit_hours:7.1f} h  ({money(audit_hours):,.0f})"
    )
    print()
    print("Costs the gate adds:")
    print(f"  approvals                 {approval_hours:7.1f} h/year")
    print(f"  policy maintenance        {maintenance_hours:7.1f} h/year")
    print(f"  setup (one-off)           {v['setup_hours']:7.1f} h")
    print(
        "  latency                   negligible; measure it:"
        " python benchmarks/proxy_overhead.py"
    )
    print()
    net1 = benefit_hours - cost_hours_year1
    net = benefit_hours - cost_hours_ongoing
    print(f"Net, first year:            {net1:7.1f} h  ({money(net1):,.0f})")
    print(f"Net, ongoing years:         {net:7.1f} h  ({money(net):,.0f})")
    if net <= 0:
        print()
        print("Negative or zero: with your inputs the gate costs more time than it")
        print("recovers. That is a real answer. It usually means the tool surface")
        print("is one raw shell (see benchmarks/README.md) or the policy blocks")
        print("things nobody needed blocked - run `calibrate` before concluding.")
    print()
    print("Not modelled, on purpose: the cost of the incident that does not")
    print("happen. It dominates every honest ROI story and nobody has the number.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
