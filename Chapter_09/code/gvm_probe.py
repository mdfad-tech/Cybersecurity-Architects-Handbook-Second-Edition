#!/usr/bin/env python3
# gvm_probe.py — diagnose why vuln_agent.py reports "0 findings across 0 hosts".
#
# Run with the lab venv active and the same env gvm_connect.sh set up:
#   source .venv/bin/activate
#   python gvm_probe.py
#
# It distinguishes the three causes of an empty pull:
#   (a) wrong report selected   — newest-by-date is empty/in-progress/discovery
#   (b) QoD filter too strict    — findings exist but all below QoD 70
#   (c) default get_report filter — results exist but the server filter hides them
import os, sys, collections
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

SOCK = os.environ.get("GVMD_SOCKET", "/tmp/gvmd.sock")
USER = os.environ.get("GVM_USER", "admin")
try:
    PASS = os.environ["GVM_PASS"]
except KeyError:
    sys.exit("GVM_PASS is not set in this shell.")

# everything in a report, regardless of QoD/severity/pagination:
PERMISSIVE = "apply_overrides=0 levels=hmlg min_qod=0 rows=-1 first=1"


def t(el, path, default="?"):
    v = el.findtext(path) if el is not None else None
    return v if v is not None else default


def histogram(results):
    qod, sev, ge70 = collections.Counter(), collections.Counter(), 0
    for r in results:
        q = r.findtext("qod/value") or "0"
        qi = int(q) if q.isdigit() else 0
        qod[f"{(qi // 10) * 10:>3}s"] += 1
        if qi >= 70:
            ge70 += 1
        s = r.findtext("severity") or "0.0"
        sev[s] += 1
    return ge70, dict(sorted(qod.items())), sev


with Gmp(connection=UnixSocketConnection(path=SOCK),
         transform=EtreeCheckCommandTransform()) as gmp:
    gmp.authenticate(USER, PASS)

    lst = gmp.get_reports(filter_string="sort-reverse=date rows=20",
                          ignore_pagination=True)
    reports = lst.findall("report")
    if not reports:
        sys.exit("No reports exist at all — run and FINISH a scan task first.")

    print(f"=== {len(reports)} most-recent reports ===")
    print(f"{'#':>2}  {'report id':36}  {'status':14}  {'results':>7}  task")
    rows = []
    for i, r in enumerate(reports):
        rid = r.get("id")
        status = t(r, ".//scan_run_status", "?")
        task = t(r, ".//task/name", "?")
        filt = t(r, ".//result_count/filtered", t(r, ".//result_count/full", "0"))
        rows.append((rid, status, task, filt))
        print(f"{i:>2}  {rid:36}  {status:14}  {filt:>7}  {task}")

    agent_pick = reports[0].get("id")                      # what the agent grabs
    best = max(rows, key=lambda x: int(x[3]) if x[3].isdigit() else -1)
    print(f"\nAgent grabs newest-by-date : {agent_pick}")
    print(f"Report with most results   : {best[0]}  ({best[3]} results, task '{best[2]}')")

    def deep(rid, label):
        seen = gmp.get_report(rid, details=True)                       # default filter (agent's view)
        seen_r = list(seen.iter("result"))
        allr = gmp.get_report(rid, details=True, filter_string=PERMISSIVE)  # everything
        all_r = list(allr.iter("result"))
        ge70, qod, sev = histogram(all_r)
        top = sorted(sev.items(), key=lambda kv: float(kv[0] or 0), reverse=True)[:5]
        print(f"\n--- {label}\n    {rid}")
        print(f"    results the agent currently sees (default filter): {len(seen_r)}")
        print(f"    results actually in the report (no filter)       : {len(all_r)}")
        print(f"    of those, QoD >= 70                              : {ge70}")
        print(f"    QoD distribution                                 : {qod}")
        print(f"    top severities (severity: count)                 : {top}")

    deep(agent_pick, "AGENT'S REPORT (newest by date)")
    if best[0] != agent_pick and (best[3].isdigit() and int(best[3]) > 0):
        deep(best[0], "REPORT WITH THE MOST FINDINGS")

print("""
How to read this:
  * If the agent's report shows 0 everywhere but another report has results
    -> wrong report selected. Fix report selection in gvm_source.py.
  * If 'actually in the report' > 0 but 'QoD >= 70' is 0
    -> the QoD>=70 filter is dropping everything. Lower min_qod.
  * If 'actually in the report' > 0 but 'agent currently sees' is 0
    -> the default get_report filter is hiding results. Pass a filter_string.
""")
