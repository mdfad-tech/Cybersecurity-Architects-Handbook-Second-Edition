# gvm_source.py
import os
import sys
from gvm.connections import (
    UnixSocketConnection,
    TLSConnection,
    SSHConnection,
)
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform


# Connection selection via GVM_CONN:
#    unix (default) - local gvmd socket, OR a remote socket forwarded here
#                     over SSH (set GVMD_SOCKET to the forwarded path).
#    tls            - network TLS to gvmd on GVM_HOST:GVM_PORT (9390). gvmd
#                     must be configured to expose a TLS listener.
#    ssh            - python-gvm SSH transport to a gvmd host.
SOCK  = os.environ.get("GVMD_SOCKET", "/run/gvmd/gvmd.sock")
GUSER = os.environ.get("GVM_USER", "admin")
GPASS = os.environ["GVM_PASS"]

# Pull ALL high/medium/low findings (rows=-1); the default get_report filter
# returns only a handful. QoD is filtered on our side afterward.
_REPORT_FILTER = "apply_overrides=1 levels=hml rows=-1 first=1 min_qod=0"


def _connection():
    mode = os.environ.get("GVM_CONN", "unix").lower()
    if mode == "tls":
        return TLSConnection(
            hostname=os.environ["GVM_HOST"],
            port=int(os.environ.get("GVM_PORT", "9390")),
        )
    if mode == "ssh":
        return SSHConnection(
            hostname=os.environ["GVM_HOST"],
            port=int(os.environ.get("GVM_SSH_PORT", "22")),
            username=os.environ["GVM_SSH_USER"],
            password=os.environ.get("GVM_SSH_PASS"),
        )
    # default: local Unix socket (or an SSH-forwarded one)
    return UnixSocketConnection(path=SOCK)


def _reports_newest_first(gmp):
    lst = gmp.get_reports(
        filter_string="sort-reverse=date rows=50",
        ignore_pagination=True,
    )
    return lst.findall("report")


def _report_meta(r):
    status = (r.findtext(".//scan_run_status") or "").strip()
    task = (r.findtext(".//task/name") or "").strip()
    cnt = (r.findtext(".//result_count/filtered")
           or r.findtext(".//result_count/full") or "0")
    n = int(cnt) if cnt.isdigit() else 0
    return r.get("id"), task, status, n


def _pick_report(reports, want_task=None):
    """First FINISHED report with results (newest-first), optionally for a task.

    'Newest by date' alone is not safe: an empty or in-progress scan can be the
    most recent and would silently yield zero findings.
    """
    want = (want_task or "").strip().lower()
    for r in reports:
        rid, task, status, n = _report_meta(r)
        if status != "Done" or n <= 0:
            continue
        if want and want not in task.lower():
            continue
        return rid, task, status, n
    return None, None, None, 0


def _latest_per_task(reports):
    """One report per task: each task's newest FINISHED report that has results.

    Reports arrive newest-first, so the first time we see a task it is that
    task's most recent qualifying report.
    """
    chosen, order = {}, []
    for r in reports:
        rid, task, status, n = _report_meta(r)
        if status != "Done" or n <= 0 or not task:
            continue
        if task not in chosen:
            chosen[task] = (rid, task, status, n)
            order.append(task)
    return [chosen[t] for t in order]


def _collect(gmp, report_id, task_name, min_qod, seen, findings):
    """Append QoD-passing findings from one report; de-dupe on (host, name, port)."""
    full = gmp.get_report(report_id, details=True, filter_string=_REPORT_FILTER)
    kept = 0
    for res in full.iter("result"):
        qod = res.findtext("qod/value") or "0"
        if not qod.isdigit() or int(qod) < min_qod:
            continue  # skip low quality-of-detection noise
        host = res.findtext("host") or "unknown"
        name = (res.findtext("name") or "").strip()
        port = res.findtext("port") or ""
        key = (host, name, port)
        if key in seen:
            continue  # same finding seen in another task's report
        seen.add(key)
        findings.append({
            "host": host,
            "name": name,
            "severity": res.findtext("severity") or "0.0",
            "port": port,
            "task": task_name,
            # truncate the long description to control token use
            "summary": (res.findtext("description") or "")[:600],
        })
        kept += 1
    return kept


def latest_report_findings(min_qod=None):
    if min_qod is None:
        min_qod = int(os.environ.get("GVM_MIN_QOD", "70"))
    all_tasks = os.environ.get("GVM_ALL_TASKS", "").strip().lower() in (
        "1", "true", "yes", "on")
    want_task = os.environ.get("GVM_TASK")  # single-task scope (ignored if all-tasks)

    conn = _connection()
    transform = EtreeCheckCommandTransform()
    findings, seen = [], set()
    with Gmp(connection=conn, transform=transform) as gmp:
        gmp.authenticate(GUSER, GPASS)
        reports = _reports_newest_first(gmp)

        if all_tasks:
            chosen = _latest_per_task(reports)
            if not chosen:
                raise SystemExit(
                    "No finished reports with results. Run 'python gvm_probe.py'.")
            print(f"Aggregating latest finished report from {len(chosen)} task(s):",
                  file=sys.stderr)
            for rid, task, status, n in chosen:
                kept = _collect(gmp, rid, task, min_qod, seen, findings)
                print(f"  - {task:<24} {rid}  {n} results -> {kept} kept "
                      f"(QoD>={min_qod})", file=sys.stderr)
            print(f"Total: {len(findings)} unique findings across {len(chosen)} task(s)",
                  file=sys.stderr)
        else:
            rid, task, status, n = _pick_report(reports, want_task)
            if not rid:
                where = f" for task matching {want_task!r}" if want_task else ""
                raise SystemExit(
                    f"No finished report with results{where}. "
                    f"Run 'python gvm_probe.py' to see available reports.")
            print(f"Using report {rid} from task '{task}' ({status}, {n} results)",
                  file=sys.stderr)
            _collect(gmp, rid, task, min_qod, seen, findings)

    return findings
