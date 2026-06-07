# gvm_source.py
import os
from gvm.connections import (
    UnixSocketConnection,
    TLSConnection,
    SSHConnection,
)
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

# Connection selection via GVM_CONN:
#   unix (default) - local gvmd socket, OR a remote socket forwarded here
#                    over SSH (set GVMD_SOCKET to the forwarded path).
#   tls            - network TLS to gvmd on GVM_HOST:GVM_PORT (9390). gvmd
#                    must be configured to expose a TLS listener.
#   ssh            - python-gvm SSH transport to a gvmd host.
SOCK  = os.environ.get("GVMD_SOCKET", "/run/gvmd/gvmd.sock")
GUSER = os.environ.get("GVM_USER", "admin")
GPASS = os.environ["GVM_PASS"]

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

def latest_report_findings(min_qod=70):
    conn = _connection()
    transform = EtreeCheckCommandTransform()
    findings = []
    with Gmp(connection=conn, transform=transform) as gmp:
        gmp.authenticate(GUSER, GPASS)
        # newest report first
        reports = gmp.get_reports(filter_string="sort-reverse=date rows=1")
        report_id = reports.find("report").get("id")
        full = gmp.get_report(report_id, details=True)
        for res in full.iter("result"):
            qod = res.findtext("qod/value") or "0"
            if int(qod) < min_qod:
                continue   # skip low quality-of-detection noise
            findings.append({
                "host": res.findtext("host") or "unknown",
                "name": (res.findtext("name") or "").strip(),
                "severity": res.findtext("severity") or "0.0",
                "port": res.findtext("port") or "",
                # truncate the long description to control token use
                "summary": (res.findtext("description") or "")[:600],
            })
    return findings
