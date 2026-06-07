# render_plan.py
import json
 
plans = json.load(open("vuln_plan.json"))
out = ["# Vulnerability Remediation Plan", ""]
for p in plans:
    host = p.get("host", "unknown")
    risk = (p.get("overall_risk") or "unknown").upper()
    out.append(f"## {host} — overall risk: {risk}")
    if p.get("quick_wins"):
        out.append("**Quick wins:** " + "; ".join(p["quick_wins"]))
    out.append("")
    for i, step in enumerate(p.get("fix_order", []), 1):
        finding = step.get("finding", "(unnamed finding)")
        effort = step.get("effort", "unknown")
        out.append(f"{i}. **{finding}** ({effort} effort)")
        out.append(f"   - Why here: {step.get('why_it_matters_here', '')}")
        out.append(f"   - Action: {step.get('action', '')}")
    out.append("")
open("vuln_plan.md", "w").write("\n".join(out))
