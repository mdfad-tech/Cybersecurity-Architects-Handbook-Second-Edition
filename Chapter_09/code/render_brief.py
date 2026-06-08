# render_brief.py
import json, datetime
 
with open("triage_results.json") as f:
    results = json.load(f)
 
lines = [f"# SIEM Triage Brief — {datetime.date.today()}", ""]
counts = {}
for r in results:
    counts[r["severity"]] = counts.get(r["severity"], 0) + 1
lines.append("**Summary:** " + ", ".join(f"{v} {k}" for k, v in counts.items()))
lines.append("")
for r in results:
    lines.append(f"## [{r[\"severity\"].upper()}] {r[\"summary\"]}")
    lines.append(f"- **Confidence:** {r[\"confidence\"]}  |  **FP likelihood:** {r[\"false_positive_likelihood\"]}")
    lines.append(f"- **Likely cause:** {r[\"likely_cause\"]}")
    lines.append(f"- **Recommended action:** {r[\"recommended_action\"]}")
    lines.append("")
open("triage_brief.md", "w").write("\n".join(lines))
print("Wrote triage_brief.md")

