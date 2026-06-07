# vuln_agent.py
import json, sys, collections
import anthropic
from vuln_prompt import VULN_SYSTEM
from gvm_source import latest_report_findings
from siem_source import scrub      # reuse the Lab 1 redaction pass
 
MODEL = "claude-sonnet-4-6"   # denser reasoning than Lab 1
client = anthropic.Anthropic()
 
def plan_for_host(host, findings):
    # Scan descriptions can echo detected credentials; redact before sending.
    findings = [{k: scrub(v) for k, v in f.items()} for f in findings]
    resp = client.messages.create(
        model=MODEL,
        max_tokens=1500,
        system=VULN_SYSTEM,
        messages=[{"role": "user",
                   "content": f"Host: {host}\nFindings:\n" + json.dumps(findings, indent=2)}],
    )
    raw = resp.content[0].text.strip()
    start, end = raw.find("{"), raw.rfind("}")
    return json.loads(raw[start:end + 1])
 
def main():
    findings = latest_report_findings()
    by_host = collections.defaultdict(list)
    for f in findings:
        by_host[f["host"]].append(f)
    print(f"{len(findings)} findings across {len(by_host)} hosts", file=sys.stderr)
    plans = []
    for host, fs in by_host.items():
        try:
            plans.append(plan_for_host(host, fs))
        except Exception as e:
            print(f"  skip {host}: {e}", file=sys.stderr)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    plans.sort(key=lambda p: order.get(p.get("overall_risk", "low"), 9))
    json.dump(plans, open("vuln_plan.json", "w"), indent=2)
    print(f"Wrote vuln_plan.json with {len(plans)} host plans")
 
if __name__ == "__main__":
    main()

