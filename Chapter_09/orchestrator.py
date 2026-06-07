# orchestrator.py
import json, collections, datetime
import anthropic
import triage_agent, vuln_agent
 
MODEL = "claude-sonnet-4-6"   # or claude-opus-4-8 for the richest synthesis
client = anthropic.Anthropic()
 
BRIEF_SYSTEM = """You are the lead analyst writing the morning security brief
for a small environment. You receive (1) triaged SIEM alerts and (2) a
vulnerability remediation plan, already joined by host. Write a concise brief:
lead with anything where an active alert coincides with a known vulnerability
on the same host — those are the day's priorities. Then note other notable
items. Be direct and skimmable. Plain prose, short paragraphs, no fluff."""
 
def correlate():
    alerts = triage_agent.main(20)
    vuln_agent.main()
    plans = json.load(open("vuln_plan.json"))
    by_host = collections.defaultdict(lambda: {"alerts": [], "vuln": None})
    for a in alerts:
        # Join key: the Wazuh source supplies "host" (agent name); Graylog
        # supplies "source". For this to line up with the scanner's host,
        # both sides must use the same identifier (hostname OR IP);
        # normalize here (e.g. resolve names to IPs) if they differ.
        host = a["_alert"].get("host") or a["_alert"].get("source") or "unknown"
        by_host[host]["alerts"].append(
            {"severity": a["severity"], "summary": a["summary"]})
    for p in plans:
        by_host[p["host"]]["vuln"] = {
            "overall_risk": p["overall_risk"],
            "quick_wins": p.get("quick_wins", [])}
    return dict(by_host)
 
def write_brief(correlated):
    resp = client.messages.create(
        model=MODEL, max_tokens=2000, system=BRIEF_SYSTEM,
        messages=[{"role": "user",
                   "content": "Joined signals by host:\n" + json.dumps(correlated, indent=2)}],
    )
    text = resp.content[0].text
    fname = f"daily_brief_{datetime.date.today()}.md"
    open(fname, "w").write(text)
    print(f"Wrote {fname}")
    return fname
 
if __name__ == "__main__":
    write_brief(correlate())

