# triage_agent.py
import json, sys
import anthropic
from triage_prompt import SYSTEM_PROMPT
from siem_source import fetch_alerts, scrub
 
MODEL = "claude-haiku-4-5-20251001"   # fast + cheap for high-volume triage
RANK  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
 
client = anthropic.Anthropic()
 
def triage_one(alert):
    clean = {k: scrub(v) for k, v in alert.items()}
    resp = client.messages.create(
        model=MODEL,
        max_tokens=400,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user",
                   "content": "Triage this alert:\n" + json.dumps(clean, indent=2)}],
    )
    raw = resp.content[0].text.strip()
    try:
        verdict = json.loads(raw)
    except json.JSONDecodeError:
        # model wrapped JSON in fences or prose; recover the object
        start, end = raw.find("{"), raw.rfind("}")
        verdict = json.loads(raw[start:end + 1])
    verdict["_alert"] = clean
    return verdict
 
def main(limit=15):
    alerts = fetch_alerts(limit)
    print(f"Fetched {len(alerts)} alerts; triaging...", file=sys.stderr)
    results = []
    for a in alerts:
        try:
            results.append(triage_one(a))
        except Exception as e:
            print(f"  skip one alert: {e}", file=sys.stderr)
    results.sort(key=lambda v: RANK.get(v.get("severity", "info"), 9))
    return results
 
if __name__ == "__main__":
    lim = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    out = main(lim)
    with open("triage_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"Wrote triage_results.json with {len(out)} verdicts")

