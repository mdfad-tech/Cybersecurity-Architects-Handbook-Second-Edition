# vuln_agent.py
import os, json, sys, collections
import anthropic
from vuln_prompt import VULN_SYSTEM
from gvm_source import latest_report_findings
from siem_source import scrub          # reuse the Lab 1 redaction pass

MODEL = "claude-sonnet-4-6"            # denser reasoning than Lab 1
PING_MODEL = "claude-haiku-4-5-20251001"   # cheap model for the credential preflight
client = anthropic.Anthropic()


def preflight():
    """Validate the Anthropic credential ONCE, before fanning out per-host calls.

    Without this, a missing or invalid key only surfaces inside the per-host
    loop, where the broad `except` turns a single global misconfiguration into
    an identical 'skip <host>' line for every host -- sending you hunting
    per-host for what is really one env-var problem. Fail fast, fail legibly.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit(
            "ANTHROPIC_API_KEY is not set in this shell.\n"
            "  Load it with:  source ~/.cah2-secrets\n"
            "  (or:           export ANTHROPIC_API_KEY=\"sk-ant-...\")"
        )
    try:
        client.messages.create(
            model=PING_MODEL,
            max_tokens=8,
            messages=[{"role": "user", "content": "ping"}],
        )
    except anthropic.AuthenticationError:
        sys.exit("ANTHROPIC_API_KEY is set but was rejected (401). Check the key value.")
    except anthropic.APIConnectionError as e:
        sys.exit(f"Cannot reach the Anthropic API (network / outbound 443?): {e}")


def plan_for_host(host, findings):
    # Scan descriptions can echo detected credentials; redact before sending.
    findings = [{k: scrub(v) for k, v in f.items()} for f in findings]
    resp = client.messages.create(
        model=MODEL,
        max_tokens=1500,
        system=VULN_SYSTEM,
        messages=[{"role": "user",
                   "content": f"Host: {host}\nFindings:\n" +
                              json.dumps(findings, indent=2)}],
    )
    raw = resp.content[0].text.strip()
    start, end = raw.find("{"), raw.rfind("}")
    return json.loads(raw[start:end + 1])


def main():
    preflight()                        # one clear failure instead of one-per-host

    findings = latest_report_findings()
    by_host = collections.defaultdict(list)
    for f in findings:
        by_host[f["host"]].append(f)

    total = len(by_host)
    print(f"{len(findings)} findings across {total} hosts", file=sys.stderr)

    plans = []
    for i, (host, fs) in enumerate(by_host.items(), 1):
        print(f"  [{i}/{total}] planning {host} ({len(fs)} findings) ...",
              file=sys.stderr)
        try:
            plans.append(plan_for_host(host, fs))
        except Exception as e:
            print(f"        skip {host}: {e}", file=sys.stderr)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    plans.sort(key=lambda p: order.get(p.get("overall_risk", "low"), 9))
    json.dump(plans, open("vuln_plan.json", "w"), indent=2)
    print(f"Wrote vuln_plan.json with {len(plans)} host plans")


if __name__ == "__main__":
    main()
