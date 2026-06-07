# siem_source.py  (Graylog variant)
import os, re, requests

GRAYLOG = os.environ.get("GRAYLOG_URL", "http://127.0.0.1:9000")
GTOKEN  = os.environ["GRAYLOG_TOKEN"]  # create under System > Users > API tokens

# --- redaction -------------------------------------------------------------
# Raw log lines can carry passwords, tokens, session IDs, and private keys.
# Redact them here so secrets never leave the host in an API call.
_PEM  = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_AUTH = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._\-+/=]+")
_KV   = re.compile(
    r'(?i)(["\']?)\b('
    r'passwd|password|passphrase|pwd|pass|secret|client[_-]?secret|'
    r'token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|'
    r'authorization|auth|session[_-]?id|sessionid|session|sid|cookie|'
    r'private[_-]?key)\b\1(\s*[:=]\s*)(["\']?)([^\s,;"\'}\)\]]+)\4'
)
_AWS  = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_LONG = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")   # high-entropy tokens / session IDs

def _kv_repl(m):
    q, key, sep, vq = m.group(1), m.group(2), m.group(3), m.group(4)
    return f"{q}{key}{q}{sep}{vq}[REDACTED]{vq}"

def scrub(value):
    """Redact common secrets from a value before it is sent to the API.
    Non-string values are returned unchanged."""
    if not isinstance(value, str):
        return value
    text = _PEM.sub("[REDACTED PRIVATE KEY]", value)
    text = _AUTH.sub(r"\1 [REDACTED]", text)
    text = _KV.sub(_kv_repl, text)
    text = _AWS.sub("[REDACTED AWS KEY]", text)
    text = _LONG.sub("[REDACTED]", text)
    return text

def fetch_alerts(limit=20):
    params = {"query": "*", "range": 3600, "limit": limit, "sort": "timestamp:desc"}
    r = requests.get(f"{GRAYLOG}/api/search/universal/relative",
                     params=params, auth=(GTOKEN, "token"),
                     headers={"Accept": "application/json"}, timeout=20)
    r.raise_for_status()
    out = []
    for m in r.json().get("messages", []):
        msg = m["message"]
        record = {
            "id": msg.get("_id"),
            "source": msg.get("source"),
            "message": msg.get("message"),
            "timestamp": msg.get("timestamp"),
        }
        # Scrub every field before it leaves this function.
        out.append({k: scrub(v) for k, v in record.items()})
    return out