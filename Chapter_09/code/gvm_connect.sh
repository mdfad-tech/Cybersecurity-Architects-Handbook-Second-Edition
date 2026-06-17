#!/usr/bin/env bash
#
# gvm_connect.sh — establish and verify GMP connectivity to a Docker-based
#                  Greenbone Community stack, for the Category 9 Vulnerability
#                  Report Agent (~/cah2-ai-agents). Runs on the AGENT box.
#
# Safe to `source`: it saves your shell options on entry and restores them on
# exit, and does NOT use a global `set -e`, so a command that fails AFTER you
# source it (e.g. a later script error) can never take down your shell/SSH
# session. Run it either way:
#   source ./gvm_connect.sh   # exports GVMD_SOCKET into THIS shell (then run the agent)
#   ./gvm_connect.sh          # runs in its own process, prints the export line
#   ./gvm_connect.sh --status # is the tunnel up and GMP reachable?
#   ./gvm_connect.sh --down   # tear the forward down
#   ./gvm_connect.sh --install-service   # keep the forward alive via systemd --user
#
# Required env: GVM_HOST, GVM_SSH_USER, GVM_PASS

# ---- sourcing-safety: detect source vs execute, preserve caller's options ----
_SOURCED=0
_GVM_RESTORE=""
if (return 0 2>/dev/null); then
    _SOURCED=1
    _GVM_RESTORE="$(set +o)"        # snapshot caller's shell options to restore later
fi
set -uo pipefail                     # NOTE: no -e — must not be able to kill a sourcing shell

# ---- configuration (env-overridable, matching the lab's variable names) -----
GVM_HOST="${GVM_HOST:-}"
GVM_SSH_USER="${GVM_SSH_USER:-}"
GVM_SSH_PORT="${GVM_SSH_PORT:-22}"
GVM_USER="${GVM_USER:-admin}"
GVMD_SOCKET="${GVMD_SOCKET:-/tmp/gvmd.sock}"                       # LOCAL forwarded path
GVM_DOCKER_SOCKET="${GVM_DOCKER_SOCKET:-/tmp/gvm/gvmd/gvmd.sock}"  # REMOTE host path
WAIT_SECS="${WAIT_SECS:-15}"

_pick_python() {
    if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
        echo "$VIRTUAL_ENV/bin/python"; return
    fi
    if [[ -x "$HOME/cah2-ai-agents/.venv/bin/python" ]]; then
        echo "$HOME/cah2-ai-agents/.venv/bin/python"; return
    fi
    command -v python3
}
PY="$(_pick_python)"

_fwd_spec() { printf '%s:%s' "$GVMD_SOCKET" "$GVM_DOCKER_SOCKET"; }
_tunnel_pid() { pgrep -f -- "-L $(_fwd_spec)" || true; }

# ---- GMP smoke test: prove SSH -> gvmd socket -> auth all the way through -----
_verify_gmp() {
    GVMD_SOCKET="$GVMD_SOCKET" GVM_USER="$GVM_USER" GVM_PASS="${GVM_PASS:-}" \
    "$PY" - <<'PY'
import os, sys
try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform
except ImportError:
    sys.stderr.write("python-gvm is not installed in this interpreter.\n"
                     "  activate the lab venv:  source ~/cah2-ai-agents/.venv/bin/activate\n")
    sys.exit(3)

sock = os.environ["GVMD_SOCKET"]
user = os.environ.get("GVM_USER", "admin")
pw   = os.environ.get("GVM_PASS", "")
if not pw:
    sys.stderr.write("GVM_PASS is not set — cannot authenticate.\n")
    sys.exit(4)
try:
    with Gmp(connection=UnixSocketConnection(path=sock),
             transform=EtreeCheckCommandTransform()) as gmp:
        ver = gmp.get_version().findtext("version") or "?"
        gmp.authenticate(user, pw)
        print(ver)
except Exception as e:
    sys.stderr.write(f"GMP verification failed: {e}\n")
    sys.exit(5)
PY
}

# ---- subcommands -------------------------------------------------------------
_status() {
    local pid; pid="$(_tunnel_pid)"
    if [[ -z "$pid" ]]; then echo "tunnel: DOWN (no ssh -L $(_fwd_spec))"; return 1; fi
    if [[ ! -S "$GVMD_SOCKET" ]]; then echo "tunnel: pid $pid but $GVMD_SOCKET is not a socket"; return 1; fi
    local ver
    if ver="$(_verify_gmp)"; then
        echo "tunnel: UP (pid $pid)  GMP reachable, protocol $ver, auth OK"; return 0
    else
        echo "tunnel: pid $pid up, but GMP verification failed (see above)"; return 1
    fi
}

_down() {
    local pid; pid="$(_tunnel_pid)"
    if [[ -n "$pid" ]]; then kill $pid && echo "stopped ssh forward (pid $pid)"; fi
    rm -f -- "$GVMD_SOCKET"
    return 0
}

_require_env() {
    local missing=()
    [[ -z "$GVM_HOST" ]]     && missing+=(GVM_HOST)
    [[ -z "$GVM_SSH_USER" ]] && missing+=(GVM_SSH_USER)
    [[ -z "${GVM_PASS:-}" ]] && missing+=(GVM_PASS)
    if (( ${#missing[@]} )); then
        echo "Missing required env: ${missing[*]}" >&2
        echo "  export GVM_HOST=...  GVM_SSH_USER=...  GVM_PASS=..." >&2
        return 1
    fi
    return 0
}

_establish() {
    _require_env || return 1

    if [[ -n "$(_tunnel_pid)" ]] && _verify_gmp >/dev/null 2>&1; then
        echo "Connectivity already up — reusing existing forward." >&2
    else
        _down >/dev/null 2>&1 || true
        echo "Forwarding $GVM_SSH_USER@$GVM_HOST:$GVM_DOCKER_SOCKET -> $GVMD_SOCKET ..." >&2
        if ! ssh -fNT \
                -o ExitOnForwardFailure=yes \
                -o StreamLocalBindUnlink=yes \
                -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
                -p "$GVM_SSH_PORT" \
                -L "$(_fwd_spec)" \
                "$GVM_SSH_USER@$GVM_HOST"; then
            echo "ssh forward failed to establish." >&2
            return 1
        fi
        local i=0
        until [[ -S "$GVMD_SOCKET" ]]; do
            if (( i++ >= WAIT_SECS )); then
                echo "Socket $GVMD_SOCKET never appeared." >&2; return 1
            fi
            sleep 1
        done
    fi

    local ver
    if ! ver="$(_verify_gmp)"; then
        echo "Tunnel is up but GMP did not verify — check GVM_PASS and that the" >&2
        echo "  host socket is readable by $GVM_SSH_USER." >&2
        return 1
    fi
    echo "OK — GMP protocol $ver, authenticated as $GVM_USER over $GVMD_SOCKET" >&2

    if (( _SOURCED )); then
        export GVMD_SOCKET
        echo "GVMD_SOCKET exported into this shell." >&2
        echo "Activate the venv and run:  source .venv/bin/activate && python vuln_agent.py" >&2
    else
        echo
        echo "# Connectivity verified. In your shell:"
        echo "export GVMD_SOCKET=\"$GVMD_SOCKET\""
        echo "source .venv/bin/activate && python vuln_agent.py"
        echo "# (or run this as 'source ./gvm_connect.sh' to skip the export copy/paste)"
    fi
    return 0
}

_install_service() {
    _require_env || return 1
    local unit_dir="$HOME/.config/systemd/user"
    mkdir -p "$unit_dir"
    cat > "$unit_dir/gvm-tunnel.service" <<EOF
[Unit]
Description=SSH forward for dockerized Greenbone gvmd socket (CAH2 Cat9 agent)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/ssh -NT \\
  -o ExitOnForwardFailure=yes \\
  -o StreamLocalBindUnlink=yes \\
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\
  -p ${GVM_SSH_PORT} \\
  -L ${GVMD_SOCKET}:${GVM_DOCKER_SOCKET} \\
  ${GVM_SSH_USER}@${GVM_HOST}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now gvm-tunnel.service
    echo "Installed and started gvm-tunnel.service (systemctl --user status gvm-tunnel)."
    echo "To survive reboots without an active login session:  sudo loginctl enable-linger $USER"
    echo "Relies on key-based SSH (no password prompt) to ${GVM_HOST}."
    return 0
}

# ---- dispatch (no 'exit' when sourced; restore caller's options at the end) --
_gvm_main() {
    case "${1:-}" in
        --status)          _status ;;
        --down)            _down ;;
        --install-service) _install_service ;;
        ""|--up)           _establish ;;
        -h|--help)         sed -n '2,20p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//' ;;
        *) echo "unknown option: $1 (try --help)" >&2; return 2 ;;
    esac
}

_gvm_rc=0
_gvm_main "${@:-}" || _gvm_rc=$?

if (( _SOURCED )); then
    eval "$_GVM_RESTORE" 2>/dev/null || true   # put the caller's shell options back
    return "$_gvm_rc" 2>/dev/null || true
else
    exit "$_gvm_rc"
fi
