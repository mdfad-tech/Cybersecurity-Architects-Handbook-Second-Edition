#!/usr/bin/env bash
#
# greenbone_expose.sh — expose the dockerized gvmd Unix socket onto the
#   Greenbone HOST so the Category 9 agent box can SSH-forward it.
#
#   RUN THIS ON THE GREENBONE HOST (e.g. greenbone-debian13-lab-kvm-svr),
#   not on the agent box. It is the one-time, host-side counterpart to
#   gvm_connect.sh. It performs the three steps the lab describes:
#     1. swaps the shared gvmd socket volume (gvmd_socket_vol:/run/gvmd) for a
#        host bind mount (/tmp/gvm/gvmd:/run/gvmd) on EVERY service that uses
#        it — so gvmd, gsad, gvm-tools, etc. all see the same socket on disk;
#     2. adds --listen-mode=666 to gvmd so the socket is readable by the SSH
#        user on the agent side (default is 660, owned by an in-container uid);
#     3. recreates the stack and verifies gvmd still answers GMP.
#
#   Safe by default: with no arguments it only prints a plan and changes
#   nothing. --apply backs up the compose file first and is reversible with
#   --restore.
#
# Usage (on the Greenbone host):
#   ./greenbone_expose.sh                 # DRY RUN: show the plan, change nothing
#   sudo ./greenbone_expose.sh --apply    # back up, edit, recreate, verify
#   sudo ./greenbone_expose.sh --restore  # roll back to the most recent backup
#   sudo ./greenbone_expose.sh --verify   # just run the gvmd GMP health check
#
# Overridable env: COMPOSE_FILE, HOST_DIR, GVMD_SERVICE, TOOLS_SERVICE,
#                  GVM_USER, GVM_PASS, WAIT_SECS
#
set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-/home/secdoc/greenbone/docker-compose.yaml}"
HOST_DIR="${HOST_DIR:-/tmp/gvm/gvmd}"          # host path the socket lands on
NAMED_MOUNT="gvmd_socket_vol:/run/gvmd"        # what the stock compose uses
HOST_MOUNT="${HOST_DIR}:/run/gvmd"             # what we swap it to
GVMD_SERVICE="${GVMD_SERVICE:-gvmd}"           # service that creates the socket
TOOLS_SERVICE="${TOOLS_SERVICE:-gvm-tools}"    # one-shot CLI service for the check
GVM_USER="${GVM_USER:-admin}"
WAIT_SECS="${WAIT_SECS:-30}"
SOCK_PATH="${HOST_DIR}/gvmd.sock"

# docker on this host may require sudo (it did in your session)
DOCKER="docker"
docker ps >/dev/null 2>&1 || DOCKER="sudo docker"
DC() { $DOCKER compose -f "$COMPOSE_FILE" "$@"; }

[[ -f "$COMPOSE_FILE" ]] || {
    echo "compose file not found: $COMPOSE_FILE" >&2
    echo "  find it with:  docker compose ls   (then set COMPOSE_FILE=...)" >&2
    exit 1
}

# We need mikefarah yq v4 for the gvmd command edit — NOT the python 'yq'
# (kislyuk/yq), which has incompatible syntax. Detect which one is present.
HAVE_YQ=0
if command -v yq >/dev/null 2>&1 && yq --version 2>&1 | grep -qiE 'mikefarah|version v?4'; then
    HAVE_YQ=1
fi

# ---- inspection helpers ------------------------------------------------------
_named_lines()  { grep -nF "$NAMED_MOUNT" "$COMPOSE_FILE" || true; }
_already_bound(){ grep -qF "$HOST_MOUNT" "$COMPOSE_FILE"; }

_listen_mode_present() {
    if (( HAVE_YQ )); then
        SVC="$GVMD_SERVICE" yq '
            (.services[strenv(SVC)].command // [])
            | (if type == "!!str" then [.] else . end)
            | map(select(test("--listen-mode"))) | length
        ' "$COMPOSE_FILE" 2>/dev/null | grep -qvx 0
    else
        # best-effort textual check within the gvmd service block
        awk -v svc="$GVMD_SERVICE" '
            $0 ~ "^[[:space:]]*"svc":" {inblk=1; next}
            inblk && /^[^[:space:]]/ {inblk=0}
            inblk && /--listen-mode/ {found=1}
            END {exit found?0:1}
        ' "$COMPOSE_FILE"
    fi
}

# ---- the GMP health check (uses run, not exec — gvm-tools is one-shot) --------
_verify_gmp() {
    echo "Verifying gvmd over GMP via the $TOOLS_SERVICE container ..." >&2
    local out
    out="$(DC run --rm --no-deps -T "$TOOLS_SERVICE" \
            gvm-cli --gmp-username "$GVM_USER" --gmp-password "${GVM_PASS:-}" \
            socket --xml "<get_version/>" 2>&1)" || true
    echo "$out" >&2
    grep -q 'status="200"' <<<"$out"
}

# ---- subcommands -------------------------------------------------------------
_plan() {
    echo "=== greenbone_expose.sh — DRY RUN (no changes made) ==="
    echo "compose file : $COMPOSE_FILE"
    echo "yq (mikefarah v4) present : $([[ $HAVE_YQ == 1 ]] && echo yes || echo NO)"
    echo
    echo "[1] Volume swap  $NAMED_MOUNT  ->  $HOST_MOUNT"
    if _already_bound; then
        echo "    already bind-mounted to the host — nothing to swap."
    fi
    local lines; lines="$(_named_lines)"
    if [[ -n "$lines" ]]; then
        echo "    lines that would change:"
        sed 's/^/      /' <<<"$lines"
    else
        echo "    no '$NAMED_MOUNT' entries found (already swapped, or your"
        echo "    compose uses long-form volume syntax — paste it and I'll adjust)."
    fi
    echo
    echo "[2] gvmd socket perms  --listen-mode=666 on service '$GVMD_SERVICE'"
    if _listen_mode_present; then
        echo "    already present — nothing to add."
    elif (( HAVE_YQ )); then
        echo "    would append '--listen-mode=666' to .services.$GVMD_SERVICE.command"
    else
        echo "    yq not found — would print a manual snippet to add by hand."
    fi
    echo
    echo "[3] Recreate stack  (docker compose down && up -d) and confirm:"
    echo "    socket on host : $SOCK_PATH"
    echo "    gvmd GMP check : <get_version/> returns status 200"
    echo
    echo "Apply for real with:   sudo $0 --apply"
}

_apply() {
    local backup="${COMPOSE_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp -a "$COMPOSE_FILE" "$backup"
    echo "Backed up compose -> $backup"

    # [1] volume swap — exact-string, idempotent, hits every service at once.
    if _named_lines | grep -q .; then
        sed -i "s#${NAMED_MOUNT}#${HOST_MOUNT}#g" "$COMPOSE_FILE"
        echo "Swapped socket volume to host bind mount on all referencing services."
    else
        echo "No '$NAMED_MOUNT' entries to swap (already done or long-form syntax)."
    fi

    # [2] listen-mode on gvmd
    if _listen_mode_present; then
        echo "--listen-mode already set on $GVMD_SERVICE — leaving it."
    elif (( HAVE_YQ )); then
        SVC="$GVMD_SERVICE" yq -i '
            .services[strenv(SVC)].command =
              (( .services[strenv(SVC)].command // [] )
                | (if type == "!!str" then [.] else . end)
                + ["--listen-mode=666"])
        ' "$COMPOSE_FILE"
        echo "Added --listen-mode=666 to $GVMD_SERVICE.command"
    else
        echo "!! yq (mikefarah v4) not installed — cannot patch the gvmd command." >&2
        echo "!! Add this under the '$GVMD_SERVICE:' service by hand, then re-run --apply:" >&2
        echo "       command:" >&2
        echo "         - --listen-mode=666" >&2
        echo "!! Without it the host socket will be mode 660 and the agent's forward" >&2
        echo "!! will fail with a permission error that looks like (but isn't) auth." >&2
        echo "Restore the pre-change file with:  sudo $0 --restore" >&2
        exit 2
    fi

    mkdir -p "$HOST_DIR"

    echo "Recreating the stack ..."
    DC down
    DC up -d

    # wait for the socket to appear on the host
    local i=0
    until [[ -S "$SOCK_PATH" ]]; do
        if (( i++ >= WAIT_SECS )); then
            echo "Socket never appeared at $SOCK_PATH after ${WAIT_SECS}s." >&2
            echo "Roll back with:  sudo $0 --restore" >&2
            exit 3
        fi
        sleep 1
    done
    echo "Socket present on host:"
    ls -l "$SOCK_PATH"

    if _verify_gmp; then
        echo
        echo "SUCCESS — gvmd answers GMP and the socket is exposed at $SOCK_PATH."
        echo "Now, on the AGENT box, point gvm_connect.sh at it:"
        echo "  export GVM_HOST=$(hostname -f 2>/dev/null || hostname) GVM_SSH_USER=secdoc GVM_PASS='...'"
        echo "  source ./gvm_connect.sh"
    else
        echo
        echo "Socket is exposed but the GMP check did not return status 200." >&2
        echo "gvmd may still be starting — retry:  sudo $0 --verify" >&2
        echo "If it persists, roll back:  sudo $0 --restore" >&2
        exit 4
    fi
}

_restore() {
    local latest
    latest="$(ls -1t "${COMPOSE_FILE}".bak.* 2>/dev/null | head -1 || true)"
    [[ -n "$latest" ]] || { echo "No backup (${COMPOSE_FILE}.bak.*) found." >&2; exit 1; }
    cp -a "$latest" "$COMPOSE_FILE"
    echo "Restored $COMPOSE_FILE from $latest"
    DC up -d
    echo "Stack recreated from the restored compose file."
}

case "${1:-}" in
    ""|--dry-run|--plan) _plan ;;
    --apply)             _apply ;;
    --restore)           _restore ;;
    --verify)            _verify_gmp && echo "gvmd GMP check OK (status 200)." ;;
    -h|--help)           sed -n '2,40p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//' ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
esac
