#!/usr/bin/env bash
set -euo pipefail
source ~/.cah2-secrets
export WAZUH_PASS GRAYLOG_TOKEN GVM_PASS GVM_CONN GVMD_SOCKET GVM_HOST GVM_PORT  # whatever your sources need
cd ~/cah2-ai-agents
source .venv/bin/activate
python orchestrator.py
