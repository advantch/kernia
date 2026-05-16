#!/usr/bin/env bash
# Boot the example backend on http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")/../.."
exec .venv/bin/python -m uvicorn examples.backend.app:app --port 8000 --host 127.0.0.1 --reload
