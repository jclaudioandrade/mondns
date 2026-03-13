#!/bin/bash
# ============================================================
# mondns — Health Check Script
# ============================================================
set -e

PORT=${PORT:-8002}

curl -f --silent --max-time 5 "http://localhost:${PORT}/health" || exit 1
