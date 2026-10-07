#!/usr/bin/env bash
# SOURCE REVIEW ONLY during 0.6.2 preparation. Albert runs this himself after review.
# Never invoke with shell tracing: this wrapper disables it before any secret action.
set +x
set -euo pipefail
umask 077
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_directory/setup_updater_key.py" "$@"
