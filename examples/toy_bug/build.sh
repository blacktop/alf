#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v fish >/dev/null 2>&1; then
  echo "[-] fish shell is required to run the helper scripts" >&2
  exit 1
fi

# Build the harness (fish script keeps compiler config tidy).
fish --no-config "${script_dir}/build.fish"

# Run the smoke fuzz + LLDB triage loop.
fish --no-config "${script_dir}/smoke.fish"
