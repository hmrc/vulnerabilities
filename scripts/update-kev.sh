#!/usr/bin/env zsh

# Convenience script for working with latest KEV data locally - downloads a JSON file
# KEV Github repo: https://github.com/cisagov/kev-data

set -euo pipefail

SCRIPT_DIR=$(
  CDPATH= cd -- "$(dirname -- "$0")" &&
  pwd -P
) || {
  printf '%s\n' "Error: unable to determine the script directory." >&2
  exit 1
}

if ! PROJECT_DIR=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null); then
  print -u2 "Error: unable to determine the Git project root from: $SCRIPT_DIR"
  exit 1
fi

JSON_DOWNLOAD_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FORMATTED_DATE=$(date -u +%Y-%m-%d)
KEV_DIR="$PROJECT_DIR/kev"
OUTPUT_FILE="$KEV_DIR/kev_${FORMATTED_DATE}.json"
TEMP_FILE=""

cleanup() {
  if [[ -n "$TEMP_FILE" ]]; then
    rm -f -- "$TEMP_FILE"
  fi
}

trap cleanup EXIT INT TERM

if ! mkdir -p -- "$KEV_DIR"; then
  print -u2 "Error: unable to create directory: $KEV_DIR"
  exit 1
fi

if ! TEMP_FILE=$(mktemp "$KEV_DIR/.kev_${FORMATTED_DATE}.XXXXXX"); then
  print -u2 "Error: unable to create temporary file in: $KEV_DIR"
  exit 1
fi

print "Downloading latest KEV data to temporary file: $TEMP_FILE"

curl \
  --location \
  --output "$TEMP_FILE" \
  "$JSON_DOWNLOAD_URL"

if command -v jq >/dev/null 2>&1; then
  if ! jq empty "$TEMP_FILE" >/dev/null; then
    print -u2 "Error: downloaded content is not valid JSON."
    exit 1
  fi
else
  print "Warning: jq is not installed; skipping JSON validation."
fi

mv -- "$TEMP_FILE" "$OUTPUT_FILE"
TEMP_FILE=""

print "Wrote latest KEV data to: $OUTPUT_FILE"