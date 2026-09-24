#!/usr/bin/env zsh

set -euo pipefail

usage() {
  print "Usage: update-epss.sh [-d|--date YYYY-MM-DD]"
}

SCRIPT_DIR=$(
  CDPATH='' cd -- "$(dirname -- "$0")" &&
  pwd -P
) || {
  printf '%s\n' "Error: unable to determine the script directory." >&2
  exit 1
}

if ! PROJECT_DIR=$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null); then
  print -u2 "Error: unable to determine the Git project root from: $SCRIPT_DIR"
  exit 1
fi

FORMATTED_DATE=$(date -u +%Y-%m-%d)

while (( $# > 0 )); do
  case "$1" in
    -d|--date)
      if (( $# < 2 )); then
        print -u2 "Error: $1 requires a date in YYYY-MM-DD format."
        usage >&2
        exit 1
      fi
      FORMATTED_DATE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      print -u2 "Error: unknown argument: $1"
      usage >&2
      exit 1
      ;;
  esac
done

PARSED_DATE=""
if [[ "$FORMATTED_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  if ! PARSED_DATE=$(date -u -j -f "%Y-%m-%d" "$FORMATTED_DATE" "+%Y-%m-%d" 2>/dev/null); then
    PARSED_DATE=""
  fi
fi

if [[ "$PARSED_DATE" != "$FORMATTED_DATE" ]]; then
  print -u2 "Error: date must be a valid date in YYYY-MM-DD format: $FORMATTED_DATE"
  exit 1
fi

EPSS_DIR="$PROJECT_DIR/epss"
DOWNLOAD_URL="https://epss.empiricalsecurity.com/epss_scores-${FORMATTED_DATE}.csv.gz"
OUTPUT_FILE="$EPSS_DIR/epss_${FORMATTED_DATE}.csv"
TEMP_GZ=""
TEMP_CSV=""

cleanup() {
  if [[ -n "$TEMP_GZ" ]]; then
    rm -f -- "$TEMP_GZ"
  fi
  if [[ -n "$TEMP_CSV" ]]; then
    rm -f -- "$TEMP_CSV"
  fi
}

trap cleanup EXIT INT TERM

if ! mkdir -p -- "$EPSS_DIR"; then
  print -u2 "Error: unable to create directory: $EPSS_DIR"
  exit 1
fi

if ! TEMP_GZ=$(mktemp "$EPSS_DIR/.epss_${FORMATTED_DATE}.gz.XXXXXX"); then
  print -u2 "Error: unable to create temporary download file in: $EPSS_DIR"
  exit 1
fi

if ! TEMP_CSV=$(mktemp "$EPSS_DIR/.epss_${FORMATTED_DATE}.csv.XXXXXX"); then
  print -u2 "Error: unable to create temporary CSV file in: $EPSS_DIR"
  exit 1
fi

# print as a multiline message to aid readbility:

print -r -- "Downloading EPSS data for $FORMATTED_DATE from url: $DOWNLOAD_URL
to temporary file: $TEMP_GZ"

curl \
  --fail \
  --location \
  --user-agent "update-epss.sh" \
  --output "$TEMP_GZ" \
  "$DOWNLOAD_URL"

print "Decompressing EPSS data to temporary CSV: $TEMP_CSV"
gzip -dc -- "$TEMP_GZ" > "$TEMP_CSV"

mv -- "$TEMP_CSV" "$OUTPUT_FILE"
TEMP_CSV=""

print "Wrote raw EPSS CSV to: $OUTPUT_FILE"
