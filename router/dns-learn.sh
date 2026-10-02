#!/bin/sh
# dns-learn v5
# Every run collects ALL newly observed NextDNS domains.
# Nothing is blocked automatically.

set -eu

BASE="/etc/dns-master"
CONF="$BASE/nextdns.conf"
PENDING="$BASE/review-pending.txt"
HISTORY="$BASE/history-seen.txt"
BLOCK="$BASE/block.txt"
ALLOW="$BASE/allow.txt"
IGNORED="$BASE/ignored.txt"
STATE="$BASE/last_success_epoch"

LOCKDIR="/tmp/dns-learn.lock"
WORK="/tmp/dns-learn.$$"
API="https://api.nextdns.io"

cleanup() {
    rm -rf "$LOCKDIR" "$WORK".* 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$BASE"
touch "$PENDING" "$HISTORY" "$BLOCK" "$ALLOW" "$IGNORED"

mkdir "$LOCKDIR" 2>/dev/null || exit 0

[ -r "$CONF" ] || { echo "Missing $CONF" >&2; exit 1; }
# shellcheck disable=SC1090
. "$CONF"

: "${NEXTDNS_PROFILE_ID:?Missing NEXTDNS_PROFILE_ID}"
: "${NEXTDNS_API_KEY:?Missing NEXTDNS_API_KEY}"
NEXTDNS_RAW="${NEXTDNS_RAW:-1}"

command -v curl >/dev/null 2>&1 || { echo "curl required" >&2; exit 1; }
command -v jsonfilter >/dev/null 2>&1 || { echo "jsonfilter required" >&2; exit 1; }

now="$(date +%s)"
if [ -s "$STATE" ]; then
    from="$(cat "$STATE" 2>/dev/null || true)"
else
    from=$((now - 300))
fi
case "$from" in ''|*[!0-9]*) from=$((now - 300));; esac

# 30s overlap prevents boundary misses.
from=$((from - 30))
[ "$from" -lt 0 ] && from=0

: > "$WORK.domains"
cursor=""
page=0

while :; do
    page=$((page + 1))
    url="$API/profiles/$NEXTDNS_PROFILE_ID/logs?from=$from&to=$now&sort=asc&limit=1000&raw=$NEXTDNS_RAW"
    [ -n "$cursor" ] && url="$url&cursor=$cursor"

    code="$(
      curl -sS --connect-timeout 15 --max-time 60 \
        -H "X-Api-Key: $NEXTDNS_API_KEY" \
        -o "$WORK.page" -w '%{http_code}' "$url"
    )"
    [ "$code" = "200" ] || {
        echo "NextDNS API HTTP $code" >&2
        exit 1
    }

    if jsonfilter -i "$WORK.page" -e '@.errors[0].code' 2>/dev/null | grep -q .; then
        cat "$WORK.page" >&2
        exit 1
    fi

    jsonfilter -i "$WORK.page" -e '@.data[*].domain' 2>/dev/null >> "$WORK.domains" || true

    cursor="$(jsonfilter -i "$WORK.page" -e '@.meta.pagination.cursor' 2>/dev/null || true)"
    [ -n "$cursor" ] || break

    # Safety guard against a malformed endless cursor chain.
    [ "$page" -lt 500 ] || { echo "Too many pages; aborting" >&2; exit 1; }
done

tr '[:upper:]' '[:lower:]' < "$WORK.domains" \
  | sed -e 's/^\*\.//' -e 's/\.$//' \
  | grep -E '^[a-z0-9][a-z0-9.-]*\.[a-z0-9-]+$' \
  | sort -u > "$WORK.clean" || true

# Permanent history is what guarantees "never add a duplicate again".
cat "$HISTORY" "$BLOCK" "$ALLOW" "$IGNORED" 2>/dev/null \
  | sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' \
  | tr '[:upper:]' '[:lower:]' \
  | sed -e 's/^\*\.//' -e 's/\.$//' \
  | sort -u > "$WORK.known"

comm -23 "$WORK.clean" "$WORK.known" > "$WORK.new" || true

new_count=0
if [ -s "$WORK.new" ]; then
    cat "$WORK.new" >> "$PENDING"
    cat "$WORK.new" >> "$HISTORY"
    sort -u "$PENDING" -o "$PENDING"
    sort -u "$HISTORY" -o "$HISTORY"
    new_count="$(wc -l < "$WORK.new" | tr -d ' ')"
fi

# Advance checkpoint only after all pages were fetched successfully.
printf '%s\n' "$now" > "$STATE"

echo "dns-learn: pages=$page +$new_count new; pending=$(wc -l < "$PENDING" | tr -d ' '); history=$(wc -l < "$HISTORY" | tr -d ' ')"
