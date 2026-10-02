#!/bin/sh
set -eu
BASE="/etc/dns-master"
SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p "$BASE"

install -m 755 "$SRC_DIR/dns-learn.sh" /usr/bin/dns-learn
install -m 755 "$SRC_DIR/dns-review" /usr/bin/dns-review
install -m 755 "$SRC_DIR/dns-intel-check" /usr/bin/dns-intel-check

touch \
  "$BASE/review-pending.txt" \
  "$BASE/history-seen.txt" \
  "$BASE/block.txt" \
  "$BASE/allow.txt" \
  "$BASE/ignored.txt"

if [ ! -e "$BASE/nextdns.conf" ]; then
cat > "$BASE/nextdns.conf" <<'EOF'
NEXTDNS_PROFILE_ID='PUT_PROFILE_ID_HERE'
NEXTDNS_API_KEY='PUT_API_KEY_HERE'
NEXTDNS_RAW='1'
EOF
fi
chmod 600 "$BASE/nextdns.conf"

if [ ! -e "$BASE/intel.conf" ]; then
cat > "$BASE/intel.conf" <<'EOF'
INTEL_BASE_URL='https://github.com/OWNER/REPO/releases/download/intel-latest'
CACHE_HOURS='24'
EOF
fi

CRON="/etc/crontabs/root"
touch "$CRON"
sed -i '\|/usr/bin/dns-learn|d' "$CRON"
printf '*/2 * * * * /usr/bin/dns-learn >> /tmp/dns-learn.log 2>&1\n' >> "$CRON"
/etc/init.d/cron restart

echo "Installed v5."
echo "Configure:"
echo "  $BASE/nextdns.conf"
echo "  $BASE/intel.conf"
