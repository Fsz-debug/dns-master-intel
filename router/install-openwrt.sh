#!/bin/sh
set -eu

BASE="/etc/dns-master"
SRC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

mkdir -p "$BASE"

echo "Installing DNS Master..."

# Review / intelligence tools
install -m 755 "$SRC_DIR/dns-review" \
    /usr/bin/dns-review

install -m 755 "$SRC_DIR/dns-intel-check" \
    /usr/bin/dns-intel-check

# Keep legacy learner available only as a manual fallback.
install -m 755 "$SRC_DIR/dns-learn.sh" \
    /usr/bin/dns-learn

# Live NextDNS SSE observer
install -m 755 "$SRC_DIR/dns-stream-capture" \
    /usr/bin/dns-stream-capture

install -m 755 "$SRC_DIR/dns-stream-process" \
    /usr/bin/dns-stream-process

install -m 755 "$SRC_DIR/dns-stream-processor-loop" \
    /usr/bin/dns-stream-processor-loop

install -m 755 "$SRC_DIR/dns-observer.init" \
    /etc/init.d/dns-observer


# Persistent state
touch \
    "$BASE/review-pending.txt" \
    "$BASE/history-seen.txt" \
    "$BASE/observed-all.tsv" \
    "$BASE/review-status.tsv" \
    "$BASE/stream-queue.tsv" \
    "$BASE/block.txt" \
    "$BASE/allow.txt" \
    "$BASE/ignored.txt"


# NextDNS credentials
if [ ! -e "$BASE/nextdns.conf" ]; then
cat > "$BASE/nextdns.conf" <<'CONFEOF'
NEXTDNS_PROFILE_ID='PUT_PROFILE_ID_HERE'
NEXTDNS_API_KEY='PUT_API_KEY_HERE'
NEXTDNS_RAW='1'
CONFEOF
fi

chmod 600 "$BASE/nextdns.conf"


# Intelligence release
if [ ! -e "$BASE/intel.conf" ]; then
cat > "$BASE/intel.conf" <<'INTELEOF'
INTEL_BASE_URL='https://github.com/Fsz-debug/dns-master-intel/releases/download/intel-latest'
CACHE_HOURS='24'
INTELEOF
fi

chmod 600 "$BASE/intel.conf"


# Remove obsolete 2-minute dns-learn cron entry.
if [ -d /etc/crontabs ]; then
    CRON="/etc/crontabs/root"
    touch "$CRON"
    sed -i '\|/usr/bin/dns-learn|d' "$CRON"

    if [ -x /etc/init.d/cron ]; then
        /etc/init.d/cron restart
    fi
fi


# Start at boot.
chmod 755 /etc/init.d/dns-observer
/etc/init.d/dns-observer enable


# Do not start with placeholder credentials.
if grep -q 'PUT_PROFILE_ID_HERE\|PUT_API_KEY_HERE' \
    "$BASE/nextdns.conf"
then
    echo
    echo "Installed successfully."
    echo
    echo "Configure first:"
    echo "  $BASE/nextdns.conf"
    echo
    echo "Then start:"
    echo "  /etc/init.d/dns-observer start"
else
    /etc/init.d/dns-observer restart

    echo
    echo "Installed and observer started."
fi

echo
echo "Observer architecture:"
echo "  NextDNS SSE stream -> queue continuously"
echo "  Queue processing   -> every 10 seconds"
echo "  Auto blocking      -> DISABLED"
echo
echo "Intel:"
echo "  $BASE/intel.conf"
echo
echo "Review:"
echo "  dns-review count"
echo "  dns-review list"
echo "  dns-intel-check example.com"
