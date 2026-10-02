# DNS Master Blocklist

قائمة DNS مخصصة تجمع مصادر منتقاة، تنظفها، تحذف التكرارات، وتطبق Allowlist محلية قبل إخراج ملفات جاهزة.

## Default profile

المصادر المفعلة افتراضياً:

1. HaGeZi Multi PRO — privacy / ads / trackers / telemetry.
2. HaGeZi TIF Mini — malware / phishing / scam / threat domains.
3. `custom/block.txt` — إضافاتنا اليدوية.
4. `custom/allow.txt` — استثناءاتنا اليدوية، ولها أولوية على الحجب.

> لا يتم دمج Pro وPro++ معاً. اختر Tier واحد فقط.
> OISD وStevenBlack موجودان كخيارات غير مفعلة افتراضياً لتجنب التضخم والتكرار بلا فائدة.

## Outputs

بعد التشغيل:

- `dist/blocklist.txt` — domains فقط.
- `dist/dnsmasq.conf` — صيغة OpenWrt/dnsmasq.
- `dist/adblock.txt` — صيغة Adblock DNS (`||domain^`).
- `dist/allowlist.txt` — نسخة منظفة من الاستثناءات.
- `dist/report.json` — إحصائيات المصادر، الأخطاء، وعدد العناصر.

## Run

```bash
python3 src/build.py
```

للتجربة بدون تنزيل المصادر:

```bash
python3 -m unittest discover -s tests -v
```

## Source policy

- لا نضيف مصدر جديد لمجرد أنه مشهور.
- المصدر يجب أن يكون مُحدَّثاً، معروف الغرض، وله صيغة قابلة للتحقق.
- لا نضع CDN أو نطاقات خدمات عامة في allowlist.
- الاستثناءات تضاف بأضيق نطاق ممكن.

## OpenWrt learner — every 2 minutes

`router/dns-learn.sh` queries NextDNS logs with `status=default`, so it learns domains that were not already blocked or explicitly allowed.

Every successful run remembers its last successful time, keeps a 30-second overlap to avoid edge losses, and deduplicates against:

- `/etc/dns-master/block.txt`
- `/etc/dns-master/allow.txt`
- `/etc/dns-master/candidates.txt`

Install:

```sh
cd router
sh install-openwrt.sh
vi /etc/dns-master/nextdns.conf
dns-learn
```

Cron installed:

```cron
*/2 * * * * /usr/bin/dns-learn >> /tmp/dns-learn.log 2>&1
```

The API key stays only on the router in `/etc/dns-master/nextdns.conf` with permission `600` and must never be committed to GitHub.


## Firebog intelligence mode

The URLs listed in `config/firebog_sources.json` are **not blindly merged into the blocking list**.

Daily GitHub Actions build:

```text
Firebog feeds
    -> normalize
    -> deduplicate
    -> dist/firebog-intel.txt
```

The router can then compare its real-world candidates:

```sh
dns-firebog-match
cat /etc/dns-master/candidates-firebog.txt
```

Only domains that are both:

1. actually observed on your network; and
2. present in the Firebog intelligence set

appear in `candidates-firebog.txt`.

This keeps the main blocklist small and avoids duplicate/unused entries.


## v4 — Observe first, decide later

Every 2 minutes, `dns-learn` reads recent NextDNS logs and stores **only never-before-seen domains**.

Files on OpenWrt:

```text
/etc/dns-master/review-pending.txt   # waiting for human decision
/etc/dns-master/history-seen.txt     # permanent de-duplicated history
/etc/dns-master/block.txt            # user decided: block
/etc/dns-master/allow.txt            # user decided: allow
/etc/dns-master/ignored.txt          # reviewed but no action
```

Nothing from `review-pending.txt` is blocked automatically.

Review commands:

```sh
dns-review list
dns-review count
dns-review block example.com
dns-review allow example.com
dns-review ignore example.com
```

Optional intelligence comparison:

```sh
dns-intel-match
```

Outputs:

```text
/etc/dns-master/review-firebog-hit.txt
/etc/dns-master/review-no-firebog-hit.txt
```

A Firebog hit is only a review signal, not an automatic block decision.


## v5 — Full lists + observed-domain review

This version does **not** treat the source URLs as the database.

GitHub Actions downloads every configured Firebog source in full, normalizes all
DNS domains, de-duplicates them, records category/source membership, and publishes
the resulting intelligence database as 256 compressed SHA-256 shards in the
rolling `intel-latest` GitHub Release.

Why shards?

- multi-million-domain sources can create very large aggregate files;
- the router never needs to download the entire intelligence corpus;
- a lookup downloads only 1/256 of the database and caches that shard.

### Router observation

Every 2 minutes `dns-learn` reads NextDNS logs with `raw=1`, follows pagination,
and stores only domains never seen before:

```text
/etc/dns-master/review-pending.txt
/etc/dns-master/history-seen.txt
```

Nothing in `review-pending.txt` is auto-blocked.

### Review

```sh
dns-review list
dns-intel-check example.com
dns-review block example.com
dns-review allow example.com
dns-review ignore example.com
```

`dns-intel-check` returns category flags and how many configured source lists
contained that domain. Human review remains the final decision.
