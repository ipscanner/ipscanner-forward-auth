#!/usr/bin/env bash
# Usage: IPSCANNER_KEY_FILE=key IPSCANNER_E2E_SITE_HELPER=site.cjs bash test/e2e/run.sh (KEEP=1 keeps the containers)
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
dir="$root/test/e2e"
: "${IPSCANNER_KEY_FILE:?set IPSCANNER_KEY_FILE}"
: "${IPSCANNER_E2E_SITE_HELPER:?set IPSCANNER_E2E_SITE_HELPER}"
API_URL=${IPSCANNER_API_URL:-http://localhost:3050}
export SITE_ID=${IPSCANNER_E2E_SITE:-site_fwdauthe2e0000000001}
export IPSCANNER_DOCKER_API_URL=${IPSCANNER_DOCKER_API_URL:-http://host.docker.internal:3050}

TOR=185.220.101.1
VPN=185.217.69.166
HOSTING=5.9.0.1
HOME_IP=84.128.0.1
GOOGLEBOT_IP=66.249.66.1
CHROME="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
HEADLESS="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36"
GOOGLEBOT="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
RUN=$(date +%s)

compose() { docker compose -f "$dir/docker-compose.yml" "$@"; }

cleanup() {
	if [ "${KEEP:-}" != 1 ]; then
		compose down -v --remove-orphans >/dev/null 2>&1 || true
		docker volume rm fae2e-secrets >/dev/null 2>&1 || true
	fi
	rm -rf "$root/vendor"
}
trap cleanup EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() {
	fail=$((fail + 1))
	printf '  FAIL  %s\n' "$1"
	if [ -n "${2:-}" ]; then printf '%s\n' "${2:0:1500}" | sed 's/^/        /'; fi
	echo
}

# req <port> <ip> <ua> [path] [extra curl args...]: sets CODE, BODY, HEAD, TIME.
req() {
	local port=$1 ip=$2 ua=$3 path=${4:-/} out
	shift 4 || shift $#
	out=$(mktemp)
	HEAD=$(curl -s -D - -o "$out" -m 15 -w '\n%{http_code} %{time_total}' \
		-H "X-Forwarded-For: $ip" -A "$ua" -H "X-IPScanner-Class: forged" -H "X-IPScanner-Status: forged" \
		"$@" "http://localhost:$port$path" || true)
	local last=${HEAD##*$'\n'}
	CODE=${last%% *}
	TIME=${last##* }
	BODY=$(cat "$out")
	rm -f "$out"
}

has() {
	local r=1
	shopt -s nocasematch
	[[ "$BODY" == *"$1"* ]] && r=0
	shopt -u nocasematch
	return $r
}
hdr() { printf '%s' "$HEAD" | grep -i "^$1:" | head -1 | cut -d: -f2- | tr -d ' \r'; }

expect() { # expect <name> <code> [body patterns...]; a pattern starting with ! must be absent
	local name=$1 code=$2 p
	shift 2
	if [ "$CODE" != "$code" ]; then bad "$name: status $CODE, want $code" "$BODY"; return; fi
	for p in "$@"; do
		if [ "${p#!}" != "$p" ]; then
			if has "${p#!}"; then bad "$name: body has '${p#!}'" "$BODY"; return; fi
		elif ! has "$p"; then
			bad "$name: body lacks '$p'" "$BODY"
			return
		fi
	done
	ok "$name"
}

with_timeout() {
	local t=$1 pid watcher rc=0
	shift
	"$@" &
	pid=$!
	(sleep "$t" && kill "$pid") >/dev/null 2>&1 &
	watcher=$!
	wait "$pid" || rc=$?
	kill "$watcher" 2>/dev/null || true
	return $rc
}

helper() { with_timeout 60 node "$IPSCANNER_E2E_SITE_HELPER" "$@"; }
site() { helper "$SITE_ID" forward_auth "$1" "$2"; }

site_rows() {
	helper rows forward_auth 500 |
		node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{console.log(JSON.parse(s).filter(r=>r.site===process.argv[1]).length)})' "$SITE_ID"
}

wait_rows() {
	local want=$1 n i
	for i in $(seq 1 20); do
		n=$(site_rows)
		[ "$n" -ge "$want" ] && break
		sleep 1
	done
	echo "$n"
}

# request_log is flushed every 5 s: wait until the row count stops changing.
settled_rows() {
	local a b
	a=$(site_rows)
	while :; do
		sleep 6
		b=$(site_rows)
		[ "$a" = "$b" ] && break
		a=$b
	done
	echo "$b"
}

echo "== setup"
site enforce '{"tor":"block","vpn":"flag"}' >/dev/null
# Warm the API up: the first edge check after a cold start can be slow.
printf 'Authorization: Bearer %s\n' "$(tr -d '\r\n' <"$IPSCANNER_KEY_FILE")" |
	curl -s -o /dev/null -m 10 -H @- -H 'Content-Type: application/json' \
		-d "{\"ip\":\"$HOME_IP\",\"user_agent\":\"warmup\",\"headers\":{}}" "$API_URL/v1/edge/check" || true

docker volume create fae2e-secrets >/dev/null
docker run --rm -i -v fae2e-secrets:/s alpine:3.20 \
	sh -c 'cat > /s/api_key && chown 65532:65532 /s/api_key && chmod 400 /s/api_key' <"$IPSCANNER_KEY_FILE"

cd "$root"
if grep -q '^replace' go.mod; then go mod vendor; fi
docker build -q -t ipscanner-forward-auth:e2e "$root" >/dev/null
compose up -d --wait --wait-timeout 60 gate gate-proxy gate-nosite gate-strict gate-dead app >/dev/null
compose up -d nginx npm traefik caddy haproxy apache >/dev/null
for port in 18110 18111 18112 18113 18114 18115 18116; do
	for i in $(seq 1 30); do
		curl -s -o /dev/null -m 2 "http://localhost:$port/robots.txt" && break
		sleep 1
	done
done
sleep 2

echo "== image"
health=$(docker inspect -f '{{.State.Health.Status}} {{.Config.User}}' fae2e-gate)
[ "$health" = "healthy nonroot:nonroot" ] && ok "HEALTHCHECK healthy, user nonroot" || bad "health/user: $health"
req 18100 "$HOME_IP" "$CHROME" /healthz
expect "/healthz" 200 '"status":"ok"' '"version":"0.1.1"' "\"site\":\"$SITE_ID\""

echo "== enforce site policy: tor block, vpn flag"
for proxy in nginx:18110 npm:18111 traefik:18112 caddy:18113 haproxy:18114 apache:18115; do
	name=${proxy%%:*}
	port=${proxy##*:}
	req "$port" "$HOME_IP" "$CHROME" "/account?run=$RUN"
	expect "$name residential allowed with headers" 200 "X-Ipscanner-Status: ok" "X-Ipscanner-Class: human" "X-Ipscanner-Action: allow" '!forged'
	req "$port" "$TOR" "$CHROME" "/login"
	expect "$name tor blocked (403 page)" 403 "Access denied" "Request ID"
	req "$port" "$VPN" "$CHROME" "/"
	expect "$name vpn flagged" 200 "X-Ipscanner-Class: vpn" "X-Ipscanner-Action: flag"
	req "$port" "$GOOGLEBOT_IP" "$GOOGLEBOT" "/"
	expect "$name verified crawler passes" 200 "X-Ipscanner-Class: verified_bot" "X-Ipscanner-Action: allow"
	req "$port" "$TOR" "$CHROME" "/static/app.css"
	expect "$name static asset skipped" 200 "X-Ipscanner-Status: skipped" '!X-Ipscanner-Class'
done
for proxy in nginx:18110 npm:18111; do
	req "${proxy##*:}" "$VPN" "$CHROME" "/"
	expect "${proxy%%:*} sets every verdict header" 200 "X-Ipscanner-Network-Class:" "X-Ipscanner-Anonymized:" "X-Ipscanner-Risk:" "X-Ipscanner-Country:" "X-Ipscanner-Site: $SITE_ID"
done
req 18110 "$HOME_IP" "$CHROME" "/" -X POST -d 'a=1'
expect "nginx POST passes with body" 200 "POST / HTTP" "a=1"
req 18110 "$TOR" "$CHROME" "/form" -X POST -d 'a=1'
expect "nginx POST from tor blocked" 403 "Access denied"

echo "== verdict cache"
ua="fae2e-cache-$RUN"
before=$(settled_rows)
req 18110 "$HOME_IP" "$ua" "/"
expect "first request" 200 "X-Ipscanner-Status: ok"
after=$(wait_rows $((before + 1)))
[ "$after" -eq $((before + 1)) ] && ok "first request: 1 edge check row ($before -> $after)" || bad "first request rows $before -> $after"
req 18110 "$HOME_IP" "$ua" "/again"
req 18110 "$HOME_IP" "$ua" "/third"
expect "repeat requests" 200 "X-Ipscanner-Class: human"
again=$(settled_rows)
[ "$again" -eq "$after" ] && ok "repeat requests made no API call ($again rows)" || bad "repeat requests rows $after -> $again"
gate_log=$(docker logs fae2e-gate 2>&1)
case "$gate_log" in *'"edge":"hit"'*) ok "gate log shows a cache hit" ;; *) bad "no cache hit in the gate log" ;; esac

echo "== policy change after POLICY_TTL"
site enforce '{"tor":"flag","vpn":"flag"}' >/dev/null
sleep 7
req 18110 "$TOR" "$CHROME" "/"
expect "nginx tor now flagged" 200 "X-Ipscanner-Class: tor" "X-Ipscanner-Action: flag"
req 18114 "$TOR" "$CHROME" "/"
expect "haproxy tor now flagged" 200 "X-Ipscanner-Class: tor" "X-Ipscanner-Action: flag"

echo "== monitor mode never blocks"
site monitor '{"tor":"block","vpn":"block"}' >/dev/null
sleep 7
for proxy in nginx:18110 traefik:18112 caddy:18113 apache:18115; do
	req "${proxy##*:}" "$TOR" "$CHROME" "/"
	expect "${proxy%%:*} tor in monitor mode" 200 "X-Ipscanner-Class: tor" "X-Ipscanner-Action: would_block"
done

echo "== no site: MODE=enforce BLOCK_CLASSES=tor,hosting"
req 18102 "$TOR" "$CHROME" /check -H "X-Forwarded-Uri: /"
[ "$CODE" = 403 ] && [ "$(hdr X-Ipscanner-Action)" = block ] && ok "tor blocked" || bad "tor: $CODE $(hdr X-Ipscanner-Action)"
req 18102 "$HOME_IP" "$CHROME" /check -H "X-Forwarded-Uri: /"
[ "$CODE" = 200 ] && [ "$(hdr X-Ipscanner-Class)" = human ] && ok "residential allowed" || bad "residential: $CODE $(hdr X-Ipscanner-Class)"
req 18102 "$VPN" "$CHROME" /check -H "X-Forwarded-Uri: /"
[ "$CODE" = 200 ] && [ "$(hdr X-Ipscanner-Action)" = allow ] && ok "vpn allowed (not listed)" || bad "vpn: $CODE $(hdr X-Ipscanner-Action)"
req 18102 "$HOSTING" "$HEADLESS" /check -H "X-Forwarded-Uri: /"
cls=$(hdr X-Ipscanner-Class)
net=$(hdr X-Ipscanner-Network-Class)
[ "$CODE" = 403 ] && ok "headless on hosting blocked (class $cls, network $net)" || bad "hosting: $CODE $cls $net"

echo "== spoofed X-Forwarded-For from an untrusted peer"
req 18116 "$TOR" "$CHROME" "/"
expect "traefik entry point without trustedIPs drops the spoofed X-Forwarded-For" 200 "X-Ipscanner-Status: skipped" '!forged'
req 18103 "$TOR" "$CHROME" /check -H "X-Forwarded-Uri: /"
[ "$CODE" = 200 ] && [ "$(hdr X-Ipscanner-Status)" = skipped ] && ok "ignored: peer address used (private, skipped)" || bad "spoof: $CODE $(hdr X-Ipscanner-Status)"
req 18102 "$TOR" "$CHROME" /check -H "X-Forwarded-Uri: /"
[ "$CODE" = 403 ] && ok "control: same request from a trusted peer is blocked" || bad "control: $CODE"

echo "== fail open"
req 18104 "$TOR" "$CHROME" /check -H "X-Forwarded-Uri: /"
[ "$CODE" = 200 ] && [ "$(hdr X-Ipscanner-Status)" = error ] && ok "dead API: allowed in ${TIME}s (status error)" || bad "dead API: $CODE $(hdr X-Ipscanner-Status)"
awk "BEGIN{exit !($TIME < 1.6)}" && ok "under the 1.5 s budget" || bad "took ${TIME}s"
req 18104 "$TOR" "$HEADLESS" /check -H "X-Forwarded-Uri: /"
[ "$CODE" = 200 ] && [ "$(hdr X-Ipscanner-Status)" = backoff ] && ok "next request in backoff (${TIME}s)" || bad "backoff: $CODE $(hdr X-Ipscanner-Status)"
req 18104 "$TOR" "$CHROME" /healthz
expect "healthz reports the backoff" 200 '"backoff":true' '"lastError":"error"'

docker stop fae2e-gate fae2e-gate-proxy >/dev/null
sleep 6
# Apache fails the gate on the first request that cannot reach it (500), then uses the hot standby.
req 18115 "$TOR" "$CHROME" "/"
echo "  info  apache first request with the gate down: $CODE"
for proxy in nginx:18110 npm:18111 haproxy:18114 apache:18115; do
	req "${proxy##*:}" "$TOR" "$CHROME" "/"
	expect "${proxy%%:*} passes with the gate down" 200 "Host:" '!X-Ipscanner-Class'
done
for proxy in traefik:18112 caddy:18113; do
	req "${proxy##*:}" "$TOR" "$CHROME" "/"
	echo "  info  ${proxy%%:*} with the gate down answers $CODE (no fail open in the proxy)"
done
docker start fae2e-gate fae2e-gate-proxy >/dev/null
sleep 4

echo "== request_log and sites"
rows=$(helper rows forward_auth 300)
printf '%s' "$rows" | node -e '
let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
  const site=process.argv[1];
  const r=JSON.parse(s).filter(x=>x.site===site);
  const classes=[...new Set(r.map(x=>x.traffic_class))].sort().join(",");
  const actions=[...new Set(r.map(x=>x.action))].sort().join(",");
  const ok=r.length>0 && r.every(x=>x.source==="forward_auth" && x.endpoint==="/v1/edge/check");
  console.log((ok?"ok":"FAIL")+" "+r.length+" rows, classes "+classes+", actions "+actions);
});' "$SITE_ID" | {
	read -r status rest
	[ "$status" = ok ] && ok "request_log rows: source forward_auth, site $SITE_ID, $rest" || bad "request_log: $rest"
}
row=$(site monitor '{"tor":"block","vpn":"block"}')
version=$(printf '%s' "$row" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).client_version))')
[ "$version" = 0.1.1 ] && ok "sites.client_version = $version" || bad "client_version: $version"

echo "== graceful shutdown"
docker stop -t 15 fae2e-gate-nosite >/dev/null
nosite_log=$(docker logs fae2e-gate-nosite 2>&1)
[[ "$nosite_log" == *'"shutting down"'* ]] && [ "$(docker inspect -f '{{.State.ExitCode}}' fae2e-gate-nosite)" = 0 ] &&
	ok "SIGTERM: logged and exited 0" || bad "shutdown" "$(docker logs fae2e-gate-nosite 2>&1 | tail -3)"
first_line=$(docker logs fae2e-gate 2>&1)
printf '%s\n' "${first_line%%$'\n'*}" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);process.exit(j.time&&j.message?0:1)})' &&
	ok "JSON log lines" || bad "log line is not JSON"
all_logs=$({ docker logs fae2e-gate; docker logs fae2e-gate-proxy; docker logs fae2e-gate-nosite; } 2>&1)
key=$(tr -d '\r\n' <"$IPSCANNER_KEY_FILE")
[ -n "$key" ] && [[ "$all_logs" != *"$key"* ]] && ok "API key not in the logs" || bad "API key in the logs"
unset key

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
