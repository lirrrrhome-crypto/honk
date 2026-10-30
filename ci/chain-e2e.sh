#!/usr/bin/env bash
# End-to-end check of node-level chained dialing (`dialer-proxy`) against two
# real sing-box servers on loopback: A (socks5) is the front, B (shadowsocks)
# the landing node. Proves the A -> B -> target hops from the servers' access
# logs, runs the group health-check probe path the same way, then stops A and
# checks both fail instead of bypassing A, and that the health check recovers
# once A is back. Finally B's front becomes a selector group of A1/A2:
# the selected member carries each new connection, a switch moves new
# connections only, and a down selected member fails closed. Last, UDP
# rides a trojan landing through A and through the group, an ss landing is
# refused for UDP, and UDP fails closed with A down.
#
# Usage: ci/chain-e2e.sh [workdir]   (Linux x86_64; needs curl, python3)
set -euo pipefail

SING_BOX_VERSION=1.13.19
SING_BOX_SHA256=150456f94fcf936fc2519de28d856422fb671a1ff181cd909b78f20e208fdcb8
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${1:-$(mktemp -d)}
mkdir -p "$WORK/www"
cd "$WORK"

if [ ! -x sing-box ]; then
  curl -fsSL -o sb.tgz "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64-musl.tar.gz"
  echo "${SING_BOX_SHA256}  sb.tgz" | sha256sum -c -
  tar xzf sb.tgz
  cp "sing-box-${SING_BOX_VERSION}-linux-amd64-musl/sing-box" .
fi

cat > a.json <<JSON
{"log":{"level":"debug","output":"$WORK/a.log"},
 "inbounds":[{"type":"socks","tag":"A-socks","listen":"127.0.0.2","listen_port":21080}],
 "outbounds":[{"type":"direct","tag":"A-direct"}]}
JSON
cat > b.json <<JSON
{"log":{"level":"debug","output":"$WORK/b.log"},
 "inbounds":[{"type":"shadowsocks","tag":"B-ss","listen":"127.0.0.3","listen_port":28388,"method":"aes-128-gcm","password":"chainpw"}],
 "outbounds":[{"type":"direct","tag":"B-direct"}]}
JSON
cat > nodes.dae <<'DAE'
node {
    A: 'socks5://127.0.0.2:21080'
    B: 'ss://YWVzLTEyOC1nY206Y2hhaW5wdw@127.0.0.3:28388?dialer-proxy=A#B'
}
DAE
echo hello-through-chain > www/index.html
: > a.log; : > b.log

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT
./sing-box run -c a.json > a.out 2>&1 & a_pid=$!; pids+=("$a_pid")
./sing-box run -c b.json > b.out 2>&1 & b_pid=$!; pids+=("$b_pid")
python3 -m http.server 18080 --bind 127.0.0.4 --directory www > http.log 2>&1 & pids+=($!)
sleep 1

(cd "$ROOT" && cargo build -q -p honk-outbound --example chain_probe)
PROBE="$ROOT/target/debug/examples/chain_probe"

"$PROBE" nodes.dae B 127.0.0.4:18080 /index.html | tee probe.out
grep -q hello-through-chain probe.out
grep -q 'A-socks.*inbound connection to 127.0.0.3:28388' a.log
grep -q 'B-ss.*inbound connection to 127.0.0.4:18080' b.log
echo "PASS: target reached via A -> B"

HEALTH_URL=http://127.0.0.4:18080/index.html
: > a.log; : > b.log
"$PROBE" nodes.dae B 127.0.0.4:18080 --healthcheck "$HEALTH_URL" | tee health.out
grep -q 'healthcheck: Ok' health.out
grep -q 'A-socks.*inbound connection to 127.0.0.3:28388' a.log
grep -q 'B-ss.*inbound connection to 127.0.0.4:18080' b.log
echo "PASS: health check probes B via A"

kill "$a_pid"; wait "$a_pid" 2>/dev/null || true
: > b.log
"$PROBE" nodes.dae B 127.0.0.4:18080 --healthcheck "$HEALTH_URL" | tee health.out
grep -q 'healthcheck: Err' health.out
if grep -q 'inbound connection' b.log; then
  echo "FAIL: health check reached the landing node without the front" >&2; exit 1
fi
echo "PASS: front down -> health check fails, no bypass"
if "$PROBE" nodes.dae B 127.0.0.4:18080 /index.html; then
  echo "FAIL: dial succeeded with the front down" >&2; exit 1
fi
if grep -q 'inbound connection' b.log; then
  echo "FAIL: landing node reached without the front" >&2; exit 1
fi
echo "PASS: front down -> dial fails, no bypass"

./sing-box run -c a.json > a.out 2>&1 & a_pid=$!; pids+=("$a_pid")
sleep 1
: > a.log; : > b.log
"$PROBE" nodes.dae B 127.0.0.4:18080 --healthcheck "$HEALTH_URL" | tee health.out
grep -q 'healthcheck: Ok' health.out
grep -q 'A-socks.*inbound connection to 127.0.0.3:28388' a.log
echo "PASS: front back -> health check recovers via A"

# Group front: B's dialer-proxy names a selector group of two fronts A1/A2.
# New connections use the group's selection at connect time; a connection
# opened before a switch keeps its front.
cat > a2.json <<JSON
{"log":{"level":"debug","output":"$WORK/a2.log"},
 "inbounds":[{"type":"socks","tag":"A2-socks","listen":"127.0.0.5","listen_port":21081}],
 "outbounds":[{"type":"direct","tag":"A2-direct"}]}
JSON
cat > group.dae <<'DAE'
node {
    A1: 'socks5://127.0.0.2:21080'
    A2: 'socks5://127.0.0.5:21081'
    B: 'ss://YWVzLTEyOC1nY206Y2hhaW5wdw@127.0.0.3:28388?dialer-proxy=fronts#B'
}
group {
    fronts {
        filter: name(A1, A2)
        policy: selector
    }
}
DAE
: > a2.log
./sing-box run -c a2.json > a2.out 2>&1 & a2_pid=$!; pids+=("$a2_pid")
sleep 1
hops() { grep -c "$1.*inbound connection to 127.0.0.3:28388" "$2" || true; }
for pick in A1 A2; do
  : > a.log; : > a2.log; : > b.log
  CHAIN_SELECT=fronts=$pick "$PROBE" group.dae B 127.0.0.4:18080 /index.html | tee probe.out
  grep -q hello-through-chain probe.out
  CHAIN_SELECT=fronts=$pick "$PROBE" group.dae B 127.0.0.4:18080 --healthcheck "$HEALTH_URL" | tee health.out
  grep -q 'healthcheck: Ok' health.out
  if [ "$pick" = A1 ]; then on=$(hops A-socks a.log); off=$(hops A2-socks a2.log)
  else on=$(hops A2-socks a2.log); off=$(hops A-socks a.log); fi
  [ "$on" = 2 ] && [ "$off" = 0 ] || { echo "FAIL: select $pick -> hops on=$on off=$off" >&2; exit 1; }
  echo "PASS: group front selected $pick carries dial + health check"
done

: > a.log; : > a2.log; : > b.log
"$PROBE" group.dae B 127.0.0.4:18080 --switch fronts A1 A2 /index.html | tee switch.out
[ "$(grep -c 'switch .*: Ok' switch.out)" = 2 ]
[ "$(hops A-socks a.log)" = 1 ] && [ "$(hops A2-socks a2.log)" = 1 ] \
  || { echo "FAIL: switch hops A1=$(hops A-socks a.log) A2=$(hops A2-socks a2.log)" >&2; exit 1; }
echo "PASS: group switch -> new connection via A2, open one kept via A1"

kill "$a2_pid"; wait "$a2_pid" 2>/dev/null || true
: > b.log
if CHAIN_SELECT=fronts=A2 "$PROBE" group.dae B 127.0.0.4:18080 /index.html; then
  echo "FAIL: dial succeeded with the selected front down" >&2; exit 1
fi
if grep -q 'inbound connection' b.log; then
  echo "FAIL: landing node reached without the selected front" >&2; exit 1
fi
echo "PASS: selected group front down -> dial fails, no bypass"

# UDP through the chain. T is a trojan landing (UDP framed inside its TCP
# stream, so the front only has to carry TCP); its front is A, then the
# selector group. A UDP echo server stands in for DNS/QUIC; the 1350-byte
# datagram is QUIC Initial sized. B (shadowsocks) needs native UDP to its
# server, which the front cannot relay, so it must be refused, never direct.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj /CN=localhost -keyout t.key -out t.crt 2>/dev/null
cat > t.json <<JSON
{"log":{"level":"debug","output":"$WORK/t.log"},
 "inbounds":[{"type":"trojan","tag":"T-trojan","listen":"127.0.0.6","listen_port":24443,
   "users":[{"password":"chainpw"}],
   "tls":{"enabled":true,"server_name":"localhost","certificate_path":"$WORK/t.crt","key_path":"$WORK/t.key"}}],
 "outbounds":[{"type":"direct","tag":"T-direct"}]}
JSON
cat > udp_echo.py <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.4", 15353))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)
PY
cat > udp.dae <<'DAE'
node {
    A1: 'socks5://127.0.0.2:21080'
    A2: 'socks5://127.0.0.5:21081'
    T: 'trojan://chainpw@127.0.0.6:24443?sni=localhost&allowInsecure=1&dialer-proxy=A1#T'
    B: 'ss://YWVzLTEyOC1nY206Y2hhaW5wdw@127.0.0.3:28388?dialer-proxy=A1#B'
}
DAE
cat > udpg.dae <<'DAE'
node {
    A1: 'socks5://127.0.0.2:21080'
    A2: 'socks5://127.0.0.5:21081'
    TG: 'trojan://chainpw@127.0.0.6:24443?sni=localhost&allowInsecure=1&dialer-proxy=fronts#TG'
}
group {
    fronts {
        filter: name(A1, A2)
        policy: selector
    }
}
DAE
: > t.log
./sing-box run -c t.json > t.out 2>&1 & t_pid=$!; pids+=("$t_pid")
python3 udp_echo.py > udp_echo.log 2>&1 & pids+=($!)
./sing-box run -c a2.json > a2.out 2>&1 & a2_pid=$!; pids+=("$a2_pid")
sleep 1
thops() { grep -c "$1.*inbound connection to 127.0.0.6:24443" "$2" || true; }
udp_seen() { grep -q 'T-trojan.*inbound packet connection to 127.0.0.4:15353' t.log; }

: > a.log; : > t.log
"$PROBE" udp.dae T 127.0.0.4:15353 --udp 32 1350 | tee udp.out
[ "$(grep -c 'udp echo: Ok' udp.out)" = 2 ]
[ "$(thops A-socks a.log)" -ge 1 ] || { echo "FAIL: UDP did not ride A" >&2; exit 1; }
udp_seen || { echo "FAIL: T did not relay the UDP target" >&2; exit 1; }
echo "PASS: UDP (32B + 1350B QUIC-sized) reached via A -> T"

for pick in A1 A2; do
  : > a.log; : > a2.log; : > t.log
  CHAIN_SELECT=fronts=$pick "$PROBE" udpg.dae TG 127.0.0.4:15353 --udp 64 | tee udp.out
  grep -q 'udp echo: Ok' udp.out
  if [ "$pick" = A1 ]; then on=$(thops A-socks a.log); off=$(thops A2-socks a2.log)
  else on=$(thops A2-socks a2.log); off=$(thops A-socks a.log); fi
  [ "$on" -ge 1 ] && [ "$off" = 0 ] || { echo "FAIL: UDP select $pick -> on=$on off=$off" >&2; exit 1; }
  udp_seen
  echo "PASS: UDP via group front $pick -> T"
done

: > b.log
if "$PROBE" udp.dae B 127.0.0.4:15353 --udp 2> udp_ss.err; then
  echo "FAIL: native-UDP landing B accepted UDP through a front" >&2; exit 1
fi
grep -q 'native UDP' udp_ss.err || { cat udp_ss.err >&2; echo "FAIL: unclear refusal" >&2; exit 1; }
if grep -q 'packet' b.log; then echo "FAIL: B got UDP directly" >&2; exit 1; fi
echo "PASS: ss landing UDP through a front -> clear refusal, nothing sent"

kill "$a_pid"; wait "$a_pid" 2>/dev/null || true
: > t.log
if "$PROBE" udp.dae T 127.0.0.4:15353 --udp; then
  echo "FAIL: UDP succeeded with the front down" >&2; exit 1
fi
if grep -q 'inbound' t.log; then echo "FAIL: T reached without the front" >&2; exit 1; fi
echo "PASS: front down -> UDP fails, no bypass"

# dae `->` chain syntax: left = landing, right = relay dialed first, so
# C rides A -> B -> T -> target. Each hop must show up in the next hop's log.
./sing-box run -c a.json > a.out 2>&1 & a_pid=$!; pids+=("$a_pid")
sleep 1
cat > arrow.dae <<'DAE'
node {
    C: 'trojan://chainpw@127.0.0.6:24443?sni=localhost&allowInsecure=1#C -> ss://YWVzLTEyOC1nY206Y2hhaW5wdw@127.0.0.3:28388 -> socks5://127.0.0.2:21080'
}
DAE
arrow_hops() {
  grep -q 'A-socks.*inbound connection to 127.0.0.3:28388' a.log \
    || { echo "FAIL: A did not dial B" >&2; exit 1; }
  grep -q 'B-ss.*inbound connection to 127.0.0.6:24443' b.log \
    || { echo "FAIL: B did not dial T" >&2; exit 1; }
}
: > a.log; : > b.log; : > t.log
"$PROBE" arrow.dae C 127.0.0.4:18080 /index.html | tee probe.out
grep -q hello-through-chain probe.out
arrow_hops
grep -q 'T-trojan.*inbound connection to 127.0.0.4:18080' t.log \
  || { echo "FAIL: T did not reach the target" >&2; exit 1; }
echo "PASS: '->' chain TCP via A -> B -> T"

: > a.log; : > b.log; : > t.log
"$PROBE" arrow.dae C 127.0.0.4:15353 --udp 64 | tee udp.out
grep -q 'udp echo: Ok' udp.out
arrow_hops
udp_seen || { echo "FAIL: T did not relay UDP" >&2; exit 1; }
echo "PASS: '->' chain UDP via A -> B -> T"

kill "$b_pid"; wait "$b_pid" 2>/dev/null || true
: > t.log
if "$PROBE" arrow.dae C 127.0.0.4:18080 /index.html; then
  echo "FAIL: '->' chain succeeded with the middle hop down" >&2; exit 1
fi
if grep -q 'inbound' t.log; then echo "FAIL: T reached without B" >&2; exit 1; fi
echo "PASS: '->' middle hop down -> fails, no bypass"
