#!/usr/bin/env bash
# End-to-end check of node-level chained dialing (`dialer-proxy`) against two
# real sing-box servers on loopback: A (socks5) is the front, B (shadowsocks)
# the landing node. Proves the A -> B -> target hops from the servers' access
# logs, runs the group health-check probe path the same way, then stops A and
# checks both fail instead of bypassing A, and that the health check recovers
# once A is back. Finally B's front becomes a selector group of A1/A2:
# the selected member carries each new connection, a switch moves new
# connections only, and a down selected member fails closed. Last, UDP
# rides a trojan landing through A and through the group; ss/socks5
# landings carry native UDP over socks5, ss, trojan, nested and group fronts,
# a vless front is refused for UDP, and UDP fails closed with A down.
# Finally the same chain is imported from sing-box JSON (`detour`) and Clash
# YAML (`dialer-proxy`, via a group), and written with dae bare-name hops.
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

(cd "$ROOT" && cargo build -q -p honk-outbound --features rprx --example chain_probe)
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
# datagram is QUIC Initial sized.
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

# Native-UDP landings: B (shadowsocks) and S (socks5) send their own UDP
# datagrams through the front's UDP relay (socks5 UDP ASSOCIATE, ss UDP,
# trojan UDP-over-TCP, vless UDP, nested chains, groups); nothing is ever
# sent direct.
cat > s.json <<JSON
{"log":{"level":"debug","output":"$WORK/s.log"},
 "inbounds":[{"type":"socks","tag":"S-socks","listen":"127.0.0.7","listen_port":21082}],
 "outbounds":[{"type":"direct","tag":"S-direct"}]}
JSON
cat > v.json <<JSON
{"log":{"level":"debug","output":"$WORK/v.log"},
 "inbounds":[{"type":"vless","tag":"V-vless","listen":"127.0.0.8","listen_port":24444,
   "users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}],
 "outbounds":[{"type":"direct","tag":"V-direct"}]}
JSON
: > s.log; : > v.log
./sing-box run -c s.json > s.out 2>&1 & pids+=($!)
./sing-box run -c v.json > v.out 2>&1 & pids+=($!)
sleep 1
SS='ss://YWVzLTEyOC1nY206Y2hhaW5wdw@127.0.0.3:28388'
nudp() { local name=$1; shift; printf 'node {\n' > "$name.dae"; printf '    %s\n' "$@" >> "$name.dae"; printf '}\n' >> "$name.dae"; }
nudp ba "A1: 'socks5://127.0.0.2:21080'" "B: '$SS?dialer-proxy=A1#B'"
nudp sb "B0: '$SS#B0'" "S: 'socks5://127.0.0.7:21082?dialer-proxy=B0#S'"
nudp bt "T: 'trojan://chainpw@127.0.0.6:24443?sni=localhost&allowInsecure=1#T'" "B: '$SS?dialer-proxy=T#B'"
nudp bn "A1: 'socks5://127.0.0.2:21080'" "S: 'socks5://127.0.0.7:21082?dialer-proxy=A1#S'" "B: '$SS?dialer-proxy=S#B'"
nudp bv "V: 'vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.8:24444?type=tcp&security=none#V'" "B: '$SS?dialer-proxy=V#B'"
nudp bg "A1: 'socks5://127.0.0.2:21080'" "A2: 'socks5://127.0.0.5:21081'" "B: '$SS?dialer-proxy=fronts#B'"
printf 'group {\n    fronts {\n        filter: name(A1, A2)\n        policy: selector\n    }\n}\n' >> bg.dae
pkt() { grep -q "$1.*inbound packet connection to $2" "$3" || { echo "FAIL: no $1 packet hop to $2" >&2; exit 1; }; }
nopkt() { if grep -q "$1.*packet" "$2"; then echo "FAIL: $1 saw UDP it must not" >&2; exit 1; fi; }
echo_ok() { [ "$(grep -c 'udp echo: Ok' udp.out)" = "$1" ] || { echo "FAIL: udp echo count" >&2; exit 1; }; }
E=127.0.0.4:15353
clr() { : > a.log; : > a2.log; : > b.log; : > s.log; : > t.log; : > v.log; }

clr; "$PROBE" ba.dae B $E --udp 32 1350 | tee udp.out; echo_ok 2
pkt A-socks 127.0.0.3:28388 a.log; pkt B-ss $E b.log
echo "PASS: ss landing UDP (32B + 1350B) via socks5 front A"
clr; "$PROBE" sb.dae S $E --udp 64 | tee udp.out; echo_ok 1
pkt B-ss 127.0.0.7 b.log; pkt S-socks $E s.log
echo "PASS: socks5 landing UDP via ss front B0"
clr; "$PROBE" bt.dae B $E --udp 64 1350 | tee udp.out; echo_ok 2
pkt T-trojan 127.0.0.3:28388 t.log; pkt B-ss $E b.log
echo "PASS: ss landing UDP via trojan front T (UDP-over-TCP)"
clr; "$PROBE" bn.dae B $E --udp 64 | tee udp.out; echo_ok 1
pkt A-socks 127.0.0.7 a.log; pkt S-socks 127.0.0.3:28388 s.log; pkt B-ss $E b.log
echo "PASS: nested UDP A -> S -> B"
for pick in A1 A2; do
  clr; CHAIN_SELECT=fronts=$pick "$PROBE" bg.dae B $E --udp 64 | tee udp.out; echo_ok 1
  if [ $pick = A1 ]; then pkt A-socks 127.0.0.3 a.log; nopkt A2-socks a2.log
  else pkt A2-socks 127.0.0.3 a2.log; nopkt A-socks a.log; fi
  pkt B-ss $E b.log
  echo "PASS: ss landing UDP via group front $pick"
done
clr
"$PROBE" bv.dae B $E --udp 64 1350 | tee udp.out; echo_ok 2
pkt V-vless 127.0.0.3:28388 v.log; pkt B-ss $E b.log
echo "PASS: ss landing UDP via vless front V"
kill "$a_pid"; wait "$a_pid" 2>/dev/null || true
clr
if "$PROBE" ba.dae B $E --udp 2> udp_down.err; then echo "FAIL: ss UDP with front down" >&2; exit 1; fi
grep -q detour udp_down.err || { cat udp_down.err >&2; echo "FAIL: unclear front-down error" >&2; exit 1; }
nopkt B-ss b.log
echo "PASS: front down -> ss landing UDP fails closed"
./sing-box run -c a.json > a.out 2>&1 & a_pid=$!; pids+=("$a_pid")
sleep 1

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

# Imported chains: the same A -> B -> T chain from a sing-box JSON
# subscription (`detour` by tag) and a Clash YAML one (`dialer-proxy`, the
# middle hop naming a selector group from the local config), run through the
# real importer (honk-core example import_nodes), then a dae entry whose hops
# are bare names of existing nodes. Each hop must show up in the next hop's log.
./sing-box run -c b.json > b.out 2>&1 & b_pid=$!; pids+=("$b_pid")
sleep 1
(cd "$ROOT" && cargo build -q -p honk-core --example import_nodes)
IMPORT="$ROOT/target/debug/examples/import_nodes"
cat > sub-singbox.json <<'JSON'
{"outbounds":[
 {"type":"trojan","tag":"SC","server":"127.0.0.6","server_port":24443,"password":"chainpw",
  "tls":{"enabled":true,"server_name":"localhost","insecure":true},"detour":"SB"},
 {"type":"shadowsocks","tag":"SB","server":"127.0.0.3","server_port":28388,"method":"aes-128-gcm","password":"chainpw","detour":"SA"},
 {"type":"socks","tag":"SA","server":"127.0.0.2","server_port":21080},
 {"type":"selector","tag":"proxy","outbounds":["SC"]}
]}
JSON
cat > sub-clash.yaml <<'YAML'
proxies:
  - {name: KC, type: trojan, server: 127.0.0.6, port: 24443, password: chainpw, sni: localhost, skip-cert-verify: true, dialer-proxy: KB}
  - {name: KB, type: ss, server: 127.0.0.3, port: 28388, cipher: aes-128-gcm, password: chainpw, dialer-proxy: kfronts}
proxy-groups:
  - {name: kfronts, type: select, proxies: [KB]}
YAML
cat > kgroups.dae <<'DAE'
node {
    KA: 'socks5://127.0.0.2:21080'
}
group {
    kfronts {
        filter: name(KA)
        policy: selector
    }
}
DAE
"$IMPORT" auto sub-singbox.json > sub-singbox.nodes.json
"$IMPORT" clash sub-clash.yaml > sub-clash.nodes.json
imported() { # label, probe args...
  local label=$1; shift
  : > a.log; : > b.log; : > t.log
  "$@" 127.0.0.4:18080 /index.html | tee probe.out
  grep -q hello-through-chain probe.out
  arrow_hops
  grep -q 'T-trojan.*inbound connection to 127.0.0.4:18080' t.log \
    || { echo "FAIL: $label: T did not reach the target" >&2; exit 1; }
  echo "PASS: $label chain via A -> B -> T"
}
imported "imported sing-box JSON (detour)" "$PROBE" sub-singbox.nodes.json SC
CHAIN_GROUPS=kgroups.dae imported "imported Clash YAML (dialer-proxy -> group)" \
  "$PROBE" sub-clash.nodes.json KC
cat > names.dae <<'DAE'
node {
    NA: 'socks5://127.0.0.2:21080'
    NB: 'ss://YWVzLTEyOC1nY206Y2hhaW5wdw@127.0.0.3:28388'
    NC: 'trojan://chainpw@127.0.0.6:24443?sni=localhost&allowInsecure=1'
    'NC -> NB'
    NB: 'NB -> nfronts'
}
group {
    nfronts {
        filter: name(NA)
        policy: selector
    }
}
DAE
imported "dae bare-name hops (node -> node -> group)" "$PROBE" names.dae NC
# Subscription lines `name -> front`: plain share links plus bare-name
# declarations (one later than the node it chains), imported as a URI list.
cat > sub-names.txt <<'TXT'
UC -> UB
trojan://chainpw@127.0.0.6:24443?sni=localhost&allowInsecure=1#UC
ss://YWVzLTEyOC1nY206Y2hhaW5wdw@127.0.0.3:28388#UB
socks5://127.0.0.2:21080#UA
UB -> UA
TXT
"$IMPORT" auto sub-names.txt > sub-names.nodes.json
imported "subscription bare-name lines (UC -> UB -> UA)" "$PROBE" sub-names.nodes.json UC
# HTTP CONNECT outbound: H (plain http, basic auth) and HS (https over TLS).
# As a front it carries a landing's TCP; as a landing it rides a front. It
# has no UDP path, so UDP through it must be refused, never sent direct.
cat > h.json <<JSON
{"log":{"level":"debug","output":"$WORK/h.log"},
 "inbounds":[
  {"type":"http","tag":"H-http","listen":"127.0.0.9","listen_port":28080,"users":[{"username":"hu","password":"hp"}]},
  {"type":"http","tag":"HS-https","listen":"127.0.0.10","listen_port":28443,
   "tls":{"enabled":true,"server_name":"localhost","certificate_path":"$WORK/t.crt","key_path":"$WORK/t.key"}}],
 "outbounds":[{"type":"direct","tag":"H-direct"}]}
JSON
: > h.log
./sing-box run -c h.json > h.out 2>&1 & pids+=($!)
sleep 1
SSU='ss://YWVzLTEyOC1nY206Y2hhaW5wdw@127.0.0.3:28388'
nudp hb "H: 'http://hu:hp@127.0.0.9:28080'" "B: '$SSU?dialer-proxy=H#B'"
nudp ah "A: 'socks5://127.0.0.2:21080'" "HS: 'https://127.0.0.10:28443?sni=localhost&allowInsecure=1&dialer-proxy=A#HS'"
nudp hsh "HS: 'https://127.0.0.10:28443?sni=localhost&allowInsecure=1#HS'" "H: 'http://hu:hp@127.0.0.9:28080?dialer-proxy=HS#H'"
nudp hbad "H: 'http://hu:wrong@127.0.0.9:28080'" "B: '$SSU?dialer-proxy=H#B'"
: > a.log; : > b.log; : > h.log
"$PROBE" hb.dae B 127.0.0.4:18080 /index.html | tee probe.out; grep -q hello-through-chain probe.out
grep -q 'H-http.*inbound connection to 127.0.0.3:28388' h.log && grep -q 'B-ss.*inbound connection to 127.0.0.4:18080' b.log \
  || { echo "FAIL: http front" >&2; exit 1; }
echo "PASS: ss landing via http front H (basic auth)"
: > a.log; : > h.log
"$PROBE" ah.dae HS 127.0.0.4:18080 /index.html | tee probe.out; grep -q hello-through-chain probe.out
grep -q 'A-socks.*inbound connection to 127.0.0.10:28443' a.log && grep -q 'HS-https.*inbound connection to 127.0.0.4:18080' h.log \
  || { echo "FAIL: https landing" >&2; exit 1; }
echo "PASS: https landing HS via socks5 front A"
: > h.log
"$PROBE" hsh.dae H 127.0.0.4:18080 /index.html | tee probe.out; grep -q hello-through-chain probe.out
grep -q 'HS-https.*inbound connection to 127.0.0.9:28080' h.log && grep -q 'H-http.*inbound connection to 127.0.0.4:18080' h.log \
  || { echo "FAIL: http over https" >&2; exit 1; }
echo "PASS: http landing H via https front HS"
: > b.log
if "$PROBE" hbad.dae B 127.0.0.4:18080 /index.html > probe.out 2>&1 && grep -q hello-through-chain probe.out; then
  echo "FAIL: wrong http credentials accepted" >&2; exit 1; fi
if grep -q 'B-ss.*inbound connection' b.log; then echo "FAIL: bad-auth front leaked to B" >&2; exit 1; fi
echo "PASS: http front with wrong credentials refused"
: > b.log; : > h.log
"$PROBE" hb.dae B $E --udp 64 > udp.out 2>&1 || true
if grep -q 'udp echo: Ok' udp.out || grep -q 'B-ss.*packet' b.log; then
  echo "FAIL: UDP went through/around http front" >&2; exit 1; fi
echo "PASS: UDP via http front refused (no bypass)"
cat > sub-http.yaml <<'YAML'
proxies:
  - {name: KH, type: http, server: 127.0.0.9, port: 28080, username: hu, password: hp}
  - {name: KHS, type: http, server: 127.0.0.10, port: 28443, tls: true, sni: localhost, skip-cert-verify: true, dialer-proxy: KH}
YAML
cat > sub-http.json <<'JSON'
{"outbounds":[
 {"type":"http","tag":"JHS","server":"127.0.0.10","server_port":28443,
  "tls":{"enabled":true,"server_name":"localhost","insecure":true},"detour":"JH"},
 {"type":"http","tag":"JH","server":"127.0.0.9","server_port":28080,"username":"hu","password":"hp"}
]}
JSON
"$IMPORT" clash sub-http.yaml > sub-http.clash.json
"$IMPORT" auto sub-http.json > sub-http.sb.json
for pair in "sub-http.clash.json KHS" "sub-http.sb.json JHS"; do
  set -- $pair; : > h.log
  "$PROBE" "$1" "$2" 127.0.0.4:18080 /index.html | tee probe.out; grep -q hello-through-chain probe.out
  grep -q 'H-http.*inbound connection to 127.0.0.10:28443' h.log && grep -q 'HS-https.*inbound connection to 127.0.0.4:18080' h.log \
    || { echo "FAIL: imported http chain $1" >&2; exit 1; }
  echo "PASS: imported http/https chain ($1)"
done
# QUIC landings behind fronts: Q (hysteria2), QO (hysteria2 + salamander) and
# U (tuic) reach their server only through the front's UDP relay (socks5 UDP
# ASSOCIATE, ss UDP, trojan UDP-over-TCP, nested and group fronts). TCP and
# UDP both ride QUIC. An http front has no UDP path: refused, nothing sent.
cat > q.json <<JSON
{"log":{"level":"debug","output":"$WORK/q.log"},
 "inbounds":[
  {"type":"hysteria2","tag":"Q-hy2","listen":"127.0.0.11","listen_port":24600,"users":[{"password":"hy2pw"}],
   "tls":{"enabled":true,"server_name":"localhost","alpn":["h3"],"certificate_path":"$WORK/t.crt","key_path":"$WORK/t.key"}},
  {"type":"hysteria2","tag":"QO-hy2","listen":"127.0.0.11","listen_port":24601,"users":[{"password":"hy2pw"}],
   "obfs":{"type":"salamander","password":"salamander-secret"},
   "tls":{"enabled":true,"server_name":"localhost","alpn":["h3"],"certificate_path":"$WORK/t.crt","key_path":"$WORK/t.key"}},
  {"type":"tuic","tag":"U-tuic","listen":"127.0.0.12","listen_port":24602,
   "users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","password":"tuicpw"}],"congestion_control":"bbr",
   "tls":{"enabled":true,"server_name":"localhost","alpn":["h3"],"certificate_path":"$WORK/t.crt","key_path":"$WORK/t.key"}}],
 "outbounds":[{"type":"direct","tag":"Q-direct"}]}
JSON
: > q.log
./sing-box run -c q.json > q.out 2>&1 & pids+=($!)
sleep 1
HY="hysteria2://hy2pw@127.0.0.11:24600?sni=localhost&insecure=1"
HYO="hysteria2://hy2pw@127.0.0.11:24601?sni=localhost&insecure=1&obfs=salamander&obfs-password=salamander-secret"
TU="tuic://b831381d-6324-4d53-ad4f-8cda48b30811:tuicpw@127.0.0.12:24602?sni=localhost&alpn=h3&congestion_control=bbr&allow_insecure=1"
nudp qa "A1: 'socks5://127.0.0.2:21080'" "Q: '$HY&dialer-proxy=A1#Q'"
nudp qob "B0: '$SSU#B0'" "QO: '$HYO&dialer-proxy=B0#QO'"
nudp ut "T: 'trojan://chainpw@127.0.0.6:24443?sni=localhost&allowInsecure=1#T'" "U: '$TU&dialer-proxy=T#U'"
nudp qn "A1: 'socks5://127.0.0.2:21080'" "S: 'socks5://127.0.0.7:21082?dialer-proxy=A1#S'" "Q: '$HY&dialer-proxy=S#Q'"
nudp qg "A1: 'socks5://127.0.0.2:21080'" "A2: 'socks5://127.0.0.5:21081'" "U: '$TU&dialer-proxy=fronts#U'"
printf 'group {\n    fronts {\n        filter: name(A1, A2)\n        policy: selector\n    }\n}\n' >> qg.dae
nudp qh "H: 'http://hu:hp@127.0.0.9:28080'" "Q: '$HY&dialer-proxy=H#Q'"
nudp bq "Q: '$HY#Q'" "B: '$SSU?dialer-proxy=Q#B'"
qclr() { clr; : > q.log; : > h.log; }
quic_case() { # label dae node front-tag front-log quic-tag quic-server
  qclr
  "$PROBE" "$2.dae" "$3" 127.0.0.4:18080 /index.html | tee probe.out; grep -q hello-through-chain probe.out \
    || { echo "FAIL: $1 TCP" >&2; exit 1; }
  "$PROBE" "$2.dae" "$3" $E --udp 64 1200 | tee udp.out; echo_ok 2
  pkt "$4" "$7" "$5"
  grep -q "$6.*inbound connection to 127.0.0.4:18080" q.log || { echo "FAIL: $1 no QUIC TCP hop" >&2; exit 1; }
  pkt "$6" $E q.log
  echo "PASS: $1 (TCP + UDP over QUIC via front)"
}
quic_case "hysteria2 landing via socks5 front" qa Q A-socks a.log Q-hy2 127.0.0.11:24600
quic_case "hysteria2+salamander landing via ss front" qob QO B-ss b.log QO-hy2 127.0.0.11:24601
quic_case "tuic landing via trojan front (UoT)" ut U T-trojan t.log U-tuic 127.0.0.12:24602
quic_case "hysteria2 landing via nested A1 -> S" qn Q S-socks s.log Q-hy2 127.0.0.11:24600
grep -q 'A-socks.*packet connection to 127.0.0.7' a.log || { echo "FAIL: nested QUIC skipped A1" >&2; exit 1; }
for pick in A1 A2; do
  qclr; CHAIN_SELECT=fronts=$pick "$PROBE" qg.dae U $E --udp 64 | tee udp.out; echo_ok 1
  if [ $pick = A1 ]; then pkt A-socks 127.0.0.12:24602 a.log; nopkt A2-socks a2.log
  else pkt A2-socks 127.0.0.12:24602 a2.log; nopkt A-socks a.log; fi
  pkt U-tuic $E q.log
  echo "PASS: tuic landing via group front $pick"
done
qclr
if "$PROBE" qh.dae Q 127.0.0.4:18080 /index.html > qh.out 2>&1 && grep -q hello-through-chain qh.out; then
  echo "FAIL: QUIC landing through http front" >&2; exit 1; fi
grep -q 'cannot relay UDP' qh.out || { cat qh.out >&2; echo "FAIL: unclear http-front QUIC refusal" >&2; exit 1; }
if grep -q 'inbound' q.log; then echo "FAIL: QUIC landing reached without a UDP front" >&2; exit 1; fi
echo "PASS: QUIC landing via http front -> clear refusal, nothing sent"
qclr
"$PROBE" bq.dae B 127.0.0.4:18080 /index.html | tee probe.out; grep -q hello-through-chain probe.out
grep -q 'Q-hy2.*inbound connection to 127.0.0.3:28388' q.log || { echo "FAIL: hy2 front" >&2; exit 1; }
echo "PASS: ss landing via hysteria2 front (regression)"
nudp qm "A1: 'socks5://127.0.0.2:21080'" "Q: '$HY&mport=24600-24605&dialer-proxy=A1#Q'"
qclr
if "$PROBE" qm.dae Q 127.0.0.4:18080 /index.html > qm.out 2>&1; then echo "FAIL: port hopping chained" >&2; exit 1; fi
if grep -q 'inbound' q.log; then echo "FAIL: hopping hy2 reached" >&2; exit 1; fi
echo "PASS: hysteria2 port hopping behind a front refused"

# VLESS landings carry UDP inside the chained stream (native UDP command,
# single XUDP, UoT v2), so any TCP-capable front works.
VL='vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.8:24444?type=tcp&security=none'
for enc in none xudp uot-v2; do
  nudp "vl_$enc" "A1: 'socks5://127.0.0.2:21080'" "VL: '$VL&packetEncoding=$enc&dialer-proxy=A1#VL'"
  clr; "$PROBE" "vl_$enc.dae" VL $E --udp 64 1350 | tee udp.out; echo_ok 2
  grep -q 'A-socks.*inbound connection to 127.0.0.8:24444' a.log || { echo "FAIL: vless $enc skipped A1" >&2; exit 1; }
  nopkt A-socks a.log
  grep -q "V-vless.*$E" v.log || { echo "FAIL: vless $enc no landing hop" >&2; exit 1; }
  echo "PASS: vless landing UDP ($enc) via socks5 front A1"
done
nudp vlh "H: 'http://hu:hp@127.0.0.9:28080#H'" "VL: '$VL&packetEncoding=none&dialer-proxy=H#VL'"
clr; : > h.log; "$PROBE" vlh.dae VL $E --udp 64 | tee udp.out; echo_ok 1
grep -q 'H-http.*127.0.0.8:24444' h.log || { echo "FAIL: vless UDP skipped http front" >&2; exit 1; }
echo "PASS: vless landing UDP via http front H (UDP inside the CONNECT stream)"
nudp vln "A1: 'socks5://127.0.0.2:21080'" "S: 'socks5://127.0.0.7:21082?dialer-proxy=A1#S'" "VL: '$VL&packetEncoding=xudp&dialer-proxy=S#VL'"
clr; "$PROBE" vln.dae VL $E --udp 64 | tee udp.out; echo_ok 1
grep -q 'A-socks.*inbound connection to 127.0.0.7' a.log && grep -q 'S-socks.*inbound connection to 127.0.0.8:24444' s.log \
  || { echo "FAIL: nested vless UDP hops" >&2; exit 1; }
echo "PASS: vless landing UDP via nested A1 -> S"
nudp vlg "A1: 'socks5://127.0.0.2:21080'" "A2: 'socks5://127.0.0.5:21081'" "VL: '$VL&dialer-proxy=fronts#VL'"
printf 'group {\n    fronts {\n        filter: name(A1, A2)\n        policy: selector\n    }\n}\n' >> vlg.dae
for pick in A1 A2; do
  clr; CHAIN_SELECT=fronts=$pick "$PROBE" vlg.dae VL $E --udp 64 | tee udp.out; echo_ok 1
  if [ $pick = A1 ]; then grep -q 'A-socks.*127.0.0.8' a.log; ! grep -q 127.0.0.8 a2.log
  else grep -q 'A2-socks.*127.0.0.8' a2.log; ! grep -q 127.0.0.8 a.log; fi
  echo "PASS: vless landing UDP via group front $pick"
done
