#!/usr/bin/env bash
# End-to-end check of node-level chained dialing (`dialer-proxy`) against two
# real sing-box servers on loopback: A (socks5) is the front, B (shadowsocks)
# the landing node. Proves the A -> B -> target hops from the servers' access
# logs, then stops A and checks the chained dial fails instead of bypassing A.
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
./sing-box run -c b.json > b.out 2>&1 & pids+=($!)
python3 -m http.server 18080 --bind 127.0.0.4 --directory www > http.log 2>&1 & pids+=($!)
sleep 1

(cd "$ROOT" && cargo build -q -p honk-outbound --example chain_probe)
PROBE="$ROOT/target/debug/examples/chain_probe"

"$PROBE" nodes.dae B 127.0.0.4:18080 /index.html | tee probe.out
grep -q hello-through-chain probe.out
grep -q 'A-socks.*inbound connection to 127.0.0.3:28388' a.log
grep -q 'B-ss.*inbound connection to 127.0.0.4:18080' b.log
echo "PASS: target reached via A -> B"

kill "$a_pid"; wait "$a_pid" 2>/dev/null || true
: > b.log
if "$PROBE" nodes.dae B 127.0.0.4:18080 /index.html; then
  echo "FAIL: dial succeeded with the front down" >&2; exit 1
fi
if grep -q 'inbound connection' b.log; then
  echo "FAIL: landing node reached without the front" >&2; exit 1
fi
echo "PASS: front down -> dial fails, no bypass"
