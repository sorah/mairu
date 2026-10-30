#!/usr/bin/env bash
# Integration checks for a hardened Linux host: classification, peer verification both ways, unverified-agent
# replacement, the platform helper, re-exec and `mairu harden` itself. Runs as a user with passwordless sudo, after
# `cargo build`.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

failures=0
check() { local d="$1"; shift; if "$@"; then echo "PASS: $d"; else echo "FAIL: $d"; failures=$((failures + 1)); fi; }
has() { grep -q -- "$1" <<<"$2"; }
# Through a file: an auto-spawned agent inherits stderr and would keep a $(...) pipe open.
capture() { local f; f="$(mktemp)"; "$@" >"$f" 2>&1; rc=$?; out="$(cat "$f")"; rm -f "$f"; echo "$out"; }

dev=./target/debug/mairu
hardened=/usr/local/libexec/mairu/mairu
# /opt is world-writable on GitHub runners, which harden refuses.
scratch=/usr/local/mairu-ci

echo "--- harden"
capture sudo "$dev" harden
check "harden succeeds" test "$rc" -eq 0
check "hardened copy root:mairu 2755" test "$(stat -c '%U:%G %a' "$hardened")" = "root:mairu 2755"
check "state directory root:mairu 2770" test "$(sudo stat -c '%U:%G %a' /var/lib/mairu)" = "root:mairu 2770"

echo "--- classification"
capture "$hardened" doctor
check "hardened copy classifies as hardened" has "^client   hardened" "$out"
capture "$dev" doctor
check "debug build in the dev profile stays unhardened" has "^client   unhardened" "$out"

echo "--- re-exec"
capture env MAIRU_PROFILE=default "$dev" doctor
check "user copy re-execs the hardened copy" has "^client   hardened  $hardened" "$out"
capture env MAIRU_PROFILE=default MAIRU_NO_HARDENED_REEXEC=1 "$dev" doctor
check "MAIRU_NO_HARDENED_REEXEC=1 stays unhardened" has "^client   unhardened" "$out"

echo "--- unverified-agent replacement and peer verification"
"$hardened" kill-agent >/dev/null 2>&1
capture "$dev" agent --daemonize
sleep 1
capture "$hardened" list-sessions
check "hardened client replaces an unhardened agent" has "Replacing an agent that is not hardened" "$out"
capture "$hardened" doctor
# shellcheck disable=SC2016
check "agent is hardened and verified" bash -c 'grep "^agent    hardened" <<<"$1" | grep -q " verified$"' _ "$out"
check "caller verified" has "^caller   verified" "$out"
check "platform helper running and verified" has "^helper   running pid=[0-9]* verified" "$out"

echo "--- platform helper"
helper="$(pgrep -u "$(id -u)" -f 'platform-helper --fd' | head -n1)"
check "helper holds the marker only as saved gid" test "$(awk '/^Gid:/ {print $3, $4}' "/proc/$helper/status")" = "$(id -g) $(getent group mairu | cut -d: -f3)"
capture "$hardened" platform-helper --fd 0 </dev/null
check "helper started by hand refuses" test "$rc" -eq 3
kill -KILL "$helper"
sleep 0.5
capture "$hardened" doctor
check "killed helper fails closed" has "^helper   unavailable: helper-unavailable" "$out"
for _ in $(seq 1 80); do
  capture "$hardened" doctor >/dev/null
  grep -q "^helper   running pid=" <<<"$out" && break
  sleep 0.5
done
check "helper respawned" has "^helper   running pid=[0-9]* verified" "$out"
capture "$dev" list-sessions
check "hardened agent refuses an unhardened client" has "the agent refused this request" "$out"
"$hardened" kill-agent >/dev/null 2>&1

echo "--- harden in a scratch home"
capture sudo "$dev" harden --home "$scratch"
check "fresh install" test -x "$scratch/libexec/mairu/mairu" -a -f "$scratch/libexec/mairu/.harden-manifest"
capture sudo "$dev" harden --home "$scratch"
check "re-run" test "$rc" -eq 0
capture sudo "$dev" harden --uninstall --home "$scratch"
check "uninstall" test ! -e "$scratch/libexec/mairu"
capture sudo "$dev" harden --uninstall --purge
check "uninstall --purge" bash -c 'test ! -e /usr/local/libexec/mairu && ! sudo test -e /var/lib/mairu'
check "group left in place" getent group mairu

echo "== $failures failure(s)"
[[ $failures -eq 0 ]]
