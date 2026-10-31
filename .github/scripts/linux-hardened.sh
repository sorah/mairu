#!/usr/bin/env bash
# Integration checks for a hardened Linux host: classification, peer verification both ways, unverified-agent
# replacement, the platform helper, authorization through polkit and pkttyagent, re-exec and `mairu harden` itself.
# Runs as a user with passwordless sudo, after `cargo build`.
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

echo "--- authorization through polkit"
check "polkit actions installed" test -f /usr/share/polkit-1/actions/co.0w0.mairu.policy
# No credential server: a request that passes authorization stops at "log in".
mkdir -p ~/.config/mairu/servers.d
echo '{"id": "ci", "url": "https://ci.invalid/"}' >~/.config/mairu/servers.d/ci.json
rules=/etc/polkit-1/rules.d/49-mairu-test.rules
# CI only: answers co.0w0.mairu.* without a human. polkitd reloads rules on change.
set_rule() {
  sudo tee "$rules" >/dev/null <<EOF
polkit.addRule(function (action, subject) {
  if (action.id.indexOf("co.0w0.mairu.") === 0) {
    return polkit.Result.$1;
  }
});
EOF
  sleep 2
}
set_rule YES
capture "$hardened" credential-process ci 123456789012/CI
check "approved request reaches the credential server step" has "Authentication Needed" "$out"
capture "$hardened" doctor
check "approval remembered for this parent process, polkit usable" has "^authorization  grants=1 leases=0 methods=platform" "$out"
set_rule NO
capture "$hardened" credential-process ci 123456789012/CI
check "remembered approval is reused without asking" has "Authentication Needed" "$out"
capture "$hardened" credential-process ci 123456789012/Other
check "another role asks, and is denied" has "authorization was denied" "$out"
capture "$hardened" lock
check "lock revokes the grant" has "Revoked 1 grant(s) and 0 lease(s)" "$out"
capture "$hardened" credential-process ci 123456789012/CI
check "after lock the role asks again" has "authorization was denied" "$out"
sudo rm -f "$rules"
sleep 2

echo "--- password prompt through pkttyagent"
# polkit's defaults ask for the user's password, and no authentication agent covers a CI process: the client
# registers pkttyagent on its terminal. expect provides the terminal and types the password.
password="mairu-ci-$RANDOM$RANDOM"
echo "$(id -un):$password" | sudo chpasswd
prompt_exp="$(mktemp)"
cat >"$prompt_exp" <<'EOF'
set timeout 30
spawn {*}$argv
expect {
  "Password:" { sleep 0.5; send "$env(PW)\r"; exp_continue }
  eof
}
EOF
capture env PW="$password" expect "$prompt_exp" "$hardened" credential-process ci 123456789012/Tty
check "the client prints the context and asks for the password" has "Enter your password below" "$out"
check "the prompt is polkit's text agent" has "AUTHENTICATING FOR co.0w0.mairu.assume-role" "$out"
check "right password: approved" has "Authentication Needed" "$out"
# shellcheck disable=SC2016
check "pkttyagent is gone afterwards" bash -c '! pgrep -u "$(id -u)" -x pkttyagent'
capture env PW=wrong-password expect "$prompt_exp" "$hardened" credential-process ci 123456789012/TtyWrong
check "wrong password: denied" has "authorization was denied" "$out"
capture setsid -w "$hardened" credential-process ci 123456789012/NoTty </dev/null
check "no terminal: refused with guidance" has "no terminal to ask for a password on" "$out"
rm -f "$prompt_exp"
rm -f ~/.config/mairu/servers.d/ci.json
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
