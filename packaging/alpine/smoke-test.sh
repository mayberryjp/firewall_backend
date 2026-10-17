#!/bin/sh
set -eu

fail() {
	echo "netcontrol package smoke test: $*" >&2
	if [ -f /var/log/netcontrold.log ]; then
		cat /var/log/netcontrold.log >&2
	fi
	exit 1
}

[ "${NETCONTROL_PACKAGE_SMOKE:-}" = 1 ] || fail "opt in only inside a disposable package-test container"
for tool in rc-service curl stat; do
	command -v "$tool" >/dev/null || fail "missing dependency: $tool"
done

trap 'rc-service netcontrold stop' EXIT
rc-service netcontrold start
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
	if curl --fail --silent --show-error --max-time 2 \
		http://127.0.0.1:8080/auth/status >/dev/null; then
		ready=1
		break
	fi
	sleep 1
done
[ "$ready" = 1 ] || fail "management listener did not become ready"
rc-service netcontrold status
code=$(curl --silent --show-error --max-time 2 -o /dev/null -w '%{http_code}' \
	http://127.0.0.1:8080/api/v1/state)
[ "$code" = 401 ] || fail "unconfigured networking API returned $code, expected 401"
for directory in /var/lib/netcontrol /etc/netcontrol/keys; do
	[ "$(stat -c '%a:%u:%g' "$directory")" = "700:0:0" ] || fail "unsafe directory: $directory"
done
[ -s /var/lib/netcontrol/credentials.db ] || fail "credential database missing"
rc-service netcontrold restart
curl --retry 10 --retry-connrefused --retry-delay 1 --max-time 2 \
	--fail --silent --show-error http://127.0.0.1:8080/auth/status >/dev/null
[ -s /var/lib/netcontrol/credentials.db ] || fail "restart lost credential database"
echo "APK install, OpenRC start/restart, HTTP and permission checks passed"
