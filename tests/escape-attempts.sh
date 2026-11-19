#!/bin/sh
# Escape-attempt integration tests for the multi-tenant guardrails:
# mount destination whitelist, network namespace policy, and combined
# resource limits. Requires Linux with usable user namespaces (or root).
# Run directly or through: make test-escape-attempts
set -u

nsjail_bin=${1:-./nsjail}
tests_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$(uname -s)" != Linux ]; then
	echo "SKIP: requires Linux"
	exit 77
fi
if [ "$(id -u)" -ne 0 ] && ! unshare --user --map-root-user true 2>/dev/null; then
	echo "SKIP: requires user namespaces"
	exit 77
fi

fails=0
pass() { echo "PASS: $1"; }
fail() {
	echo "FAIL: $1" >&2
	fails=$((fails + 1))
}

# expect_reject <desc> <cfg> <log-pattern>
expect_reject() {
	out=$(timeout 60 "$nsjail_bin" -C "$2" 2>&1)
	rc=$?
	if [ $rc -eq 124 ]; then
		fail "$1: nsjail timed out"
		return
	fi
	if [ $rc -eq 0 ]; then
		fail "$1: jail started successfully, expected rejection"
		return
	fi
	case "$out" in
	*"$3"*) pass "$1" ;;
	*)
		fail "$1: expected log pattern '$3'"
		echo "$out" | tail -5 >&2
		;;
	esac
}

# 1. Mount escape: bind-mount of host /etc outside the whitelist.
expect_reject "mount-whitelist rejects host /etc bind" \
	"$tests_dir/escape-mount-whitelist.cfg" "not allowed by mount_whitelist"

# 2. Mount escape: '..' traversal out of a whitelisted directory.
expect_reject "mount-whitelist rejects '..' traversal" \
	"$tests_dir/escape-mount-traversal.cfg" "not allowed by mount_whitelist"

# 3. Invalid whitelist entries (relative paths) must be rejected as well.
out=$(timeout 60 "$nsjail_bin" -Mo --disable_clone_newnet --disable_clone_newcgroup \
	--disable_proc --mount_whitelist usr -R /usr:/usr -- /usr/bin/id 2>&1)
rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q "not a valid absolute path"; then
	pass "mount-whitelist rejects relative whitelist entry"
else
	fail "mount-whitelist accepted relative whitelist entry (rc=$rc)"
fi

# 4. Mounts inside the whitelist must still work.
out=$(timeout 60 "$nsjail_bin" -Mo --disable_clone_newnet --disable_clone_newcgroup \
	--disable_proc --mount_whitelist /usr --mount_whitelist /lib \
	--mount_whitelist /lib64 --mount_whitelist /tmp \
	-R /usr:/usr -s /usr/lib:/lib -s /usr/lib64:/lib64 -T /tmp -- \
	/usr/bin/id -u 2>/dev/null)
rc=$?
if [ $rc -eq 0 ] && [ "$out" = "$(id -u)" ]; then
	pass "mount-whitelist allows whitelisted mounts"
else
	fail "mount-whitelist blocked legitimate mounts (rc=$rc, out='$out')"
fi

# 5. Network escape: tenant asks for host networking and user-mode net, but
#    NETNS_ISOLATED must force a private, offline namespace.
host_net=$(readlink /proc/self/ns/net)
out=$(timeout 60 "$nsjail_bin" -C "$tests_dir/escape-netns-isolated.cfg" 2>/dev/null)
rc=$?
jail_net=$(printf '%s' "$out" | grep '^net:\[' || true)
if [ $rc -eq 0 ] && [ -n "$jail_net" ] && [ "$jail_net" != "$host_net" ]; then
	pass "netns_policy=isolated overrides clone_newnet:false ($jail_net)"
else
	fail "netns_policy=isolated did not isolate (rc=$rc, jail='$jail_net' host='$host_net')"
fi

# 6. The isolated namespace must be offline: even loopback is unreachable.
timeout 60 "$nsjail_bin" -C "$tests_dir/escape-netns-isolated.cfg" -- \
	/usr/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' >/dev/null 2>&1
rc=$?
if [ $rc -ne 0 ]; then
	pass "netns_policy=isolated blocks outbound connections"
else
	fail "netns_policy=isolated allowed a loopback connection"
fi

# 7. NETNS_HOST must force the host namespace even with clone_newnet:true.
out=$(timeout 60 "$nsjail_bin" -C "$tests_dir/escape-netns-host.cfg" 2>/dev/null)
rc=$?
jail_net=$(printf '%s' "$out" | grep '^net:\[' || true)
if [ $rc -eq 0 ] && [ "$jail_net" = "$host_net" ]; then
	pass "netns_policy=host overrides clone_newnet:true ($jail_net)"
else
	fail "netns_policy=host did not share host netns (rc=$rc, jail='$jail_net' host='$host_net')"
fi

# 8. Resource-limit combination: limits enforced, escape attempts fail.
out=$(timeout 60 "$nsjail_bin" -C "$tests_dir/escape-resource-limits.cfg" 2>&1)
rc=$?
if [ $rc -eq 0 ] && printf '%s' "$out" | grep -q "ESCAPE_RESOURCE_CHECKS_PASSED"; then
	pass "resource_limits combination enforced (raise/fsize escapes blocked)"
else
	fail "resource_limits combination not enforced (rc=$rc)"
	printf '%s\n' "$out" | tail -8 >&2
fi

# 9. disable_rl must not be usable to neutralize a resource_limits combination.
expect_reject "resource_limits rejects disable_rl escape" \
	"$tests_dir/escape-resource-conflict.cfg" "cannot be combined with disable_rl"

if [ $fails -ne 0 ]; then
	echo "FAIL: $fails escape-attempt test(s) failed" >&2
	exit 1
fi
echo "PASS: all escape-attempt tests passed"
