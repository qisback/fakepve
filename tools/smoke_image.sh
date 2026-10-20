#!/bin/sh
# Smoke test of the container image: run it, wait until it answers, log in, list the VMs.
#
#   tools/smoke_image.sh IMAGE                  # docker run IMAGE, published on 127.0.0.1 only
#   tools/smoke_image.sh --url https://127.0.0.1:8006   # test a fakepve that is already running
#
# EXPECT_VERSION=X.Y.Z also checks `IMAGE --version`. The default login (root@pam / secret) is only
# ever sent to a loopback address.
set -eu

PORT="${SMOKE_PORT:-18006}"
WAIT="${SMOKE_WAIT:-60}"
name="fakepve-smoke-$$"
started=

cleanup() {
    if [ -n "$started" ]; then
        docker logs "$name" 2>&1 | tail -20 || true
        docker rm -f "$name" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

fail() {
    echo "smoke: $*" >&2
    exit 1
}

case "${1:-}" in
    --url)
        [ $# -eq 2 ] || fail "usage: $0 IMAGE | --url URL"
        base="$2"
        ;;
    '' | -*)
        fail "usage: $0 IMAGE | --url URL"
        ;;
    *)
        image="$1"
        if [ -n "${EXPECT_VERSION:-}" ]; then
            reported="$(docker run --rm "$image" --version)"
            [ "$reported" = "fakepve $EXPECT_VERSION" ] || fail "image reports '$reported', expected 'fakepve $EXPECT_VERSION'"
        fi
        docker run -d --name "$name" -p "127.0.0.1:$PORT:8006" "$image" >/dev/null
        started=1
        base="https://127.0.0.1:$PORT"
        ;;
esac

# The credentials are public; never send them anywhere but this machine.
case "$base" in
    https://127.* | https://localhost[:/]* | https://localhost | 'https://[::1]'*) ;;
    *) fail "refusing to log in to $base: not a loopback address" ;;
esac

api="$base/api2/json"
i=0
until curl -sk --fail -o /dev/null "$api/access/domains"; do
    i=$((i + 1))
    [ "$i" -lt "$WAIT" ] || fail "no answer from $base after ${WAIT}s"
    sleep 1
done

ticket="$(curl -sk --fail -d username=root@pam -d password=secret "$api/access/ticket")" || fail "login failed"
cookie="$(printf '%s' "$ticket" | python3 -c 'import json,sys; print("PVEAuthCookie=" + json.load(sys.stdin)["data"]["ticket"])')"
vms="$(curl -sk --fail -H "Cookie: $cookie" "$api/cluster/resources?type=vm")" || fail "listing VMs failed"
count="$(printf '%s' "$vms" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]))')"
[ "$count" -gt 0 ] || fail "no VMs listed"
echo "smoke: ok, $count VMs listed from $base"
