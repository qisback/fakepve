#!/bin/sh
# Drive a running fakepve with curl: log in, read, start a VM, follow the task.
#
#   python -m fakepve examples/guests.json --time-scale 0 &
#   sh examples/curl.sh
#
# PVE_URL, PVE_USER and PVE_PASS override the defaults. -k skips certificate
# verification, because the fake serves a self-signed certificate.
set -eu

PVE_URL=${PVE_URL:-https://127.0.0.2:8006}
PVE_USER=${PVE_USER:-root@pam}
PVE_PASS=${PVE_PASS:-secret}
API="$PVE_URL/api2/json"

# Pull one field out of a JSON document on stdin: field <dotted.path>
field() {
    python3 -c 'import json, sys
node = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    node = node[key]
print(node)' "$1"
}

echo "== login"
login=$(curl -sk --data-urlencode "username=$PVE_USER" --data-urlencode "password=$PVE_PASS" "$API/access/ticket")
ticket=$(echo "$login" | field data.ticket)
csrf=$(echo "$login" | field data.CSRFPreventionToken)

echo "== version"
curl -sk -b "PVEAuthCookie=$ticket" "$API/version"
echo

echo "== VMs"
curl -sk -b "PVEAuthCookie=$ticket" "$API/cluster/resources?type=vm"
echo

echo "== start VM 101 (writes need the CSRF header)"
upid=$(curl -sk -b "PVEAuthCookie=$ticket" -H "CSRFPreventionToken: $csrf" -X POST \
    "$API/nodes/pve1/qemu/101/status/start" | field data)
echo "$upid" | sed 's/:[0-9A-F]*:[0-9A-F]*:[0-9A-F]*:/:...:/'

echo "== task status"
curl -sk -b "PVEAuthCookie=$ticket" "$API/nodes/pve1/tasks/$upid/status" | field data.exitstatus

echo "== task log"
curl -sk -b "PVEAuthCookie=$ticket" "$API/nodes/pve1/tasks/$upid/log"
echo

echo "== a validation error (container 50: VM ids start at 100)"
curl -sk -b "PVEAuthCookie=$ticket" -H "CSRFPreventionToken: $csrf" -X POST \
    "$API/nodes/pve1/lxc/50/status/start" -w '\nHTTP %{http_code}\n'
