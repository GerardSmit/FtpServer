#!/usr/bin/env bash
#
# Verifies that an FTPS data connection resumes the control connection's TLS session.
#
# Clients can be configured to *require* this as proof that both connections belong to the same
# peer — FileZilla's "Require TLS session resumption on data connection", vsftpd's
# require_ssl_reuse. A server that cannot do it is refused by those clients, so it is worth being
# able to check.
#
# .NET exposes no API to observe resumption, so this uses openssl s_client, which reports
# "Reused" or "New" for every handshake.
#
# Scope: this proves the data listener will resume a session the control listener issued — the
# capability a client needs. It does not prove the data connection resumed *its own* control
# channel's session, because .NET's session cache is process-wide and openssl cannot be made to
# offer a session mid-connection. Read a PASS as "resumption works", not as proof of
# per-connection binding.
#
# Usage:
#   1. Start the server with FTPS and anonymous access enabled:
#        dotnet run --project src/FtpServer -- \
#          --Port=2500 --Path=/tmp/ftproot --Ftps=true --Authentication:AllowAnonymous=true
#      and put a file called a.txt in the root.
#   2. tools/verify-tls-resumption.sh 2500
#
# Expected output ends with: RESULT: Reused, TLSv1.3, ...
#
# Note: the server only performs the data-side handshake once a transfer command is running, so
# the control channel must issue RETR before the data socket handshakes. A test that connects to
# the passive port without issuing a transfer measures a timeout, not a handshake.

set -u

PORT=${1:-2500}
HOST=${2:-127.0.0.1}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

command -v openssl >/dev/null || { echo "openssl is required"; exit 1; }

echo "### 1. control handshake, saving the session"
printf 'QUIT\r\n' | openssl s_client -starttls ftp -connect "$HOST:$PORT" -sess_out "$WORK/c.pem" 2>/dev/null \
  | grep -aE '^(New|Reused),' | sed 's/^/  /'

echo "### 2. control handshake offering it back (confirms the ticket is usable)"
printf 'QUIT\r\n' | openssl s_client -starttls ftp -connect "$HOST:$PORT" -sess_in "$WORK/c.pem" 2>/dev/null \
  | grep -aE '^(New|Reused),' | sed 's/^/  /'

echo
echo "### 3. live control channel: PASV, RETR, then handshake the data socket"
{
  printf 'USER anonymous\r\n'; sleep 1
  printf 'PASS a@b.c\r\n';     sleep 1
  printf 'PBSZ 0\r\n';         sleep 1
  printf 'PROT P\r\n';         sleep 1
  printf 'PASV\r\n';           sleep 2
  printf 'RETR a.txt\r\n';     sleep 20
  printf 'QUIT\r\n'
} | openssl s_client -quiet -starttls ftp -connect "$HOST:$PORT" > "$WORK/c.out" 2>&1 &
CONTROL=$!

sleep 8

DATA_PORT=$(grep -a '227 ' "$WORK/c.out" \
  | sed -E 's/.*\(([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)\).*/\5 \6/' \
  | head -1 | awk '{print $1 * 256 + $2}')

if [ -z "${DATA_PORT:-}" ]; then
  echo "  could not parse a passive port from the control channel:"
  sed 's/^/    /' "$WORK/c.out"
  kill $CONTROL 2>/dev/null
  exit 1
fi

echo "  data port: $DATA_PORT"
grep -aE '^150' "$WORK/c.out" | sed 's/\r//;s/^/  control: /'

printf '' | timeout 12 openssl s_client -connect "$HOST:$DATA_PORT" -sess_in "$WORK/c.pem" > "$WORK/d.out" 2>&1
STATUS=$?

if [ $STATUS -ne 0 ]; then
  echo "  data handshake failed (s_client exit $STATUS)"
  sed 's/^/    /' "$WORK/d.out" | head -10
  kill $CONTROL 2>/dev/null
  exit 1
fi

grep -aE '^(Reused|New),' "$WORK/d.out" | sed 's/^/  RESULT: /'

kill $CONTROL 2>/dev/null
wait $CONTROL 2>/dev/null

grep -aqE '^Reused,' "$WORK/d.out"
