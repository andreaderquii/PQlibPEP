#!/bin/sh
set -eu
root="${1:-lab/material}"
# This directory is used ONLY by the offline setup tool, never mounted at runtime.
mkdir -p "$root/offline-ca" "$root/a" "$root/b" "$root/transcryptor"
[ ! -e "$root/offline-ca/key.pem" ] || { echo 'Refusing to overwrite lab CA' >&2; exit 1; }
umask 077
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 -subj '/CN=PQPEP Lab CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$root/offline-ca/key.pem" -out "$root/offline-ca/cert.pem"
for entry in 'a source' 'b recipient' 'transcryptor transcryptor'; do
  set -- $entry
  role="$1"; name="$2"
  openssl req -new -newkey rsa:3072 -nodes -subj "/CN=$name" \
    -keyout "$root/$role/key.pem" -out "$root/$role/request.csr"
  printf 'subjectAltName=DNS:%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n' "$name" > "$root/$role/extensions.cnf"
  openssl x509 -req -in "$root/$role/request.csr" -CA "$root/offline-ca/cert.pem" \
    -CAkey "$root/offline-ca/key.pem" -CAcreateserial -days 30 -sha256 \
    -extfile "$root/$role/extensions.cnf" -out "$root/$role/cert.pem"
  cp "$root/offline-ca/cert.pem" "$root/$role/ca.pem"
  rm "$root/$role/request.csr" "$root/$role/extensions.cnf"
done
cp "$root/a/cert.pem" "$root/b/authorized-source.pem"
cp "$root/a/cert.pem" "$root/transcryptor/authorized-source.pem"
echo 'Lab certificates created (30 days). Runtime mounts must exclude offline-ca.'
