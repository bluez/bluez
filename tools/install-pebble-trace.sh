#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary="$repo/src/bluetoothd"

if [ ! -x "$binary" ]; then
	echo "Execute make antes de instalar." >&2
	exit 1
fi

sudo -v
sudo install -m 0755 "$binary" /usr/local/libexec/bluetooth/bluetoothd-5.87
sudo systemctl restart bluetooth.service
sudo systemctl --no-pager --full status bluetooth.service | sed -n '1,14p'

echo "Instrumentação Pebble instalada."
