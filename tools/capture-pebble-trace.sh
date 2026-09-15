#!/bin/sh
set -eu

output=${1:-"$HOME/Documents/bluez-pebble/pebble-trace.log"}

echo "Capturando PEBBLE_TRACE em $output"
echo "Use Ctrl+C para encerrar."
sudo journalctl -u bluetooth.service -f -o short-precise \
	| grep --line-buffered 'PEBBLE_TRACE' \
	| tee -a "$output"
