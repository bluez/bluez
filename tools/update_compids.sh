#!/bin/bash
# Download the list of company IDs from bluetooth.org and generate a diff which
# can be applied to source tree to update bt_compidtostr(). Usage:
#
# 1) ./tools/update_compids.sh | git apply -p0
# 2) Inspect changes to make sure they are sane
# 3) git commit -m "lib: Update list of company identifiers" lib/bluetooth.c
#
# Requires html2text: http://www.mbayer.de/html2text/
#
set -e -u

tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" EXIT

scriptdir=$(pwd)

mkdir $tmpdir/lib
cp lib/bluetooth.c $tmpdir/lib/bluetooth.c.orig
cp lib/bluetooth.c $tmpdir/lib/bluetooth.c

cd $tmpdir

echo -e 'const char *bt_compidtostr(int compid)\n{\n\tswitch (compid) {' > new.c

path=specifications/assigned-numbers/company-identifiers
# Use "iconv -c" to strip unwanted unicode characters
curl --insecure https://www.bluetooth.com/$path | \
    $scriptdir/tools/parse_companies.pl >> new.c

if ! grep -q "return \"" new.c; then
    echo "ERROR: could not parse company IDs from bluetooth.org" >&2
    exit 1
fi
echo -e '\tcase 65535:\n\t\treturn "internal use";' >> new.c
echo -e '\tdefault:\n\t\treturn "not assigned";\n\t}\n}' >> new.c

sed -n '/^const char \*bt_compidtostr(int compid)/,/^}/p' \
    lib/bluetooth.c > old.c

diff -Naur old.c new.c | patch -sp0 lib/bluetooth.c
diff -Naur lib/bluetooth.c.orig lib/bluetooth.c
