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

mkdir $tmpdir/lib
cp lib/bluetooth.c $tmpdir/lib/bluetooth.c.orig
cp lib/bluetooth.c $tmpdir/lib/bluetooth.c

cd $tmpdir

path=en-us/specification/assigned-numbers/company-identifiers
# Use "iconv -c" to strip unwanted unicode characters
# Fixups:
# - strip <input> tags of type "checkbox" because html2text generates UTF-8 for
#   them in some distros even when using -ascii (e.g. Fedora)
# - replace "&#160;" (non-breaking space) with whitespace manually, because
#   some versions incorrectly convert it into "\xC2\xA0"
curl https://www.bluetooth.org/$path | iconv -c -f utf8 -t ascii | \
    sed '/<input.*type="checkbox"/d; s/&#160;/ /g' | \
    html2text -ascii -width 160 -o identifiers.txt >/dev/null

# Some versions of html2text do not replace &amp; (e.g. Fedora)
sed -i 's/&amp;/\&/g' identifiers.txt

sed -n '/^const char \*bt_compidtostr(int compid)/,/^}/p' \
    lib/bluetooth.c > old.c

echo -e 'const char *bt_compidtostr(int compid)\n{\n\tswitch (compid) {' > new.c
cat identifiers.txt |
    perl -ne 'm/^(\d+)\s+0x[0-9a-f]+\s+(.*)/i &&
        print "\tcase $1:\n\t\treturn \"$2\";\n"' >> new.c
if ! grep -q "return \"" new.c; then
    echo "ERROR: could not parse company IDs from bluetooth.org" >&2
    exit 1
fi
if [ -n "$(tr -d '[:print:]\t\n' < new.c)" ]; then
    echo -n "ERROR: invalid non-ASCII characters found while parsing" >&2
    echo -n " company IDs. Please identify offending sequence and fix" >&2
    echo " tools/update_compids.sh accordingly." >&2
    exit 1
fi
echo -e '\tcase 65535:\n\t\treturn "internal use";' >> new.c
echo -e '\tdefault:\n\t\treturn "not assigned";\n\t}\n}' >> new.c

diff -Naur old.c new.c | patch -sp0 lib/bluetooth.c
diff -Naur lib/bluetooth.c.orig lib/bluetooth.c
