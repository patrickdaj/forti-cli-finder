#!/usr/bin/env bash
# Rebuild site/data/*.json from the Fortinet PDFs in sources/.
# Needs: python3, pdftotext (poppler-utils).
#
# Which documents are used is sources.json; which exact PDFs is sources.lock.json.
#   python3 tools/discover_sources.py   # refresh the lock file from docs.fortinet.com
#   python3 tools/fetch_sources.py      # download what the lock file names
#   ./build.sh                          # parse and bundle (about 60s)
set -euo pipefail
cd "$(dirname "$0")"
export WORK=work OUT=site/data
mkdir -p "$OUT"

missing=$(python3 - <<'PY'
import json, os
docs = json.load(open('sources.lock.json'))['documents']
print(' '.join(k for k in sorted(docs) if not os.path.exists(f'sources/{k}.pdf')))
PY
)
if [ -n "$missing" ]; then
  echo "missing PDFs: $missing" >&2
  echo "run: python3 tools/fetch_sources.py" >&2
  exit 1
fi

# text extraction is the slow part, so only redo it when the PDF is newer
totext() {  # totext <key>
  mkdir -p "work/$1"
  if [ ! -s "work/$1/text.txt" ] || [ "sources/$1.pdf" -nt "work/$1/text.txt" ]; then
    pdftotext -layout "sources/$1.pdf" "work/$1/text.txt"
  fi
}

echo "== CLI references"
python3 - <<'PY' > work/cli.list
import json
for e in json.load(open('sources.json'))['cli']:
    print(e['key'], e['parser'], e['product'])
PY
while read -r key parser product; do
  totext "$key"
  printf '%-14s ' "$product"
  python3 "tools/parse_${parser}.py" "work/$key/text.txt" "work/$key/tree.json" "$product"
done < work/cli.list
python3 tools/build_bundles.py

echo "== sample output"
python3 - <<'PY' > work/out.list
import json
for e in json.load(open('sources.json'))['output']:
    print(e['key'])
PY
while read -r key; do
  totext "$key"
  printf '%-14s ' "$key"
  python3 tools/extract_outputs.py "work/$key/text.txt" "work/$key/samples.json"
  printf '%-14s ' "$key"
  python3 tools/extract_config_examples.py "work/$key/text.txt" "work/$key/config-examples.json"
done < work/out.list
python3 tools/attach_outputs.py
python3 tools/attach_config_examples.py
# after attaching: a sample for `get system ha status` must create that entry, not be
# swallowed by a derived `get system ha` that merely prefixes it. Anything the guides
# already produced is skipped here.
python3 tools/derive_getshow.py

echo "== done"
ls -la "$OUT"
