# Forti CLI Finder -- every collection and build step, with what each one costs.
#
#   make              what you are reading
#   make all          the normal path: lock -> download -> parse -> bundle -> check
#
# Needs python3 (stdlib only) and pdftotext (poppler). Nothing else, ever: the bundles
# ship to a browser from a static host, so a dependency here is a dependency forever.

SHELL   := /bin/bash
PY      := python3
WORK    ?= work
OUT     ?= site/data
PORT    ?= 8000
export WORK OUT

# A doc path for `make probe`, e.g. /document/fortigate/8.0.1/administration-guide
DOC     ?=
BUNDLE  ?= fortios

.DEFAULT_GOAL := help
.PHONY: help all versions versions-check sources sources-check fetch build check \
        tree probe serve diff clean distclean

## ---------------------------------------------------------------- discovery

help:
	@sed -n 's/^##//p' $(MAKEFILE_LIST)

##
##   DISCOVERY -- asks docs.fortinet.com what exists. Reads only; writes no bundles.
##
## versions        Which firmware versions exist that we do not ship.       ~25s, network
##                 This is the "8.1 came out" check. sources.json pins a version into
##                 every doc path, so a new release is a path nobody has looked at and
##                 `make sources` will never find it.
##                 Expect: a few lines per document, newest first, with the PDF each
##                 candidate path actually serves. Read that filename -- Fortinet
##                 redirects an unpublished version to the nearest build, so
##                 /fortiswitch/7.6.8/ serving FortiSwitchOS-7.6.7_CLI_Reference.pdf
##                 means 7.6.8 is not worth adding.
##                 Does NOT edit sources.json, download, or decide anything.
versions:
	@$(PY) tools/discover_versions.py

## versions-check  Same, but exit 1 if anything newer exists. For CI.          ~25s, network
versions-check:
	@$(PY) tools/discover_versions.py --check

## sources         Re-resolve the doc paths we already ship to today's PDFs.  ~20s, network
##                 Writes sources.lock.json (URL, filename, byte size per document).
##                 Catches Fortinet re-releasing a version in place; does not find new
##                 versions -- that is `make versions`.
sources:
	@$(PY) tools/discover_sources.py

## sources-check   Same, but exit 1 if the lock file is stale. The weekly job's gate.
sources-check:
	@$(PY) tools/discover_sources.py --check

## probe DOC=...   Measure a candidate guide before adding it.          minutes, ~100MB+
##                 Downloads one document and reports how many CLI commands and output
##                 samples it would actually contribute. Most guides contribute almost
##                 nothing -- six measured candidates yielded 13 new commands between
##                 them -- so measure before you commit 100MB of PDF to the pipeline.
##                 Expect: a count, not a recommendation.
##                   make probe DOC=/document/fortigate/8.0.1/administration-guide
probe:
	@test -n "$(DOC)" || { echo "set DOC=/document/<product>/<version>/<guide>"; exit 2; }
	@$(PY) tools/prospect.py "$(DOC)"

##
##   COLLECTION -- downloads. The PDFs are ~550MB and are not in the repo.
##
## fetch           Download every PDF sources.lock.json names.        ~10min first run
##                 Resumable and idempotent: a file whose size already matches the lock
##                 is left alone, so re-running costs nothing. Run `make sources` first
##                 or it downloads whatever the committed lock file says.
fetch:
	@$(PY) tools/fetch_sources.py

##
##   BUILD -- offline. Needs the PDFs present.
##
## build           Parse, bundle, attach samples, derive get/show, stamp, check.   ~60s
##                 Writes $(OUT)/*.json and rewrites the PRODUCTS list and BUILD hash in
##                 site/index.html. Safe to re-run: byte-identical output from unchanged
##                 input, which is worth confirming with `git diff --stat $(OUT)`.
build:
	@./build.sh

## check           Bundle invariants, and the tree parser's selftest.           instant
##                 One bundle per cli entry, ids and names well formed, no duplicate
##                 get/show paths, worked examples not lopsided across builds of one
##                 platform, and index.html's PRODUCTS list agreeing with sources.json.
##                 Runs at the end of build too; this is for after a hand edit.
check:
	@$(PY) tools/check_bundles.py
	@$(PY) tools/parse_tree.py --selftest

## all             sources -> fetch -> build. The whole pipeline from nothing.
all: sources fetch build

##
##   GROUND TRUTH -- optional, and the only thing here that involves a device.
##   Nothing in `make all` needs one. Skip this section entirely and the pipeline
##   still builds every bundle from Fortinet's PDFs.
##
## tree FILE=...   Parse a device's `tree` capture; diff it against a bundle.    instant
##                 `tree` on a FortiGate prints its own command tree. It is the only
##                 source that is exact for a firmware BUILD rather than for whatever
##                 Fortinet last regenerated a PDF from, and it carries what the CLI
##                 Reference does not: the arguments of diagnose and execute commands,
##                 integer ranges and string lengths on every config field, each table's
##                 mkey, and the `<Enter> or` optional-argument marker.
##                 Expect: counts, then a per-verb diff. "bundle has it but with no
##                 arguments" is the interesting column -- those are commands we ship
##                 bare that the box can describe.
##                 Does NOT give descriptions, defaults, option values, sample output,
##                 or `get router info *` -- the routing daemon's tree is opaque to it.
##                   make tree FILE=work/live/fgt-7.6-tree.txt BUNDLE=fortios
tree:
	@test -n "$(FILE)" || { echo "set FILE=<a tree capture>"; exit 2; }
	@$(PY) tools/parse_tree.py "$(FILE)" --diff "$(BUNDLE)"

##
##   LOCAL
##
## serve           Serve site/ on http://localhost:$(PORT).
##                 Opening site/index.html from disk will not load the data.
serve:
	@cd site && $(PY) -m http.server $(PORT)

## diff            What the last build changed in the bundles, readably.       instant
##                 `git diff` on a minified bundle says "1 insertion, 1 deletion", which
##                 is why a data-refresh PR is unreviewable without this.
diff:
	@$(PY) tools/diff_bundles.py

## clean           Drop parsed text and trees; keep the PDFs and the bundles.
clean:
	@rm -rf $(WORK)/*/text.txt $(WORK)/*/tree.json $(WORK)/*.list
	@echo "cleaned $(WORK) intermediates; PDFs and $(OUT) kept"

## distclean       Also drop the downloaded PDFs (~550MB, re-fetchable from the lock).
distclean: clean
	@rm -f sources/*.pdf sources/*.part
	@echo "removed sources/*.pdf -- `make fetch` brings them back"
##
