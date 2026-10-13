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
DEV     ?=
CONFIG  ?=
BUNDLE  ?= auto        # `auto` matches the capture's own firmware to a bundle
ROOT    ?=             # a command prefix for `make crawl`, e.g. get

.DEFAULT_GOAL := help
.PHONY: help all versions versions-check sources sources-check fetch build check \
        capture crawl tree probe serve diff clean distclean

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

## check           Bundle invariants, and both parser selftests.                 instant
##                 One bundle per cli entry, ids and names well formed, no duplicate
##                 get/show paths, worked examples not lopsided across builds of one
##                 platform, and index.html's PRODUCTS list agreeing with sources.json.
##                 Then three parser selftests: the tree parser against its fixture,
##                 the device crawl against a scripted box that hangs up on cue (how we
##                 know a crawl resumes without a lab to try it in), and the
##                 hand-written-reference parser against real syntax lines from the
##                 FortiSwitch, FortiManager and FortiAnalyzer documents.
##                 Runs at the end of build too; this is for after a hand edit.
check:
	@$(PY) tools/check_bundles.py
	@$(PY) tools/parse_tree.py --selftest
	@$(PY) tools/capture_device.py --selftest
	@$(PY) tools/parse_hand.py --selftest

## all             sources -> fetch -> build. The whole pipeline from nothing.
all: sources fetch build

##
##   GROUND TRUTH -- optional, and the only thing here that involves a device.
##   Nothing in `make all` needs one. Skip this section entirely and the pipeline
##   still builds every bundle from Fortinet's PDFs.
##
## capture         Walk every device in .env.devices over SSH.      ~10-45min, network
##                 Runs `get system status`, `tree`, and `<command> ?` for the 3104
##                 FortiOS commands the reference prints bare. All reads, and it never
##                 enters config mode -- so it works under an accprofile with
##                 `cli-config disable`, which means the DEVICE enforces read-only
##                 rather than this script promising to.
##                 Needs .env.devices (copy .env.devices.example, chmod 600). That file
##                 and everything under work/live/ are gitignored: a status banner
##                 carries a serial number and a hostname.
##                 Expect: one directory per build under work/live/, and a line telling
##                 you whether `?` survived the ssh pty at all. If it did not, the tree
##                 is still captured and useful.
##                   make capture              # every device
##                   make capture DEV=fgt1     # one
##                   make capture CONFIG=1     # also walk config tables (see below)
##
##                 `make crawl` is the long one, and it is interruptible on purpose:
##                 devices hang up well before a 2000-node walk finishes (fgt01 at
##                 about 450 asks). It reconnects once per drop, appends every record
##                 as it goes, and re-running the same command picks up where it
##                 stopped rather than starting over. Ctrl-C costs one path.
##
##                 CONFIG=1 adds field-level help, which needs config mode. It is safe
##                 by construction rather than by promise: every table is entered,
##                 probed with `set ?`, and left with `abort` -- never `end` -- so the
##                 candidate config is discarded. Before the walk it takes a restorable
##                 revision on the device (`execute backup config flash`) and records
##                 `diagnose sys ha checksum show`; after it, the checksum again. Equal
##                 checksums prove the walk wrote nothing. If they differ it says so
##                 loudly and tells you how to restore.
capture:
	@$(PY) tools/capture_device.py $(DEV) $(if $(CONFIG),--config-walk)

## crawl ROOT=...  Walk `?` down a command tree on every device.    20-90min, resumable
##                 This is where `get router info bgp neighbors <A.B.C.D>` comes from:
##                 the CLI Reference omits `get` entirely and the device's own `tree`
##                 cannot expand the routing daemon's subtree, so asking `?` at every
##                 node is the only way to reach it. Nothing is executed -- `?` is
##                 answered on the keystroke and the line is cleared with ctrl-U.
##                 Expect: a progress line every 25 asks, and to run it more than once.
##                 A FortiGate `get` tree is ~2000 nodes and the box hangs up around
##                 450; it reconnects once per drop and re-running resumes from the
##                 records already on disk. "queue empty: complete" is the finish line.
##                   make crawl ROOT=get
##                   make crawl ROOT=get,diagnose DEV=fgt01
crawl:
	@test -n "$(ROOT)" || { echo "set ROOT=get (or get,diagnose)"; exit 2; }
	@$(PY) tools/capture_device.py $(DEV) --crawl "$(ROOT)"

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
##                 A capture that begins with `get system status` identifies itself, so
##                 BUNDLE defaults to `auto`: same platform, same major.minor, and it
##                 refuses rather than guess across a minor boundary. Captures live in
##                 work/live/, which is gitignored -- a status banner carries a serial
##                 number and a hostname. Add --record to note the model and build in
##                 captures.json, which is the committed answer to "what have we
##                 measured this bundle against, and when".
##                   make tree FILE=work/live/fgt-7.6-tree.txt
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
