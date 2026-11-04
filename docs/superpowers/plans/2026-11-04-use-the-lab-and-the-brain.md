# Plan: make the Finder a citizen of the lab and the brain

**Date:** 2026-11-04 · **Status:** accepted 2026-11-04, decisions in §6, nothing built yet · **Owner:** Patrick Avery
**Audience:** the sessions that will be handed one task each from §5. Read §2 and §6 before your task.

## 0. Why this document exists

Three repos, one engineer, three different answers to "what does this FortiOS command do":

| Repo | What it is | Last moved |
|---|---|---|
| `~/Development/forti-cli-helper` (GitHub: `patrickdaj/forti-cli-finder`) | a static, keyboard-first CLI lookup and block composer: 5 bundles parsed from Fortinet PDFs, 7,315 FortiOS 7.6.7 entries, sample output on 500 of them, a composer that quotes values the way `show` prints them. Public on GitHub Pages | 2026-10-12 |
| `~/Development/fortinet-brain` (GitHub: `patrickdaj/fortinet-second-brain`) | the corpus: 132 documents chunked into 31,908 markdown files with page ranges; `fortinet-docs` and `investigate` skills; `clicheck` (does this block exist in the reference, in the right order), `fgconf` (a config as objects, with FortiManager's syntax schema for 7.6 and 8.0), `logid`, a 38-row retrieval benchmark | 2026-11-04 |
| `~/Development/fortinet-lab` (no remote) | Proxmox lab: FortiGate-VM templates for 7.6.7 build 3704 and 8.0.2 build 0251, two FortiFlex pools of five licensed clones each, FMG/FAZ pairs on both trains; the `lab` command (logged read-only runs, `expect`, `regress`, `api`), a permission hook with tiers, 19 findings, 3 verified regression suites, 11,530 logged command records | 2026-11-04 |

The Finder was built in isolation in October. In the three weeks since, the other two repos grew exactly the things the Finder lacks and had to invent: a device that can be spun up and read on demand, a machine-readable schema for every config table, a record of what FortiOS actually does, and a citation discipline. Meanwhile the Finder has the one thing the other two lack: a structured, per-command, per-argument model of the whole CLI, including `diagnose`, `execute` and `get`, and a page an engineer can type into.

This plan says how the three should feed each other, what to build in which repo, in what order, and what Patrick must decide first.

## 1. What each repo has that the others want

**The Finder alone has**

- A parsed command tree for every verb on four platforms, with arguments: FortiOS 7.6.7 and 8.0.1, FortiSwitchOS, FortiAnalyzer and FortiManager 7.6.7. The brain's CLI-reference chunks are prose per table; `clicheck` greps them. Nothing else in the three repos knows that `diagnose sniffer packet` takes `<interface> <filter> <verbose> <count>`.
- The `get` tree. The generated FortiOS CLI Reference contains no `get` and no `show`. The Finder derives `show`/`get` for every config table and carries 798 device-learned `get`/`diagnose` facts from a 70G crawl.
- Field frequency (`fq`): which parameters Fortinet's own 3,786 admin-guide examples actually set, per table.
- A composer: the block an engineer pastes, with quoting and positional arguments done right.

**The brain alone has**

- `tools/fgconf/fmg-syntax-{7.6,8.0}-{device,adom}.json`: FortiManager's `option: syntax` dump. For 565 (7.6) and 592 (8.0) device tables, every attribute with `type`, `default`, `opts`, `opts help`, `help`, `sz`, `max_argv`, and, decisively, `ref` (which other table an attribute names). The Finder reconstructs type, default and options from PDF column layout; this file has them as data, and it has cross-references, which no PDF has.
- `tools/fgconf/tree-{7.6,8.0}.txt`: a FortiGate `tree` capture per train. The Finder's `make tree` diff wants exactly this and has it only for 7.6.
- `tools/clicheck_rules.yaml`: ordering and context rules the device taught (`add-route` is refused unless `type dynamic` is set first). `tools/fgconf/rules/*.yaml`: 25 best-practice lint rules, each citing the best-practices guide.
- Citations as a shape: `doc_id / section / pp. N-M`, and the PDF deep link `source#page=N` from `documents.json`.
- CLI References one release newer than the Finder's: 7.6.8 and 8.0.2 (the Finder ships 7.6.7 and 8.0.1).

**The lab alone has**

- Devices on demand, on both trains, with a serial each, factory-resettable, snapshot-able: `make fgt-new`, the FortiFlex pools at 5081–5085 (7.6.7) and 5091–5095 (8.0.2), `fmg02`/`faz02` on 8.0.2. A FortiSwitch is physical only (two 224E in the lab domain).
- `lab run`: read-only commands, logged with timestamp, device, exit and masked output. 11,530 records exist today across two places: `investigations/<id>/lab.log` when a run carried `--inv` (1,823 records), else `investigations/_lab/<date>.log` (the rest, including every `lab regress` and `lab plan run`, mixed with the hook's `policy` records). About 5,400 are successful device reads: `diagnose sys sdwan` 753 times, `diagnose vpn ike` 660, `get router info` 503, `diagnose vpn tunnel` 105.
- `findings/F-0001..F-0019`: one claim per file, each with the device output and the log lines behind it, and a `relation` to the docs (confirms, extends, contradicts).
- Regression suites whose `checks.plan` lines are `lab expect <device> "<command>" --match <pattern>`: a command, and what its output should contain, verified on a named build.
- The permission hook and tiers, which decide what a session may do without asking. A scratch FortiGate-VM (VMID 5000–5099) allows reads, config and snapshots with zero prompts.

## 2. Rules every task obeys

1. **The Finder stays python3 stdlib plus `pdftotext`, and a static site.** Anything imported from the lab or the brain arrives as a committed JSON overlay written by a tool in `tools/`, the way `device-overlay.json` and `cheat-overlay.json` already do. Read the other repos at generation time; never at build time on CI, which has neither.
2. **Provenance travels with every fact.** A sample from the lab says `lab, FortiOS 7.6.7 build 3704, suite pqc-hub-spoke-76, 2026-11-03`. A parameter fact from the FortiManager schema says so. The page already prints a source line under every sample; keep using it.
3. **Nothing private reaches the Finder repo.** It is public. No serial, hostname, address, PSK, token, company name from `docs/companies/`, or anything from `investigations/` except command text and masked output. `lab/mask.py` has already masked the logs; the import tool masks again and refuses to write if a line still matches `lab/mask.py`'s patterns. Shorten any serial that survives to its last four characters, as the proof pages do.
4. **The lab's rules are the lab's.** A task that touches a device runs from `~/Development/fortinet-lab`, through `uv run lab` or `make`, on scratch only (sites 7–11, inside VLANs 61–69, VMIDs 5000–5099). The hook decides; if a line would ask, change the line. Never the 70G pair: the Finder's October crawl ran against the household perimeter and hung it up every 450 asks, and that must not happen again. Lab CLAUDE.md §11 applies: the task's report names its policy-log lines.
5. **The brain's non-negotiables hold.** Nothing is written into `sources/` or `courses/` by hand. A brain tool change follows its CLAUDE.md: test first against a temporary corpus, `/code-review`, one commit per change.
6. **Measure before you add.** `make probe`, `make diff`, `parse_tree.py --diff`: every data change in the Finder is reported as counts (commands added, arguments gained, samples gained) before it is committed, and the commit message carries them.
7. **Each repo owns its git.** A task that changes two repos makes two commits, each described in its own repo's terms. No commit without the task brief saying so.
8. **YAML inputs, without a dependency (my call).** The brain's rules (`clicheck_rules.yaml`, `fgconf/rules/*.yaml`, `refs-map.yaml`) and the lab's `allow.yaml` are YAML, and PyYAML is not stdlib. Rule 1 binds the build and the shipped site, not the generation-time importers, so an importer that needs YAML is run through the owning repo's environment: `uv run --project ~/Development/fortinet-brain python3 tools/import_brain.py`, with the Makefile target spelling that out. The Finder's own `pyproject` stays absent, `make check` never needs YAML, and the committed overlay is JSON. If that proves awkward, the fallback is a JSON export command in the owning repo, which is a second repo's commit under its rules.

## 3. The workstreams

Ordered by value per hour of a lower model's time. A, B and C are independent of each other and can run in parallel; D depends on C; E and F are later.

### A. Ground truth from the lab, not the perimeter

The Finder's device half was measured once, against the wrong device. Redo it on scratch VMs, on both trains, and record it.

What exists: `tools/capture_device.py` (pty over ssh, `tree`, `<command> ?`, resumable crawl, selftest), `tools/parse_tree.py --diff`, `tools/merge_device.py --apply`, `.env.devices`. What is missing: any 8.0 capture, a FortiSwitch 7.6 capture, FMG/FAZ 8.0.2 captures, and `captures.json` (the committed record `--record` writes) was never produced.

Tasks:

- **A1.** Capture a 7.6.7 pool clone and an 8.0.2 pool clone (`tree`, bare-command `?`, `get` and `diagnose` crawls). Then `fmg02` and `faz02` for the FMG/FAZ 8.0 `?` crawls. Run `parse_tree.py --record` for each; commit `captures.json` and the regenerated `device-overlay.json`. Report `make diff` counts. Expect the 8.0 bundle to gain the most: it has no device facts at all today.
- **A2.** Transport, decided (§6 Q1): build `lab crawl` first; nothing captures a lab device from the Finder repo. The reasoning that led there, kept for the record: `capture_device.py` opens its own pty session as a named user; the lab's rule is that sessions read devices through `lab run`. Two honest options: (a) run `capture_device.py` as-is from the Finder repo against a pool clone's address as `lab-ro` with the Mac key. The lab's hook is registered only in the lab repo's `.claude/settings.json`, and even there it treats `python3 x.py` as "not a lab operation", so this crawl is **invisible to the hook and absent from the lab log**: it is a read-only crawl on a throwaway VM, but the task's report cannot name policy-log lines for it. (b) add a `lab crawl` subcommand in the lab repo that drives the same walk through `lab/transport.py` and logs each `?` as a record, so the hook judges it and the log holds it. (b) is the right end state and roughly a day; (a) is an afternoon. Separately, `fmg02` and `faz02` are `[shared]` guests (VMIDs 2032, 2033), not scratch: a change there asks, and a read through (a) is unlogged on a device other sessions depend on. Patrick chose (b). So A2 is now a lab-repo task in wave 1: `lab crawl <device> --root get,diagnose [--tree] [--bare FILE] --out DIR`, driving the walk `capture_device.py` already knows how to do (pty, `?` on the keystroke, ctrl-U to clear, reconnect and resume from the records on disk, and the `--selftest` box that hangs up on cue) through `lab/transport.py`, every ask logged as a device record, output written in the same `work/live/`-shaped layout so `parse_tree.py` and `merge_device.py` read it unchanged. Reads only; the hook allows it on scratch and asks on shared. For `fmg02` and `faz02`, the shared pair, the crawl runs as one `lab plan` whose single prompt names the device and the root, at a time Patrick picks, and it never enters config mode. A1 then runs on a 7.6.7 clone and an 8.0.2 clone first, FMG/FAZ after. Lab CLAUDE.md §11 reporting applies to both.
- **A3.** The 8.0 bundle is built from the 8.0.1 PDF while the lab runs 8.0.2 and the brain tracks the 8.0.2 reference. `make versions` to confirm what docs.fortinet.com serves, then the hand recipe in `docs/pipeline.md` "Adding a firmware version" step 2: download to `work/probe/`, `pdftotext`, `parse_fos.py` to a scratch tree, and compare section and argument counts against the shipped bundle (`work/probe/80/decision.md` is the worked example). `make probe` is not this: it measures a guide's sample output, not a CLI reference. Add 8.0.2 if it gains arguments or sections. Measure 7.6.8 the same way but expect to skip it: Patrick's read is that 7.6.7 and 7.6.8 barely differ (§6 Q6), so it is added only if the counts say otherwise, and D4's page map is built against whatever the Finder ships.
- **A4.** Compare the brain's `tree-7.6.txt` and `tree-8.0.txt` with the lab captures from A1. They are config-tree-only captures with no `get system status` banner (nine lines in each mention `diagnose` or `execute`), so `parse_tree.py --diff` reads them with an explicit `BUNDLE=`, never `auto`, they cannot feed `--record`, and they say nothing about the diagnose/execute half. Their value is the config half for 8.0 before A1 lands, and as a check on A1's capture afterwards. Report, do not duplicate the files.

### B. Lab output as sample output

Sample output is the Finder's thinnest column: 19.6% of output-capable FortiOS commands show anything, FMG and FAZ under 4%, because Fortinet's guides contain almost none. The lab produces real output, on a known build, every day, already masked and logged.

Tasks:

- **B1. `tools/import_lab.py` in the Finder.** Reads `~/Development/fortinet-lab/investigations/<id>/lab.log` **and** `investigations/_lab/<date>.log` (and nothing else from `investigations/`): suites and plans log only to the dated files, so reading `lab.log` alone would miss every regression run. Keep only device records, meaning a `=== <timestamp> <device> exit=N` header whose device is a `[devices.<name>]` entry in `lab.toml`; skip `policy` and `plan` records outright. For each kept record with `exit=0` whose command begins with `get`, `show`, `diagnose` or `execute ping|traceroute`: command, output, timestamp, device name mapped to a build string through `lab.toml`'s `vmid` and the template table in `docs/build-plan.md` (7.6.7 build 3704 for the 5081–5085 pool, 8.0.2 build 0251 for 5091–5095; FMG/FAZ by device name), and a caption: the investigation folder for a `lab.log` record, or the suite name from the nearest preceding `plan` record (`plan=<id>`) for a dated-log record, else the date. (My call: this is why B3 needs no lab-side change.) Company devices are in scope (§6 Q3: the companies are fictional and there is no real customer data), on one condition that applies to every record, scratch or company: the output is anonymised before it is written. Concretely (my call on the specifics): serials shortened to their last four characters; the device prompt and any hostname replaced with a generic one per platform (`FGT #`, `FMG #`); the five company names and their abbreviations (`nw`, `hv`, and the rest as `lab.toml` spells them) removed from captions and output; tokens, keys and anything `lab/mask.py` catches masked; any public address replaced. Private-range and RFC 5737 lab addressing stays, because the output means nothing without it. Keep one sample per distinct command per build, newest first, longest under a size cap (the page truncates past ~40 lines anyway). Re-mask with the patterns in `lab/mask.py`; refuse to write on any hit. Write `lab-overlay.json` with the `_comment` block the other overlays carry. `--report` prints what it would add, per bundle.
- **B2. Attach.** Extend `attach_outputs.py` (or a small step after `merge_device.py --apply` in `build.sh`) to attach lab samples with `src: "lab"` and a per-sample build string, ranked **below** a guide sample for the same command on the same build and **above** an inherited ancestor sample. Add `lab` to `srcs` so the page prints `lab, FortiOS 7.6.7 build 3704, pqc-hub-spoke-76` under it. `check_bundles.py` gains: no sample text matches a mask pattern, no sample names a company set.
- **B3. A sample run the lab can repeat.** In the lab repo, `regression/finder-samples/checks.plan`: one `lab run` line per command worth a sample, on a scratch pool clone of each train, in the shape `lab regress` already runs. Start from the troubleshooting cheat sheet's commands (`cheat-overlay.json` has them parsed) intersected with `lab/allow.yaml`; a command the allowlist refuses is a candidate to name there, never a reason to loosen it. Running the suite then B1 is how the Finder gets a fresh, complete sample set on a new build in one sitting. State it Reasoned until it has run.
- **B4. Expectations as "look for".** The page already supports an `o.g` ("look for") line under a sample. A suite's `lab expect ... --match <pattern>` is exactly that: what in this output proves the claim. Import each `--match` from `regression/*/checks.plan` as the `g` of the sample for that command, with the suite's name. Only from phases the suite README states as Verified.

### C. The FortiManager schema as the config half's second source

The Finder's config tables come from parsing PDF column layouts, and `docs/pipeline.md` records the pain. The brain already holds the same information as JSON, generated by the product, for both trains, plus `ref` targets. Use it as a check first and a source second.

Tasks:

- **C1. Diff, read-only.** `tools/diff_schema.py`: load `fmg-syntax-<train>-device.json`, join to the bundle on table path and attribute name, and report per bundle: parameters in the schema and not the bundle, the reverse, type disagreements, default disagreements, option-list disagreements. Numbers first. Every disagreement is either a parser bug (fix it in `parse_fos.py`, the PDF is still the citation) or a schema quirk (`excluded: true`, FortiManager-only attributes); the report must separate the two before anyone edits a parser.
- **C2. Cross-references in the inspector.** From `ref`: when the cursor is on `srcaddr`, the inspector says it names a `firewall address` or `firewall addrgrp`, and enter on it jumps to that table (the page already has a jump-to-includes mechanism from the worked-examples commit). Shipped as a `refs` overlay generated from the schema: table path, attribute, list of target table paths. Reuse the brain's `refs-map.yaml` overrides rather than rediscovering them.
- **C3. Option help.** `opts help` gives one line per option value (`ipsec: Firewall policy becomes a policy-based IPsec VPN policy`), which the PDF table does not. Show it when cycling an option value with left/right. Overlay, same file as C2 or its own.
- **C4. Redistribution, decided (§6 Q2).** Derived facts from the schema may ship on the public page. Provenance stays explicit: a fact that came from the schema says `FortiManager 7.6.7 syntax metadata` on the page the way device facts say their model and build, and the PDF remains the citation wherever both say the same thing.

### D. What the lab learned, shown where the engineer types

The lab's findings and the brain's rules are the knowledge an engineer wants at the moment of composing a block, and today they live in YAML and markdown nobody opens while typing.

Tasks:

- **D1. Ordering and context rules in the composer.** `clicheck_rules.yaml` is small and precise (`requires-before`, `absent-in-context`, `refused-after`, each with a fix line and a source). Import it as an overlay keyed by table and attribute. When the composed block violates one, the inspector shows the rule's fix line and source under the block, the way it shows "the 9 fields a policy needs". Pure page logic over the same block the composer already holds.
- **D2. Findings as notes.** `tools/import_lab.py` also reads `findings/*.md` frontmatter. Any finding whose `claim` or `doc_cite` names a command path or a `table > attribute` the bundle has gets a note on that entry: the claim, `F-NNNN`, build, date, relation. `contradicts` renders differently from `confirms`. Nothing from the body except the claim; findings have no secrets but keep it to one line.
- **D3. Best-practice lint as hints.** `tools/fgconf/rules/*.yaml`: 25 rules with citations. Where a rule names a table and a setting, show it as a hint in that table's inspector ("best practice: `admin-https-redirect enable`, Best Practices p. N"). Overlay; 7.6 only, as the rules are.
- **D4. A cite button.** Every entry already carries the document and page. Add `y` (or a `/cite` command) that copies the brain's citation shape, `fortios-7.6-cli-reference / config firewall policy (part 1) / pp. 537-545`, and a link to the PDF page. The mapping from the Finder's source key to the brain's `doc_id` is a ten-line table in `sources.json`; the page range comes from the brain's chunk whose `pages` contains the entry's `pg`, generated once into an overlay. The brain has no FortiSwitchOS CLI reference, so the FortiSwitch bundle's cite falls back to the Finder's own document title and page with no `doc_id`; say so in the copied text rather than inventing one. After this, an answer written with `fortinet-docs` and a lookup in the Finder cite the same thing in the same words.

### E. One discovery, not two

Both the Finder and the brain poll docs.fortinet.com weekly and differ in what they catch. The Finder's `discover_versions.py` reads the sitemap and finds a version nobody has looked at (the "8.1 came out" check); the brain's `shelf.py sync` resolves the newest release within a train and would not notice a new train. The brain's `documents.json` carries the exact S3 URL per document the Finder's lock file also records.

Decided (§6 Q4): Patrick owns discovery. Both weekly workflows keep running and he reads both pull requests; no tool merges them. One task survives, optional:

- **E1.** Port the new-train check into the brain as `tools/shelf.py new-trains` (or a flag), reporting rows whose product has a newer train than any shelf row, so the brain can notice an 8.2 the way the Finder's `make versions` does. Brain conventions apply. E2 and E3 from the draft are dropped.

### F. Validate a composed block on a device

`docs/pipeline.md` names this as the feature the `abort` discipline was built for and says it is not built: paste the composed block into a scratch FortiGate inside a config context, read the parse errors, leave with `abort`. The lab now has everything it needs: scratch-tier config runs with no prompt, `lab run` with one CLI line per argument, and `clicheck` as the offline pre-check.

Tasks:

- **F1.** In the lab repo, `lab probe <device> --block FILE`: run `clicheck --train <device's train>` first; if clean, send the block to a scratch device with `abort` substituted for every `end` at depth zero, capture the device's error lines (the lab already parses `command parse error` and `Command fail. Return code -N`), and `diagnose sys ha checksum show` before and after as the proof nothing was written. Refuse on any non-scratch tier. Log as a normal record.
- **F2.** In the Finder, nothing ships to the page: the page is static and must not talk to a device. The integration is a documented workflow: copy the block, `uv run lab probe fgt-flex1 --block -`, read the result. A later `lab crawl` (A2 option b) belongs here too.

### G. Finder housekeeping the other two repos already did

- **G1.** Write a `CLAUDE.md` for the Finder: the stdlib rule, the overlay pattern, the public-repo rule from §2.3, `make check` as the gate, and the relationship to the other two repos in five lines. The brain's and the lab's are the models; keep it to a page.
- **G2.** The directory is `forti-cli-helper`, the remote and the README are `forti-cli-finder`. Patrick's call (§6 Q5): leave it. `CLAUDE.md` states both names in one line so a session is not confused.
- **G3.** `make check` runs `check_bundles.py`, four `--selftest`s and `check_page.py`; there is no `pytest` (`docs/pipeline.md` still says three selftests; fix the count while there). That is a deliberate choice recorded in `docs/pipeline.md` and this plan does not reverse it, but every new tool here ships a `--selftest` wired into `make check`, as the existing ones do.

### H. A usability review, in a real browser

Every Finder change so far was judged by `check_page.py`, a stub DOM, and whoever typed into it last. Patrick asked for a review of how it actually feels to use, done with the Chrome driver (the `claude-in-chrome` tools), against the real bundles.

Tasks:

- **H1. The walk.** Start `make serve`, open `http://localhost:8000` in a fresh tab, and drive the flows the README promises, keyboard only, recording a GIF of each: type `conf sys ha over` and watch the listing; tab-complete; enter into the inspector; `/dstaddr` jump on `config firewall policy`; `e` to add the nine fields; set values with left/right and enter; copy the block and paste it into a text field to check the quoting; `n`/`p` through sample output; `/ver` and `/fgt@8.0.1`; `/fsw diag`; ctrl-L; a nonsense command and an empty platform. Also: cold load time with the cache cleared (the bundles are 7.5MB), the console (`read_console_messages`, any error or warning), and a narrow window. Deliverable: `docs/usability-2026-11.md` with one row per flow (what the README says, what happened, a screenshot or GIF name, severity), the GIFs under `docs/usability/`, and a ranked list of fixes with the smallest fix per item. Nothing is changed in `index.html` during the review: it is a measurement.
- **H2. The fixes.** Each item from H1's list that Patrick picks becomes its own task; each fix adds an assertion to `check_page.py` where a stub DOM can express it, so the thing that was wrong stays caught. Re-run the relevant H1 flow afterwards and attach the new GIF.
- **H3. Repeat after waves 2 and 3.** B2, C2, C3, D1 and D4 all add to the inspector, which is the densest part of the page; H1's walk is re-run once they land, with the same document gaining a dated column.

## 4. Beyond the Finder: what else would help the engineer

Noted so they are not lost; none is in §5's first wave.

- **A FortiManager API composer.** `fmg-syntax-*-adom.json` (332 and 352 object types) plus `ref-how-to-fortimanager-api` in the brain, plus `lab api` to run it: the same keyboard-first page could compose `/pm/config/adom/{adom}/obj/firewall/address` calls with typed attributes. Professional Services engineers write these daily. A sixth "platform" in the Finder, built from the schema rather than a PDF. Q2 is answered yes, so nothing blocks it but priority; it is the first candidate for a wave 5.
- **Log IDs in the Finder.** The brain's `logid.py` resolves a ten-digit log ID to its chunk. A `/log 0100032001` slash command would need the log reference as a bundle; measure its size first, since the Finder ships everything to the browser.
- **The allowlist as a signal.** `lab/allow.yaml` names which `diagnose` paths a session may run without approval. Badge those entries in the Finder so an engineer or a session knows at a glance which diagnostics are "free" on the lab, and generate candidate additions from the cheat sheet. Widening the allowlist stays a hand edit, per its own header.
- **Frequency from more than the admin guide.** `fq` counts only admin-guide examples. The brain's `src-gh-fortinet-4d-demo` chunks are Fortinet's own reference configs; the lab's Verified suites are configs that provably work. Counting those too would move `fq` from "what the guide shows" toward "what a working build sets". Small, after B.
- **A proof page links back.** The lab's `proof.html` pages quote commands and output; each command could link to its Finder entry, and each Finder entry with a lab sample could link to the proof page that produced it. Both directions are URL work once B lands.

## 5. Sequencing, sizes, and dependencies

Sizes are for a careful lower model with the brief in §7. "Day" means one focused session.

| Wave | Task | Repo | Size | Needs first |
|---|---|---|---|---|
| 1 | A2 `lab crawl` (hooked, logged, resumable; selftest) | lab | 1 day | nothing |
| 1 | B1 `import_lab.py` with `--report` and the anonymiser | Finder | 1 day | nothing |
| 1 | C1 schema diff, report only | Finder | half a day | nothing |
| 1 | H1 usability walk in Chrome, findings document | Finder | half a day | nothing |
| 1 | G1 `CLAUDE.md` | Finder | an hour | nothing |
| 2 | A1 crawl a 7.6.7 and an 8.0.2 pool clone; `captures.json`; overlay | lab (run), Finder (commit) | 1 day, mostly waiting | A2 |
| 2 | B2 attach lab samples, checks | Finder | half a day | B1 |
| 2 | A3 measure 8.0.2 (and 7.6.8, expecting to skip), add what pays | Finder | half a day | A1 |
| 2 | D4 cite button and `doc_id` map | Finder | half a day | nothing |
| 2 | D1 ordering rules in the composer | Finder | half a day | nothing |
| 2 | H2 fixes Patrick picks from H1 | Finder | per item | H1 |
| 3 | C2, C3 references and option help | Finder | 1 day | C1 |
| 3 | D2, D3 findings and lint hints | Finder | half a day | B1's reader |
| 3 | B3, B4 the sample suite and "look for" | lab, Finder | 1 day | B2, a pool clone |
| 3 | A1 (rest) FMG/FAZ 8.0.2 crawls as one approved plan | lab | half a day | A2, Patrick present |
| 3 | H3 second usability walk | Finder | half a day | C2, D1, D4 |
| 4 | F1 `lab probe` | lab | 1 day | low urgency |
| 4 | E1 new-train check in the brain | brain | half a day | optional |

Parser fixes that C1 surfaces are their own tasks, one per finding, sized when the report exists.

## 6. Decisions, as Patrick made them on 2026-11-04

1. **Q1. How does the Finder read a lab device?** Build `lab crawl` first; coordinate it as a lab task. FMG and FAZ need more care: they are shared guests, so their crawl runs as one approved plan with Patrick present. Nothing crawls from the Finder repo.
2. **Q2. May derived facts from FortiManager's syntax metadata appear on the public page?** Yes.
3. **Q3. Which lab output may the Finder ship?** All of it, company devices included, because there is no real customer data in the lab; every output is anonymised first (B1 says how).
4. **Q4. Who owns weekly discovery?** Patrick. Both workflows stay; he reads both pull requests. E2 and E3 dropped, E1 optional.
5. **Q5. Rename the directory to match the remote?** Not worth it. Left as is, noted in `CLAUDE.md`.
6. **Q6. Does the Finder add 7.6.8?** Only if the measurement shows value; the expectation is that it does not. 8.0.2 is measured the same way and is the likelier addition.
7. **Added:** a usability review with the Chrome driver (workstream H), before and after the inspector grows.

## 7. The brief every task gets

A lower model is handed one task from §5 and this document. Its brief states, in this order:

1. The task id and the one paragraph from §3, verbatim.
2. The repo to work in, and the files to read before anything else: for the Finder, `README.md`, `docs/pipeline.md`, `Makefile`, and the tool nearest to the one being written (for H, the README's *Keys* table and `tools/check_page.py`); for the lab, `CLAUDE.md` and `README.md` (the `lab` command and Permissions sections) and `.claude/skills/replicate/SKILL.md`; for the brain, `CLAUDE.md` and the tool being changed.
3. The rules from §2, by number, that bind this task.
4. Acceptance: the exact commands whose output proves it is done (`make check` green; `python3 tools/<new>.py --report` showing counts; `make diff` output pasted into the commit message; for the lab, the policy-log lines per CLAUDE.md §11; for the brain, `uv run tools/vault.py lint && uv run pytest -q`).
5. What it must not do: touch the 70G or any address on VLAN 10; crawl or read a lab device from any repo but the lab's, through anything but `uv run lab`; write into `sources/` or `courses/`; add a dependency to the Finder; commit secrets or anything from `investigations/` beyond command text and anonymised output; widen `lab/allow.yaml`; commit in a repo the brief did not name.
6. The report shape: done, resolved alone, needs Patrick, each item with its evidence.

Every task ends with that report, and with the counts §2.6 asks for, before any commit.
