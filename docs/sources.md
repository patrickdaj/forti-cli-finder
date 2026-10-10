# Where the sample output comes from

Most Fortinet guides are GUI-facing and contain no CLI output at all. Rather than guess,
every candidate below was downloaded and run through `tools/extract_outputs.py`. The
numbers are distinct commands / total samples found in that document.

Re-measure any guide with:

    python3 tools/prospect.py /document/fortigate/7.6.7/new-features

## In the build

| Document | Commands | Samples | Feeds |
|---|---:|---:|---|
| FortiOS 7.6.7 Administration Guide | 720 | 1734 | FortiOS |
| FortiOS 7.4.12 Administration Guide | 578 | 1403 | FortiOS |
| FortiOS 7.4.0 New Features Guide | 219 | 445 | FortiOS |
| FortiOS 7.6.0 New Features Guide | 215 | 419 | FortiOS |
| FortiSwitchOS 7.6.7 FortiLink Guide | 36 | 51 | FortiOS + FortiSwitch |
| FortiSwitchOS 7.6.7 Administration Guide | 14 | 19 | FortiSwitch |
| FortiAnalyzer 7.6.7 Administration Guide | 9 | 12 | FortiAnalyzer |
| FortiManager 7.6.7 Administration Guide | 7 | 10 | FortiManager |
| NSE 4 / FortiSwitch course material (hand-transcribed) | 47 | 47 | FortiOS + FortiSwitch |

The older FortiOS guides are included because a 7.4 sample for a command the 7.6 guide
never shows is still worth having. They rank below current-firmware guides, so where both
cover a command the 7.6 sample wins; `sources.json` sets that with `rank`.

Overlap is heavy. The four FortiOS guides contain 831 distinct commands between them, only
111 more than the 7.6.7 Administration Guide alone.

## Measured and rejected (0-2 commands each)

FortiOS Carrier · Hyperscale Firewall Guide · Hardware Acceleration · Parallel Path
Processing · Best Practices · ZTNA Reference Guide · SD-WAN Architecture for Enterprise ·
NGFW Web Security Deployment · FortiGate 6000 and 7000F Administration Guides ·
FortiSwitch Large Campus / LAN Edge / VXLAN deployment guides · FortiAnalyzer Best
Practices · FortiManager Examples.

These are prose and screenshots. Not worth the download.

## The CLI troubleshooting cheat sheet

`/document/fortigate/7.6.4/cli-troubleshooting-cheat-sheet` has no output either, but it is
a curated two-column table of the commands Fortinet considers worth knowing. That is the
natural source for an "essential commands" marking, which the Finder does not have yet.

## What this means for coverage

Sample output is limited by what Fortinet publishes, not by the extractor. Counting only
commands that can actually produce output (`config` prints nothing, so it is excluded):

| | output-capable | own sample | + inherited | shows something |
|---|---:|---:|---:|---:|
| FortiOS | 5217 | 500 | 523 | 19.6% |
| FortiSwitch | 284 | 23 | 26 | 17.3% |
| FortiAnalyzer | 239 | 9 | 0 | 3.8% |
| FortiManager | 277 | 7 | 0 | 2.5% |

"Inherited" is a command with no sample of its own shown the nearest ancestor that has one,
labelled as such -- `diagnose debug application acd` has no sample anywhere, but
`diagnose debug application` does, and seeing it is better than an empty pane.

The FortiOS denominator is inflated: 2808 of the uncovered sections are generated leaves of
the command tree with no parameters and a one-line syntax. Output for those does not exist
in any Fortinet document.

## HTML instead of PDF

docs.fortinet.com serves every guide as HTML with CLI blocks in real `<pre>` tags, which
needs no column reconstruction. It was not adopted because each topic page ships the whole
1414-entry table of contents, so harvesting one guide means ~1.1GB of transfer for content
the PDF already yields. Worth revisiting if the PDF extractor starts losing blocks, or for
a guide published only as HTML.

## Samples under a build they were not written for

A platform may ship more than one firmware build (`fortios` and `fortios-8.0`), and the
guides we mine are version-specific -- there is no 8.0 Administration Guide in `output` at
the time of writing. A `target` list may therefore name several builds of one platform,
and a sample then attaches to each build whose command tree actually contains the command.

That is deliberate, and it is honest because provenance travels with the sample: a
`diagnose sniffer packet` capture taken from the FortiOS 7.6 study guide and shown under
the 8.0 build still prints "FortiOS 7.6 Administrator study guide (annotated), p.488"
under it. The alternative -- an 8.0 bundle with no sample output at all -- is worse and
no more truthful.

Builds of one platform never compete with each other for a sample. The platform question
("is this switch-controller command FortiGate's or FortiSwitch's?") is settled first, by
the longest path match any of a platform's builds found; then every build of the winning
platform takes its own best match, or, having none, becomes a candidate for a new entry.
A command 8.0 documents more deeply must not stop 7.6.7 recording the one it has.
