# Usability review, 2026-11-04

Task H1 of `docs/superpowers/plans/2026-11-04-use-the-lab-and-the-brain.md`. The page was
served with `make serve` from commit `4ad6b42` and driven keyboard-only in Chrome through the
`claude-in-chrome` tools, at 1280 wide, then 760 and 333. Nothing in `site/` was changed: this
is a measurement. H2 turns the items Patrick picks into fixes, each with a `check_page.py`
assertion.

A 50-frame recording of the walk was captured but not exported: exporting is a browser
download, which needs Patrick's go-ahead. The steps below reproduce every finding.

## Flows

| # | Flow | README says | What happened | Severity |
|---|---|---|---|---|
| 1 | `conf sys ha over` | prefixes expand, listing above the prompt | expands correctly, `override` matched inside the HA table, 4 of 96 parameters filtered | works |
| 2 | enter on a listing row | "open in the inspector, keep it in the scrollback, move focus there" | focus moves to the inspector, but **nothing is added to the scrollback** and the prompt keeps the query. Repeated with `diag sys session list`: same | medium |
| 3 | focus in the inspector | — | the only cue that focus moved is a thin border on one row; the prompt still looks live | low |
| 4 | `/dstaddr` on `config firewall policy` | filters as you type, enter lands the cursor | filters to 4 of 186, enter lands on `dstaddr`. Works well | works |
| 5 | `e` after the jump | adds the nine fields | adds them, but the block grows above the list and **the selected row ends up below the viewport** (row top at 717px in a 681px window). The user loses their place | high |
| 6 | enter, type `web servers`, enter on `dstaddr` | quoted the way `show` prints | becomes `set dstaddr "web" "servers"`: a list field splits on the space, so a single object name containing a space cannot be entered, and nothing on screen says so | medium |
| 7 | `e` fields default | — | `set action deny` is added because deny is the default; a block built with `e` is a deny policy unless the user changes it | low (by design, but surprising) |
| 8 | worked examples | "worked examples from the guides" | **238 of 713 FortiOS examples (179 tables) are syntax templates**, not configurations: `set evpn-ttl <integer>`, `set hb-interval-in-milliseconds {100ms \| 10ms}`, `set diffserv-copy {enable \| disable}`. 8.0: 237 of 709. Four more are a bare `delete 27` | high (data) |
| 9 | `n` / `p` on `get sys ha status` | next or previous sample | pages 1 of 8 to 2 of 8 with caption and "look for" line. Works | works |
| 10 | sample output width | — | long lines are clipped at the right edge of the pane; only horizontal scroll reveals them | low |
| 11 | `/ver` | lists builds | lists FGT 7.6.7 and 8.0.1 with sources, marks the current one | works |
| 12 | `/fgt@8.0.1`, then `/fsw diag` | switch build, then platform and type | both work; each slash reply replaces the previous one in the scrollback, so the history of switches is not kept | low |
| 13 | `/fgt` after `/fsw diag` | — | returns to FortiGate but keeps **8.0.1 and the `diag` filter**; the prompt says so (`FGT-8.0.1 (diag)`), so it is visible, just sticky | low |
| 14 | nonsense query `xyzzy plugh` | — | "% no command or help text matches", in the CLI's own voice. Good | works |
| 15 | ctrl-L | clear the scrollback | clears it | works |
| 16 | console | — | no message from the page. The only entries come from a browser extension | works |
| 17 | load | ~7.5MB | **all five bundles load at startup, 16MB uncompressed** (fortios 5.7MB, fortios-8.0 6.1MB, the other three 1.1 to 1.3MB), although only one platform is shown. Parse is 15ms per large bundle; on localhost the page is interactive at 281ms. The README's 7.5MB figure predates the 8.0 bundle | medium on a slow link |
| 18 | 760 wide | — | both panes fit | works |
| 19 | 333 wide | — | stacks: listing only, enter opens the inspector full-width with a "back to the CLI" link. The command box clips the command under the copy button | low |

## Ranked fixes, smallest change first within each

1. **Keep the cursor row visible after `e`** (flow 5). After the block re-renders, scroll the
   selected row into view (`scrollIntoView({block:'nearest'})`). `check_page.py`: after `e`,
   the cursor row is inside the pane's visible rectangle.
2. **Filter template syntax out of worked examples** (flow 8). In
   `tools/extract_config_examples.py`, drop a block when any `set` value matches
   `{a | b}`, `<word>` or `[a|b]`; drop bare `delete N` blocks. Expect about a third of
   examples to go, and `fq` to be recomputed over real blocks only. Report the before and after
   counts per bundle with `make diff`. `check_bundles.py`: no shipped example carries template
   syntax.
3. **Put the entered command in the scrollback** (flow 2), as the README promises, and clear
   the prompt; or change the README. The CLI metaphor argues for the first.
4. **Lazy-load bundles** (flow 17). Fetch the default build at startup and the others on first
   switch; the build-switch race is already asserted in `check_page.py`, so the risk is covered.
   Fix the README's size figure in the same change.
5. **Say how to enter a name with a space** (flow 6): accept `"web servers"` typed with quotes
   as one element, and show `space separates names; quote a name with spaces` under the field.
6. **A visible focus state for the inspector** (flow 3): dim the prompt line while focus is in
   the inspector.
7. **Wrap or soft-wrap sample output** (flow 10), behind a key if wrapping hurts alignment.
8. Low: keep slash replies in the scrollback (12), make the narrow command box wrap (19).

Item 2 is a data fix and will change the bundles; the rest are page logic.
