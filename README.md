# ReleaseLedger: consensus-pinned GitHub releases with tamper detection

A checksum only proves a download matches what the publisher serves **today**.
If an attacker swaps a release binary and its checksum file together, a
SHA256SUMS check still passes. ReleaseLedger records what a release looked
like when it was **pinned**, agreed by independent GenLayer validators, so a
later swap, a moved tag or a re-created release is visible to everyone.

```
pin("PsyProtocol/psy-node", "v0.1.1")      -> fingerprint of the snapshot
verify("PsyProtocol/psy-node", "v0.1.1",
       "psy-node-v0.1.1-x86_64-unknown-linux-gnu.tar.gz", "<sha256 of my file>")
                                            -> {"result": "match", "release_status": "ok"}
recheck("PsyProtocol/psy-node", "v0.1.1")  -> "ok" | "updated" | "tampered" | "missing"
```

Use cases:
- installers and CI checking binaries against an on-chain record
- node operators verifying client releases before upgrading
- package registries and security monitors watching for release tampering

## Deployment

| Network | Address |
|---|---|
| GenLayer Studio | [`0x215d0C1D99e5391f50aD092B85CBD662687e5Cb6`](https://explorer-studio.genlayer.com/address/0x215d0C1D99e5391f50aD092B85CBD662687e5Cb6) |

Open it in Studio: https://studio.genlayer.com/?import-contract=0x215d0C1D99e5391f50aD092B85CBD662687e5Cb6

### Live run (Studio, full consensus)

```
pin("PsyProtocol/psy-node", "v0.1.1")     -> FINALIZED
get_pin(...)  -> status "ok", 5 assets with GitHub sha256 digests,
                 commit 19f8d985f045c2961bcd2ea08ccbe03a1d6e0219,
                 fingerprint 1529d33c7a09776cfc2c5c2b7479d44901464c93adb1d9d9d5222c0dd055c1ef
verify(..., "psy-node-v0.1.1-x86_64-unknown-linux-gnu.tar.gz",
       "96ca061f1966fe6f682dba1e44aae13da4eed582a3e7888271c8e3e9966df334")
              -> {"result": "match", "release_status": "ok"}
recheck(...)  -> FINALIZED (unchanged release)
```

The pinned commit and all 5 digests were cross-checked against the GitHub API
independently.

## How consensus is used

Validators fetch the GitHub REST API directly (no oracle) and must agree on a
**byte-identical canonical snapshot**: strict-equality consensus, using
`gl.vm.run_nondet_unsafe` with a validator that re-snapshots and compares
exactly.

| Snapshot field | Source |
|---|---|
| tag commit sha + object type | `GET /repos/{repo}/git/ref/tags/{tag}` |
| release id, published_at | `GET /repos/{repo}/releases/tags/{tag}` |
| every asset: name, size, **GitHub-computed sha256 digest** | same |

The design work is in making exact equality reachable for honest validators:
- **Volatile fields are excluded**: download counts, asset `updated_at`, URLs,
  the prerelease flag. Assets are sorted, and JSON is canonicalised (sorted
  keys, fixed separators).
- **Errors are values.** The leader returns `ERR:<kind>:<detail>`
  (`missing`, `fetch`, `invalid`) instead of raising, so validators agree on
  failures too. State changes only after consensus, outside the nondet block.

## Tamper detection

`recheck` re-snapshots under the same consensus, and the contract diffs it
**deterministically** against the pin:

| Change since pin | Result |
|---|---|
| existing asset's digest or size changed | **tampered** |
| asset removed | **tampered** |
| tag points at a different commit | **tampered** |
| release deleted and re-created (new release id) | **tampered** |
| only new assets added (e.g. a late platform build) | **updated**: pin extended, `added_later` counted |
| release or tag gone (404) | **missing**: cleared if it returns unchanged |
| transient error (rate limit, 5xx) | reverts, no state change; try again |

`tampered` is **sticky**. The original findings are kept even if the attacker
later restores the file, because a release that was swapped once can't be
trusted again. Each pin also stores a sha256 **fingerprint** of the original
snapshot.

## Methods

| Method | Kind | Notes |
|---|---|---|
| `pin(repo, tag) -> str` | write, consensus | returns the snapshot fingerprint. Drafts are rejected; one pin per repo@tag |
| `recheck(repo, tag) -> str` | write, consensus | `ok` / `updated` / `tampered` / `missing` |
| `verify(repo, tag, asset_name, sha256) -> dict` | view | `match` / `MISMATCH` / `unknown_asset` / `no_digest_on_record` / `not_pinned`, plus the release status |
| `get_pin(repo, tag) -> dict` | view | commit, assets, status, findings, checks |
| `list_pins() -> list` | view | |

**Inputs:**
- `repo` is `owner/name` and is case-insensitive.
- Tags may contain `/` (they're percent-encoded), but `..` is rejected.
- A release can have at most 100 assets.

## State

```
pins: TreeMap[str, Pin]   "owner/repo@tag" -> Pin(repo, tag, snapshot, fingerprint,
                          status, findings, pinned_by, checks, added_later)
keys: DynArray[str]       pin order, for list_pins
```

## Tests (direct mode, no Docker)

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
.venv/Scripts/python -m pytest tests/ -v
```

There are 17 tests:
- the canonical snapshot
- validators agree despite different download counts, and disagree on a
  different digest or commit
- each recheck outcome: unchanged, swapped binary (sticky, with evidence kept
  after a restore), tag moved, re-created release, removed asset, added asset,
  missing then restored, transient error
- `verify` results
- input validation
- URL-encoding of tags containing `/`

**Mutation-checked:** each of these, when disabled, makes its tests fail:
- an "accept anything" validator
- download counts left in the snapshot
- ignoring tag moves
- non-sticky tampering

`GENVM_VERSION` defaults to `v0.2.16`, and `tests/conftest.py` patches a
Windows-only temp-file bug in genlayer-test.

## Limits

- **GitHub only.** Unauthenticated API calls are rate-limited (60/hour per IP).
  A rate-limited validator disagrees, which delays consensus, and a
  rate-limited leader makes the call revert so it can be retried.
- **Trust starts at the pin.** If a release is already tampered when pinned,
  the ledger records the tampered state. Pin early, ideally right after
  publishing.
- **Older releases may have no digest.** GitHub has added asset digests over
  time. For those, `verify` returns `no_digest_on_record`, and only name and
  size changes are detected.
