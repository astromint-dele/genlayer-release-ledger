# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
ReleaseLedger: consensus-pinned GitHub releases with tamper detection.

A downloaded binary's checksum only proves it matches what the publisher
uploaded *today*. ReleaseLedger records what a release looked like when it
was pinned, agreed by independent validators, so later swaps are visible:

  pin(repo, tag)      validators fetch the release from the GitHub API and
                      must produce a byte-identical canonical snapshot
                      (strict equality): tag commit, release id,
                      publish time, and every asset's name, size and
                      GitHub-computed sha256 digest.
  recheck(repo, tag)  anyone re-snapshots under the same consensus and the
                      contract diffs it deterministically against the pin:
                        - existing asset digest/size changed, asset removed,
                          tag moved to another commit, release re-created
                          -> status "tampered" (sticky, never cleared)
                        - only new assets added -> pin extended, "updated"
                        - release or tag gone -> status "missing"
  verify(...)         view: does my file's sha256 match the pinned digest?

Snapshots exclude volatile fields (download counts, timestamps of edits,
prerelease flag), so honest validators converge on exact equality.
"""
from dataclasses import dataclass
import hashlib
import json
import re

from genlayer import *

API = "https://api.github.com"
HEADERS = {"User-Agent": "genlayer-release-ledger", "Accept": "application/vnd.github+json"}
MAX_ASSETS = 100
REPO_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}")
TAG_RE = re.compile(r"[A-Za-z0-9._/+-]{1,100}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")

OK = "ok"
TAMPERED = "tampered"
MISSING = "missing"


@allow_storage
@dataclass
class Pin:
    repo: str
    tag: str
    snapshot: str      # canonical JSON of the pinned release
    fingerprint: str   # sha256 of the original snapshot
    status: str        # ok | tampered | missing
    findings: str      # JSON list of human-readable findings from the last bad recheck
    pinned_by: Address
    checks: u256       # successful rechecks
    added_later: u256  # assets appended after pinning


# ---------------------------------------------------------------- pure helpers

def norm_repo(repo: str) -> str:
    repo = repo.strip()
    if not REPO_RE.fullmatch(repo):
        raise gl.vm.UserError("repo must look like owner/name")
    return repo.lower()


def norm_tag(tag: str) -> str:
    tag = tag.strip()
    if not TAG_RE.fullmatch(tag) or ".." in tag:
        raise gl.vm.UserError("tag has unsupported characters")
    return tag


def pin_key(repo: str, tag: str) -> str:
    return f"{repo}@{tag}"


def url_part(s: str) -> str:
    """Percent-encode everything except unreserved characters."""
    return "".join(c if c.isalnum() or c in "-._~" else "%{:02X}".format(ord(c)) for c in s)


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def fingerprint(snapshot: str) -> str:
    return hashlib.sha256(snapshot.encode("utf-8")).hexdigest()


def get_json(url: str) -> tuple[int, dict | list | None]:
    resp = gl.nondet.web.get(url, headers=HEADERS)
    if resp.status != 200:
        return resp.status, None
    body = resp.body or b""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    try:
        return 200, json.loads(body)
    except ValueError:
        return 0, None


def take_snapshot(repo: str, tag: str) -> str:
    """Canonical release snapshot, or 'ERR:<kind>:<detail>'. Runs in nondet."""
    status, rel = get_json(f"{API}/repos/{repo}/releases/tags/{url_part(tag)}")
    if status == 404:
        return "ERR:missing:release not found"
    if status != 200 or not isinstance(rel, dict):
        return f"ERR:fetch:release lookup failed (HTTP {status})"
    status, ref = get_json(f"{API}/repos/{repo}/git/ref/tags/{url_part(tag)}")
    if status == 404:
        return "ERR:missing:tag not found"
    if status != 200 or not isinstance(ref, dict):
        return f"ERR:fetch:tag lookup failed (HTTP {status})"
    if rel.get("draft"):
        return "ERR:invalid:draft releases cannot be pinned"
    raw_assets = rel.get("assets") or []
    if len(raw_assets) > MAX_ASSETS:
        return f"ERR:invalid:more than {MAX_ASSETS} assets"
    assets = sorted(
        ({"name": str(a.get("name", "")), "size": int(a.get("size") or 0),
          "digest": str(a.get("digest") or "")} for a in raw_assets),
        key=lambda a: a["name"],
    )
    obj = ref.get("object") or {}
    return canon({
        "repo": repo,
        "tag": tag,
        "release_id": int(rel.get("id") or 0),
        "published_at": str(rel.get("published_at") or ""),
        "commit": {"sha": str(obj.get("sha") or ""), "type": str(obj.get("type") or "")},
        "assets": assets,
    })


def consensus_snapshot(repo: str, tag: str) -> str:
    """Strict-equality consensus: each validator takes its own snapshot and
    accepts only a byte-identical result (same semantics as
    gl.eq_principle.strict_eq, written out so it is testable in direct mode).
    Errors are returned as 'ERR:' strings, so validators also agree on them."""
    def leader_fn() -> str:
        return take_snapshot(repo, tag)

    def validator_fn(leader_res) -> bool:
        if not isinstance(leader_res, gl.vm.Return) or not isinstance(leader_res.calldata, str):
            return False
        return take_snapshot(repo, tag) == leader_res.calldata

    return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)


def compare(old: dict, new: dict) -> tuple[list[str], list[str], list[dict]]:
    """Deterministic diff -> (tamper findings, info notes, added assets)."""
    bad, info = [], []
    if new["commit"] != old["commit"]:
        bad.append(f"tag moved: {old['commit']['sha'][:12]} -> {new['commit']['sha'][:12]}")
    if new["release_id"] != old["release_id"]:
        bad.append("release was deleted and re-created")
    if new["published_at"] != old["published_at"]:
        info.append(f"published_at changed: {old['published_at']} -> {new['published_at']}")
    old_assets = {a["name"]: a for a in old["assets"]}
    new_assets = {a["name"]: a for a in new["assets"]}
    for name in sorted(old_assets.keys() - new_assets.keys()):
        bad.append(f"asset removed: {name}")
    for name in sorted(old_assets.keys() & new_assets.keys()):
        o, n = old_assets[name], new_assets[name]
        if o["digest"] != n["digest"] or o["size"] != n["size"]:
            bad.append(f"asset changed: {name} ({o['digest'] or 'no digest'} -> {n['digest'] or 'no digest'})")
    added = [new_assets[n] for n in sorted(new_assets.keys() - old_assets.keys())]
    for a in added:
        info.append(f"asset added: {a['name']}")
    return bad, info, added


def raise_fetch_error(snap: str) -> None:
    _, kind, detail = snap.split(":", 2)
    raise gl.vm.UserError(f"{kind}: {detail}")


# ---------------------------------------------------------------- contract

class ReleaseLedger(gl.Contract):
    pins: TreeMap[str, Pin]
    keys: DynArray[str]

    def __init__(self):
        pass

    @gl.public.write
    def pin(self, repo: str, tag: str) -> str:
        repo, tag = norm_repo(repo), norm_tag(tag)
        key = pin_key(repo, tag)
        if key in self.pins:
            raise gl.vm.UserError("already pinned; use recheck")
        snap = consensus_snapshot(repo, tag)
        if snap.startswith("ERR:"):
            raise_fetch_error(snap)
        self.pins[key] = Pin(
            repo=repo, tag=tag, snapshot=snap, fingerprint=fingerprint(snap),
            status=OK, findings="[]", pinned_by=gl.message.sender_address,
            checks=u256(0), added_later=u256(0),
        )
        self.keys.append(key)
        return fingerprint(snap)

    @gl.public.write
    def recheck(self, repo: str, tag: str) -> str:
        repo, tag = norm_repo(repo), norm_tag(tag)
        key = pin_key(repo, tag)
        if key not in self.pins:
            raise gl.vm.UserError("not pinned")
        p = self.pins[key]
        snap = consensus_snapshot(repo, tag)

        if snap.startswith("ERR:missing:"):
            if p.status != TAMPERED:  # tampered is sticky and keeps its evidence
                p.status = MISSING
                p.findings = canon([snap.split(":", 2)[2]])
                self.pins[key] = p
            return p.status
        if snap.startswith("ERR:"):
            raise_fetch_error(snap)  # transient: no state change, try later

        old, new = json.loads(p.snapshot), json.loads(snap)
        bad, info, added = compare(old, new)
        p.checks = u256(int(p.checks) + 1)
        if p.status == TAMPERED:
            # Sticky: keep the original evidence, only count the check.
            self.pins[key] = p
            return TAMPERED
        if bad:
            p.status = TAMPERED
            p.findings = canon(bad + info)
            self.pins[key] = p
            return TAMPERED
        if p.status == MISSING:
            p.status = OK  # release is back and unchanged
        if added:
            old["assets"] = sorted(old["assets"] + added, key=lambda a: a["name"])
            p.snapshot = canon(old)
            p.added_later = u256(int(p.added_later) + len(added))
        p.findings = canon(info)
        self.pins[key] = p
        return "updated" if added else OK

    @gl.public.view
    def verify(self, repo: str, tag: str, asset_name: str, sha256_hex: str) -> dict:
        """Check a downloaded file's sha256 against the consensus-pinned digest."""
        repo, tag = norm_repo(repo), norm_tag(tag)
        key = pin_key(repo, tag)
        if key not in self.pins:
            return {"result": "not_pinned", "release_status": ""}
        p = self.pins[key]
        h = sha256_hex.strip().lower().removeprefix("sha256:")
        if not SHA256_RE.fullmatch(h):
            raise gl.vm.UserError("sha256 must be 64 hex characters")
        assets = {a["name"]: a for a in json.loads(p.snapshot)["assets"]}
        a = assets.get(asset_name)
        if a is None:
            result = "unknown_asset"
        elif not a["digest"]:
            result = "no_digest_on_record"
        else:
            result = "match" if a["digest"] == f"sha256:{h}" else "MISMATCH"
        return {"result": result, "release_status": p.status}

    @gl.public.view
    def get_pin(self, repo: str, tag: str) -> dict:
        key = pin_key(norm_repo(repo), norm_tag(tag))
        if key not in self.pins:
            raise gl.vm.UserError("not pinned")
        p = self.pins[key]
        snap = json.loads(p.snapshot)
        return {
            "repo": p.repo, "tag": p.tag, "status": p.status,
            "fingerprint": p.fingerprint, "commit": snap["commit"]["sha"],
            "published_at": snap["published_at"], "assets": snap["assets"],
            "findings": json.loads(p.findings), "checks": int(p.checks),
            "added_later": int(p.added_later), "pinned_by": p.pinned_by.as_hex,
        }

    @gl.public.view
    def list_pins(self) -> list:
        out = []
        for key in self.keys:
            p = self.pins[key]
            out.append({"key": key, "status": p.status, "checks": int(p.checks)})
        return out
