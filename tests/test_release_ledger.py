import json
import os

CONTRACT = "contracts/release_ledger.py"
# genlayer-test 0.29.2 defaults to the newest GenVM release, but the v0.3.0-rc
# releases ship no genvm-universal.tar.xz, so pin the last one that does.
GENVM = os.environ.get("GENVM_VERSION", "v0.2.16")

REPO = "Acme/tool"
TAG = "v1.0.0"
REL_RE = r"repos/acme/tool/releases/tags/v1\.0\.0"
REF_RE = r"repos/acme/tool/git/ref/tags/v1\.0\.0"
COMMIT = "a" * 40
D_LINUX = "sha256:" + "1" * 64
D_MAC = "sha256:" + "2" * 64


def asset(name, digest, size=100, downloads=5):
    return {"name": name, "size": size, "digest": digest, "download_count": downloads,
            "updated_at": "2026-11-01T00:00:00Z", "browser_download_url": f"https://x/{name}"}


def release(assets=None, rel_id=77, published="2026-11-01T10:00:00Z", draft=False):
    if assets is None:
        assets = [asset("tool-mac.tar.gz", D_MAC), asset("tool-linux.tar.gz", D_LINUX)]
    return {"id": rel_id, "tag_name": TAG, "published_at": published, "draft": draft,
            "prerelease": False, "assets": assets}


def ref(sha=COMMIT):
    return {"ref": f"refs/tags/{TAG}", "object": {"sha": sha, "type": "commit"}}


def mock_gh(vm, rel=None, tag_ref=None, rel_status=200, ref_status=200):
    vm.mock_web(REL_RE, {"status": rel_status, "body": json.dumps(release() if rel is None else rel)})
    vm.mock_web(REF_RE, {"status": ref_status, "body": json.dumps(ref() if tag_ref is None else tag_ref)})


def deploy(direct_deploy):
    return direct_deploy(CONTRACT, sdk_version=GENVM)


def pinned(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    mock_gh(direct_vm)
    c.pin(REPO, TAG)
    return c


def remock(vm, **kw):
    vm.clear_mocks()
    mock_gh(vm, **kw)


# --------------------------------------------------------------- pin + consensus

def test_pin_records_canonical_snapshot(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    mock_gh(direct_vm)
    fp = c.pin(REPO, TAG)
    p = c.get_pin("acme/TOOL", TAG)  # repo is case-insensitive
    assert p["status"] == "ok" and p["fingerprint"] == fp and len(fp) == 64
    assert p["commit"] == COMMIT
    assert [a["name"] for a in p["assets"]] == ["tool-linux.tar.gz", "tool-mac.tar.gz"]
    assert set(p["assets"][0]) == {"name", "size", "digest"}  # volatile fields dropped
    assert direct_vm.run_validator() is True


def test_validators_ignore_volatile_fields(direct_vm, direct_deploy):
    pinned(direct_vm, direct_deploy)
    remock(direct_vm, rel=release(assets=[asset("tool-linux.tar.gz", D_LINUX, downloads=999),
                                          asset("tool-mac.tar.gz", D_MAC, downloads=1)]))
    assert direct_vm.run_validator() is True


def test_validator_rejects_different_digest(direct_vm, direct_deploy):
    pinned(direct_vm, direct_deploy)
    remock(direct_vm, rel=release(assets=[asset("tool-linux.tar.gz", "sha256:" + "9" * 64),
                                          asset("tool-mac.tar.gz", D_MAC)]))
    assert direct_vm.run_validator() is False


def test_validator_rejects_different_commit(direct_vm, direct_deploy):
    pinned(direct_vm, direct_deploy)
    remock(direct_vm, tag_ref=ref("b" * 40))
    assert direct_vm.run_validator() is False


# --------------------------------------------------------------- recheck outcomes

def test_recheck_unchanged_is_ok(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    assert c.recheck(REPO, TAG) == "ok"
    assert c.get_pin(REPO, TAG)["checks"] == 1


def test_swapped_binary_is_tampered_and_sticky(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    remock(direct_vm, rel=release(assets=[asset("tool-linux.tar.gz", "sha256:" + "9" * 64),
                                          asset("tool-mac.tar.gz", D_MAC)]))
    assert c.recheck(REPO, TAG) == "tampered"
    findings = c.get_pin(REPO, TAG)["findings"]
    assert any("asset changed: tool-linux.tar.gz" in f for f in findings)
    # Attacker restores the original file: status stays tampered, evidence kept.
    remock(direct_vm)
    assert c.recheck(REPO, TAG) == "tampered"
    assert c.get_pin(REPO, TAG)["findings"] == findings


def test_tag_moved_is_tampered(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    remock(direct_vm, tag_ref=ref("b" * 40))
    assert c.recheck(REPO, TAG) == "tampered"
    assert any(f.startswith("tag moved") for f in c.get_pin(REPO, TAG)["findings"])


def test_recreated_release_is_tampered(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    remock(direct_vm, rel=release(rel_id=78))
    assert c.recheck(REPO, TAG) == "tampered"


def test_removed_asset_is_tampered(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    remock(direct_vm, rel=release(assets=[asset("tool-linux.tar.gz", D_LINUX)]))
    assert c.recheck(REPO, TAG) == "tampered"
    assert "asset removed: tool-mac.tar.gz" in c.get_pin(REPO, TAG)["findings"]


def test_added_asset_extends_pin(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    d_win = "sha256:" + "3" * 64
    remock(direct_vm, rel=release(assets=[asset("tool-linux.tar.gz", D_LINUX),
                                          asset("tool-mac.tar.gz", D_MAC),
                                          asset("tool-win.zip", d_win)]))
    assert c.recheck(REPO, TAG) == "updated"
    p = c.get_pin(REPO, TAG)
    assert p["status"] == "ok" and p["added_later"] == 1
    assert c.verify(REPO, TAG, "tool-win.zip", "3" * 64)["result"] == "match"
    assert c.recheck(REPO, TAG) == "ok"  # no double counting


def test_missing_then_restored(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    remock(direct_vm, rel_status=404)
    assert c.recheck(REPO, TAG) == "missing"
    remock(direct_vm)
    assert c.recheck(REPO, TAG) == "ok"


def test_transient_error_changes_nothing(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    remock(direct_vm, rel_status=502)
    with direct_vm.expect_revert("fetch"):
        c.recheck(REPO, TAG)
    p = c.get_pin(REPO, TAG)
    assert p["status"] == "ok" and p["checks"] == 0


# --------------------------------------------------------------- verify

def test_verify_results(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    assert c.verify(REPO, TAG, "tool-linux.tar.gz", "1" * 64) == {"result": "match", "release_status": "ok"}
    assert c.verify(REPO, TAG, "tool-linux.tar.gz", "SHA256:" + "1" * 64)["result"] == "match"
    assert c.verify(REPO, TAG, "tool-linux.tar.gz", "f" * 64)["result"] == "MISMATCH"
    assert c.verify(REPO, TAG, "nope.zip", "1" * 64)["result"] == "unknown_asset"
    assert c.verify(REPO, "v9.9.9", "x", "1" * 64)["result"] == "not_pinned"
    with direct_vm.expect_revert("64 hex"):
        c.verify(REPO, TAG, "tool-linux.tar.gz", "xyz")


def test_verify_reports_tampered_release(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    remock(direct_vm, tag_ref=ref("b" * 40))
    c.recheck(REPO, TAG)
    v = c.verify(REPO, TAG, "tool-linux.tar.gz", "1" * 64)
    assert v == {"result": "match", "release_status": "tampered"}


# --------------------------------------------------------------- input checks

def test_pin_twice_rejected(direct_vm, direct_deploy):
    c = pinned(direct_vm, direct_deploy)
    with direct_vm.expect_revert("already pinned"):
        c.pin(REPO, TAG)


def test_pin_errors(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    mock_gh(direct_vm, rel_status=404)
    with direct_vm.expect_revert("release not found"):
        c.pin(REPO, TAG)
    remock(direct_vm, rel=release(draft=True))
    with direct_vm.expect_revert("draft"):
        c.pin(REPO, TAG)
    with direct_vm.expect_revert("owner/name"):
        c.pin("not a repo", TAG)
    with direct_vm.expect_revert("unsupported characters"):
        c.pin(REPO, "v1/../x")
    with direct_vm.expect_revert("not pinned"):
        c.recheck(REPO, TAG)


def test_tag_with_slash_is_url_encoded(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    direct_vm.mock_web(r"releases/tags/release%2Fv2$", {"status": 200, "body": json.dumps(release())})
    direct_vm.mock_web(r"git/ref/tags/release%2Fv2$", {"status": 200, "body": json.dumps(ref())})
    c.pin(REPO, "release/v2")
    assert c.list_pins() == [{"key": "acme/tool@release/v2", "status": "ok", "checks": 0}]
