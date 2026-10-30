import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


SEED_PATH = "crates/netcontrol-core/release-version"
ASSETS = ("netcontrold-ubuntu-amd64", "netcontrol-ubuntu-amd64.json")
BINARY_LIMIT = 256 * 1024 * 1024


def version_key(value):
    match = re.fullmatch(r"([0-9]{4})\.([0-9]{2})\.([0-9]{2})\.([1-9][0-9]*)", value)
    if not match:
        raise ValueError(f"invalid calendar version: {value}")
    year, month, day, iteration = map(int, match.groups())
    if iteration > 4294967295:
        raise ValueError("version iteration exhausted")
    return datetime.date(year, month, day), iteration


def git(*arguments):
    return subprocess.run(
        ["git", *arguments], check=True, capture_output=True, text=True
    ).stdout.strip()


def mainline(commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected a full commit SHA")
    return git("rev-list", "--first-parent", "--reverse", commit).splitlines()


def plan(event_name, event, commit):
    if event.get("deleted"):
        return [], False
    default_ref = "refs/heads/" + event["repository"]["default_branch"]
    publish = event_name in ("push", "workflow_dispatch") and event["ref"] == default_ref
    if not publish:
        mainline(commit)
        return [commit], False
    history = mainline(commit)
    inputs = event.get("inputs") or {}
    target = inputs.get("to_commit") or commit
    if target not in history:
        raise ValueError("release target must be on the default branch's first-parent history")
    before = event.get("before") if event_name == "push" else inputs.get("from_commit")
    end = history.index(target) + 1
    start = end - 1
    if before:
        if before == "0" * 40:
            start = 0
        elif before in history[:end]:
            start = history.index(before) + 1
        else:
            raise ValueError("force pushes/reversed release ranges are not supported")
    commits = [
        sha for sha in history[start:end]
        if git("ls-tree", "--name-only", sha, "--", SEED_PATH) == SEED_PATH
    ]
    if len(commits) > 256:
        raise ValueError(
            "GitHub permits 256 matrix jobs; replay this range in batches with "
            "workflow_dispatch from_commit/to_commit. No commits were truncated."
        )
    return commits, True


class APIError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class GitHub:
    def __init__(self, repository):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid GitHub repository")
        self.repository = repository
        self.base = f"repos/{repository}"

    def api(self, method, route, payload=None):
        command = ["gh", "api", "--hostname", "github.com", "--method", method, route]
        if payload is not None:
            command += ["--input", "-"]
        result = subprocess.run(
            command, input=json.dumps(payload) if payload is not None else None,
            capture_output=True, text=True
        )
        if result.returncode:
            status = re.search(r"\(HTTP ([0-9]{3})\)", result.stderr)
            raise APIError(result.stderr.strip(), int(status[1]) if status else None)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def pages(self, route):
        values = []
        page = 1
        while True:
            batch = self.api("GET", f"{route}?per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ValueError("expected a paginated GitHub list")
            values.extend(batch)
            if len(batch) < 100:
                return values
            page += 1

    def tag_target(self, tag):
        matches = self.api("GET", f"{self.base}/git/matching-refs/tags/{tag}")
        exact = [ref for ref in matches if ref["ref"] == f"refs/tags/{tag}"]
        if not exact:
            return None
        if len(exact) != 1:
            raise ValueError("duplicate exact tag reference")
        target = exact[0]["object"]
        for _ in range(8):
            if target["type"] == "commit":
                return target["sha"]
            if target["type"] != "tag":
                break
            target = self.api("GET", f"{self.base}/git/tags/{target['sha']}")["object"]
        raise ValueError("release tag does not resolve to a commit")

    def ensure_tag(self, tag, commit):
        target = self.tag_target(tag)
        if target is None:
            try:
                self.api("POST", f"{self.base}/git/refs",
                         {"ref": f"refs/tags/{tag}", "sha": commit})
            except APIError as error:
                if error.status != 422:
                    raise
                if self.tag_target(tag) != commit:
                    raise
            target = self.tag_target(tag)
        if target != commit:
            raise ValueError(f"refusing to move existing tag {tag} to another commit")

    def upload(self, tag, directory):
        subprocess.run(
            ["gh", "release", "upload", tag,
             *(str(directory / name) for name in ASSETS), "--clobber",
             "--repo", f"github.com/{self.repository}"],
            check=True
        )


def fingerprints(directory, version):
    version_key(version)
    if {path.name for path in directory.iterdir()} != set(ASSETS):
        raise ValueError("release artifact must contain exactly the binary and JSON manifest")
    manifest_path = directory / ASSETS[1]
    if manifest_path.stat().st_size > 4096:
        raise ValueError("release manifest exceeds 4096 bytes")
    manifest = json.loads(manifest_path.read_bytes())
    if set(manifest) != {"schema", "version", "target", "size", "sha256"}:
        raise ValueError("unexpected manifest fields")
    if (type(manifest["schema"]) is not int or manifest["schema"] != 1
            or manifest["version"] != version
            or manifest["target"] != "ubuntu-amd64-systemd"
            or type(manifest["size"]) is not int
            or not 64 <= manifest["size"] <= BINARY_LIMIT
            or not isinstance(manifest["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])):
        raise ValueError("invalid release manifest")
    values = {}
    for name in ASSETS:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("release assets must be regular files")
        with path.open("rb") as source:
            values[name] = (path.stat().st_size, hashlib.file_digest(source, "sha256").hexdigest())
    if values[ASSETS[0]] != (manifest["size"], manifest["sha256"]):
        raise ValueError("binary does not match manifest size/digest")
    with (directory / ASSETS[0]).open("rb") as source:
        header = source.read(64)
    if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
        raise ValueError("release binary must be amd64 ELF")
    return values


def verify_assets(release, expected):
    for name, (size, digest) in expected.items():
        matches = [asset for asset in release["assets"] if asset["name"] == name]
        if (len(matches) != 1 or matches[0]["size"] != size
                or matches[0].get("digest") != "sha256:" + digest):
            raise ValueError(f"GitHub asset {name} is missing, duplicated or has a different size/digest")


def publish(api, commit, version, directory):
    if commit not in mainline(git("rev-parse", "HEAD")):
        raise ValueError("release commit is not on the workflow's default-branch history")
    expected = fingerprints(directory, version)
    tag = "v" + version
    api.ensure_tag(tag, commit)
    releases = [release for release in api.pages(f"{api.base}/releases")
                if release["tag_name"] == tag]
    if len(releases) > 1:
        raise ValueError("multiple releases for one tag")
    release = releases[0] if releases else api.api("POST", f"{api.base}/releases", {
        "tag_name": tag, "target_commitish": commit, "name": version,
        "body": f"Automated validated default-branch build.\n\nCommit: {commit}\n\n"
                f"[Changelog](https://github.com/{api.repository}/blob/{commit}/CHANGELOG.md)\n\n"
                "Ubuntu update assets trust this repository over HTTPS; SHA-256 is "
                "integrity checking, not independent publisher authentication.",
        "draft": True, "prerelease": False, "make_latest": "false",
    })
    if release["prerelease"]:
        raise ValueError("refusing to repurpose a prerelease")
    if not release["draft"]:
        verify_assets(release, expected)
        return
    api.upload(tag, directory)
    release = api.api("GET", f"{api.base}/releases/{release['id']}")
    verify_assets(release, expected)
    api.api("PATCH", f"{api.base}/releases/{release['id']}",
            {"draft": False, "make_latest": "false"})


def promote_latest(api):
    history = set(mainline(git("rev-parse", "HEAD")))
    candidates = []
    for release in api.pages(f"{api.base}/releases"):
        if release["draft"] or release["prerelease"]:
            continue
        tag = release["tag_name"]
        if not tag.startswith("v"):
            continue
        key = version_key(tag[1:])
        candidates.append((key, release))
    selected = None
    for _, release in sorted(candidates, key=lambda entry: entry[0], reverse=True):
        if api.tag_target(release["tag_name"]) in history:
            selected = release
            break
    if selected is None:
        print("No validated calendar release is available to promote.")
        return
    release = selected
    required = [asset for asset in release["assets"] if asset["name"] in ASSETS]
    assets = {asset["name"]: asset for asset in required}
    if set(assets) != set(ASSETS) or len(required) != len(ASSETS):
        raise ValueError("latest candidate is missing required assets")
    for name, limit in zip(ASSETS, (BINARY_LIMIT, 4096)):
        asset = assets[name]
        if not 0 < asset["size"] <= limit or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", asset.get("digest") or ""):
            raise ValueError("latest candidate has invalid asset metadata")
    try:
        current = api.api("GET", f"{api.base}/releases/latest")
    except APIError as error:
        if error.status != 404:
            raise
        current = None
    if current and version_key(current["tag_name"].removeprefix("v")) > version_key(release["tag_name"][1:]):
        raise ValueError("refusing to move latest backward")
    api.api("PATCH", f"{api.base}/releases/{release['id']}", {"make_latest": "true"})


def main():
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("plan")
    publishing = subcommands.add_parser("publish")
    publishing.add_argument("--commit", required=True)
    publishing.add_argument("--version", required=True)
    publishing.add_argument("--directory", type=Path, required=True)
    subcommands.add_parser("latest")
    arguments = parser.parse_args()
    if arguments.command == "plan":
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        event["ref"] = os.environ["GITHUB_REF"]
        commits, publishing = plan(os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_SHA"])
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write("matrix=" + json.dumps({"include": [{"commit": sha} for sha in commits]}) + "\n")
            output.write(f"count={len(commits)}\npublish={str(publishing).lower()}\n")
    elif arguments.command == "publish":
        publish(GitHub(os.environ["GITHUB_REPOSITORY"]),
                arguments.commit, arguments.version, arguments.directory)
    else:
        promote_latest(GitHub(os.environ["GITHUB_REPOSITORY"]))


if __name__ == "__main__":
    main()
