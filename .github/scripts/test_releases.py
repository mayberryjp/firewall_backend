import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import releases


COMMIT = "a" * 40
OTHER = "b" * 40
VERSION = "2026.10.30.6"


class PlanningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.previous = Path.cwd()
        os.chdir(self.temporary.name)
        releases.git("init", "-b", "main")
        releases.git("config", "user.name", "Release Test")
        releases.git("config", "user.email", "release@example.invalid")
        self.before = self.commit()
        seed = Path(releases.SEED_PATH)
        seed.parent.mkdir(parents=True)
        seed.write_text(VERSION)
        releases.git("add", ".")
        self.seed = self.commit()
        self.middle = self.commit()
        self.head = self.commit()

    def tearDown(self):
        os.chdir(self.previous)
        self.temporary.cleanup()

    def commit(self):
        releases.git("commit", "--allow-empty", "-m", "fixture")
        return releases.git("rev-parse", "HEAD")

    def event(self, before=None, ref="refs/heads/main", inputs=None):
        return {"repository": {"default_branch": "main"}, "ref": ref,
                "before": before or self.before, "inputs": inputs or {}}

    def test_multi_commit_push_and_new_branch_exclude_pre_automation_history(self):
        expected = [self.seed, self.middle, self.head]
        self.assertEqual(releases.plan("push", self.event(), self.head), (expected, True))
        self.assertEqual(releases.plan("push", self.event(before="0" * 40), self.head),
                         (expected, True))

    def test_pull_requests_and_other_branches_never_publish(self):
        for event_name, ref in [("pull_request", "refs/pull/1/merge"),
                                ("push", "refs/heads/feature")]:
            self.assertEqual(releases.plan(event_name, self.event(ref=ref), self.head),
                             ([self.head], False))
        event = self.event()
        event["deleted"] = True
        self.assertEqual(releases.plan("push", event, self.head), ([], False))

    def test_replay_ranges_and_force_push_refusal(self):
        event = self.event(inputs={"from_commit": self.seed, "to_commit": self.head})
        self.assertEqual(releases.plan("workflow_dispatch", event, self.head),
                         ([self.middle, self.head], True))
        for event in [self.event(before=OTHER),
                      self.event(inputs={"to_commit": OTHER}),
                      self.event(inputs={"from_commit": self.head, "to_commit": self.seed})]:
            with self.assertRaises(ValueError):
                releases.plan("workflow_dispatch" if event["inputs"] else "push", event, self.head)

    def test_side_branch_commits_are_not_default_branch_commits(self):
        releases.git("checkout", "-b", "feature")
        side = self.commit()
        releases.git("checkout", "main")
        releases.git("merge", "--no-ff", "feature", "-m", "merge fixture")
        merged = releases.git("rev-parse", "HEAD")
        selected, publishing = releases.plan("push", self.event(before=self.head), merged)
        self.assertEqual(selected, [merged])
        self.assertNotIn(side, selected)
        self.assertTrue(publishing)

    def test_matrix_limit_is_an_explicit_failure_not_truncation(self):
        commits = [f"{number:040x}" for number in range(1, 258)]
        with patch.object(releases, "mainline", return_value=commits), \
                patch.object(releases, "git", return_value=releases.SEED_PATH):
            with self.assertRaisesRegex(ValueError, "No commits were truncated"):
                releases.plan("push", self.event(before="0" * 40), commits[-1])


class FakeGitHub(releases.GitHub):
    def __init__(self):
        super().__init__("example/netcontrol")
        self.refs = {}
        self.releases = []
        self.changes = []
        self.uploads = 0
        self.fail_upload = False
        self.latest = None
        self.latest_error = None
        self.race_target = None

    def api(self, method, route, payload=None):
        self.changes.append((method, route, payload))
        if "/git/matching-refs/tags/" in route:
            tag = route.rsplit("/", 1)[-1]
            return ([{"ref": "refs/tags/" + tag,
                      "object": {"type": "commit", "sha": self.refs[tag]}}]
                    if tag in self.refs else [])
        if method == "POST" and route.endswith("/git/refs"):
            tag = payload["ref"].removeprefix("refs/tags/")
            if self.race_target:
                self.refs[tag] = self.race_target
                raise releases.APIError("tag race", 422)
            self.refs[tag] = payload["sha"]
            return {}
        if method == "GET" and route.endswith("/releases/latest"):
            if self.latest_error:
                raise self.latest_error
            if self.latest is None:
                raise releases.APIError("no latest release", 404)
            return copy.deepcopy(self.latest)
        if method == "GET" and "/releases?" in route:
            return copy.deepcopy(self.releases)
        if method == "POST" and route.endswith("/releases"):
            release = dict(payload, id=len(self.releases) + 1, assets=[])
            self.releases.append(release)
            return copy.deepcopy(release)
        identifier = int(route.rsplit("/", 1)[-1])
        release = next(item for item in self.releases if item["id"] == identifier)
        if method == "GET":
            return copy.deepcopy(release)
        if method == "PATCH":
            release.update(payload)
            if payload.get("make_latest") == "true":
                self.latest = release
            return copy.deepcopy(release)
        raise AssertionError((method, route, payload))

    def upload(self, tag, directory):
        self.uploads += 1
        if self.fail_upload:
            raise releases.APIError("injected upload failure", 500)
        release = next(item for item in self.releases if item["tag_name"] == tag)
        release["assets"] = [
            {"name": name, "size": size, "digest": "sha256:" + digest}
            for name, (size, digest) in releases.fingerprints(directory, tag[1:]).items()
        ]


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        binary = bytearray(64)
        binary[:6] = b"\x7fELF\x02\x01"
        binary[18] = 62
        (self.directory / releases.ASSETS[0]).write_bytes(binary)
        self.manifest = {"schema": 1, "version": VERSION,
                         "target": "ubuntu-amd64-systemd", "size": len(binary),
                         "sha256": hashlib.sha256(binary).hexdigest()}
        self.write_manifest()
        self.api = FakeGitHub()
        self.git = patch.object(releases, "git", return_value=COMMIT)
        self.history = patch.object(releases, "mainline", return_value=[COMMIT])
        self.git.start()
        self.history.start()

    def tearDown(self):
        self.history.stop()
        self.git.stop()
        self.temporary.cleanup()

    def write_manifest(self):
        (self.directory / releases.ASSETS[1]).write_text(json.dumps(self.manifest))

    def publish(self):
        releases.publish(self.api, COMMIT, VERSION, self.directory)

    def test_complete_release_and_rerun_do_not_duplicate_or_overwrite(self):
        self.publish()
        self.assertEqual(self.api.refs, {"v" + VERSION: COMMIT})
        self.assertFalse(self.api.releases[0]["draft"])
        self.assertEqual(self.api.releases[0]["make_latest"], "false")
        self.publish()
        self.assertEqual(len(self.api.releases), 1)
        self.assertEqual(self.api.uploads, 1)
        self.api.releases[0]["assets"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            self.publish()
        self.assertEqual(self.api.uploads, 1)

    def test_upload_failure_stays_draft_and_retry_repairs_it(self):
        self.api.fail_upload = True
        with self.assertRaises(releases.APIError):
            self.publish()
        self.assertTrue(self.api.releases[0]["draft"])
        self.api.fail_upload = False
        self.publish()
        self.assertFalse(self.api.releases[0]["draft"])
        self.assertEqual(len(self.api.releases), 1)

    def test_tag_collisions_are_never_reassigned(self):
        self.api.refs["v" + VERSION] = OTHER
        with self.assertRaisesRegex(ValueError, "refusing to move"):
            self.publish()
        self.assertEqual(self.api.refs["v" + VERSION], OTHER)
        self.assertEqual(self.api.releases, [])

    def test_only_same_commit_tag_creation_races_are_accepted(self):
        self.api.race_target = COMMIT
        self.publish()
        other = FakeGitHub()
        other.race_target = OTHER
        with self.assertRaises(releases.APIError):
            releases.publish(other, COMMIT, VERSION, self.directory)
        self.assertEqual(other.releases, [])

    def test_bad_artifacts_fail_before_creating_tags(self):
        for field, invalid in [("size", releases.BINARY_LIMIT + 1),
                               ("version", "2026.10.30.7"), ("schema", True),
                               ("sha256", "0" * 64)]:
            original = self.manifest[field]
            self.manifest[field] = invalid
            self.write_manifest()
            with self.assertRaises(ValueError):
                self.publish()
            self.manifest[field] = original
        self.assertEqual(self.api.refs, {})
        self.write_manifest()
        (self.directory / "unexpected.sig").write_bytes(b"not used")
        with self.assertRaises(ValueError):
            self.publish()

    def test_latest_uses_highest_successful_version_not_completion_order(self):
        self.publish()
        template = copy.deepcopy(self.api.releases[0])
        for number, iteration in enumerate([10, 9, 11], 2):
            release = dict(copy.deepcopy(template), id=number,
                           tag_name=f"v2026.10.30.{iteration}", draft=iteration == 11)
            self.api.releases.append(release)
            self.api.refs[release["tag_name"]] = COMMIT
        lookups_before = sum("/git/matching-refs/" in route for _, route, _ in self.api.changes)
        releases.promote_latest(self.api)
        self.assertEqual(self.api.latest["tag_name"], "v2026.10.30.10")
        lookups_after = sum("/git/matching-refs/" in route for _, route, _ in self.api.changes)
        self.assertEqual(lookups_after - lookups_before, 1)

    def test_latest_never_moves_backward_or_hides_authentication_errors(self):
        self.publish()
        self.api.latest = {"tag_name": "v2026.10.30.9"}
        with self.assertRaisesRegex(ValueError, "backward"):
            releases.promote_latest(self.api)
        self.api.latest_error = releases.APIError("forbidden", 403)
        with self.assertRaises(releases.APIError):
            releases.promote_latest(self.api)

    def test_github_errors_keep_http_status(self):
        result = subprocess.CompletedProcess([], 1, "", "gh: Reference already exists (HTTP 422)")
        with patch.object(subprocess, "run", return_value=result):
            with self.assertRaises(releases.APIError) as error:
                releases.GitHub("example/netcontrol").api("POST", "repos/example/netcontrol/git/refs", {})
        self.assertEqual(error.exception.status, 422)


if __name__ == "__main__":
    unittest.main()
