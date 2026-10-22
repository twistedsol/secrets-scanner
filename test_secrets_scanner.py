import json
import tempfile
import unittest
from pathlib import Path

import secrets_scanner as ss

# Fake secrets are built from pieces at run time so this test file itself
# does not look like a leaked secret to other scanners.
AWS_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK_TOKEN = "xoxb-" + "1234567890-abcdefghij"
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".abcdefghij1234567890"


def ids(text):
    return [f.rule_id for f in ss.scan_text(text)]


class RuleTests(unittest.TestCase):
    def test_aws_access_key_id(self):
        self.assertEqual(ids(f'key = "{AWS_ID}"'), ["aws-access-key-id"])

    def test_temporary_aws_key_prefix(self):
        self.assertIn("aws-access-key-id", ids("ASIA" + "IOSFODNN7EXAMPLE"))

    def test_aws_secret_access_key(self):
        self.assertIn(
            "aws-secret-access-key", ids(f'AWS_SECRET_ACCESS_KEY = "{AWS_SECRET}"')
        )

    def test_aws_secret_with_colon_style(self):
        self.assertIn(
            "aws-secret-access-key", ids(f"aws_secret_access_key: {AWS_SECRET}")
        )

    def test_private_key_header(self):
        self.assertEqual(ids(PRIVATE_KEY), ["private-key"])

    def test_openssh_private_key_header(self):
        self.assertEqual(ids("-----BEGIN OPENSSH " + "PRIVATE KEY-----"), ["private-key"])

    def test_github_token(self):
        self.assertEqual(ids(f"token {GITHUB_TOKEN}"), ["github-token"])

    def test_slack_token(self):
        self.assertEqual(ids(f"SLACK={SLACK_TOKEN}"), ["slack-token"])

    def test_password_in_url(self):
        self.assertEqual(
            ids("curl https://admin:Hunter2Hunter2@host.example/x"), ["password-in-url"]
        )

    def test_url_without_password_is_clean(self):
        self.assertEqual(ids("curl https://host.example/path?a=1"), [])

    def test_url_with_username_only_is_clean(self):
        self.assertEqual(ids("git clone https://user@host.example/repo.git"), [])

    def test_json_web_token(self):
        self.assertEqual(ids(f"Authorization: Bearer {JWT}"), ["json-web-token"])

    def test_hardcoded_password(self):
        self.assertEqual(ids('DB_PASSWORD = "Winter2026Backup!"'), ["hardcoded-secret"])

    def test_hardcoded_api_key_in_json_style(self):
        self.assertEqual(ids('{"api_key": "k3y-value-98765"}'), ["hardcoded-secret"])

    def test_single_quotes_are_found(self):
        self.assertEqual(ids("password = 'Winter2026Backup!'"), ["hardcoded-secret"])


class FalsePositiveTests(unittest.TestCase):
    def test_environment_lookup_is_clean(self):
        self.assertEqual(ids('PASSWORD = os.environ["DB_PASSWORD"]'), [])

    def test_changeme_placeholder_is_skipped(self):
        self.assertEqual(ids('password = "changeme-please"'), [])

    def test_template_variable_is_skipped(self):
        self.assertEqual(ids('token = "${DEPLOY_TOKEN}"'), [])

    def test_angle_bracket_placeholder_is_skipped(self):
        self.assertEqual(ids('api_key = "<your api key here>"'), [])

    def test_the_word_password_alone_is_skipped(self):
        self.assertEqual(ids('password = "password"'), [])

    def test_short_values_are_skipped(self):
        self.assertEqual(ids('password = "abc"'), [])

    def test_a_password_containing_the_word_password_is_still_flagged(self):
        self.assertEqual(ids('password = "mypassword123"'), ["hardcoded-secret"])

    def test_ignore_marker_skips_the_line(self):
        self.assertEqual(ids(f'k = "{AWS_ID}"  # secrets-scanner: ignore'), [])

    def test_empty_text(self):
        self.assertEqual(ids(""), [])


class OutputTests(unittest.TestCase):
    def test_secret_is_masked(self):
        finding = ss.scan_text(f'k = "{AWS_ID}"')[0]
        self.assertEqual(finding.preview, "AKIA****")
        self.assertNotIn(AWS_ID, ss.format_text([finding], 1))

    def test_short_secret_is_fully_masked(self):
        self.assertEqual(ss.mask("abc"), "****")

    def test_line_numbers(self):
        findings = ss.scan_text(f"a = 1\nb = 2\nk = '{AWS_ID}'")
        self.assertEqual(findings[0].line, 3)

    def test_sorted_most_severe_first(self):
        text = f'password = "Winter2026Backup!"\nk = "{PRIVATE_KEY}"'
        ordered = ss.sort_findings(ss.scan_text(text))
        self.assertEqual(ordered[0].severity, "critical")

    def test_summary_line_counts(self):
        findings = ss.scan_text(f'k = "{AWS_ID}"')
        self.assertIn("1 finding(s) (1 high)", ss.format_text(findings, 1))


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_scan_file_finds_secret(self):
        path = self.write("a.py", f'k = "{AWS_ID}"')
        self.assertEqual(len(ss.scan_file(path)), 1)

    def test_binary_file_is_skipped(self):
        path = self.root / "image.bin"
        path.write_bytes(b"\x00\x01\x02" + AWS_ID.encode())
        self.assertEqual(ss.scan_file(path), [])

    def test_git_folder_is_skipped(self):
        self.write(".git/config", f'k = "{AWS_ID}"')
        self.write("ok.txt", "nothing here")
        names = [p.name for p in ss.collect_files([self.root])]
        self.assertEqual(names, ["ok.txt"])

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            list(ss.collect_files([self.root / "nope"]))


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, *args):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ss.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_clean_folder_exits_0(self):
        (self.root / "a.txt").write_text("hello", encoding="utf-8")
        self.assertEqual(self.run_main(self.root)[0], 0)

    def test_high_finding_exits_1(self):
        (self.root / "a.py").write_text(f'k = "{AWS_ID}"', encoding="utf-8")
        self.assertEqual(self.run_main(self.root)[0], 1)

    def test_medium_finding_exits_0_by_default(self):
        (self.root / "a.py").write_text('password = "Winter2026Backup!"', encoding="utf-8")
        self.assertEqual(self.run_main(self.root)[0], 0)

    def test_fail_on_medium_exits_1(self):
        (self.root / "a.py").write_text('password = "Winter2026Backup!"', encoding="utf-8")
        self.assertEqual(self.run_main(self.root, "--fail-on", "medium")[0], 1)

    def test_missing_path_exits_2(self):
        code, _, err = self.run_main(self.root / "nope")
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_json_output_is_valid(self):
        (self.root / "a.py").write_text(f'k = "{AWS_ID}"', encoding="utf-8")
        _, out, _ = self.run_main(self.root, "--format", "json")
        data = json.loads(out)
        self.assertEqual(data[0]["rule_id"], "aws-access-key-id")

    def test_min_severity_hides_lower_findings(self):
        (self.root / "a.py").write_text('password = "Winter2026Backup!"', encoding="utf-8")
        _, out, _ = self.run_main(self.root, "--min-severity", "high", "--format", "json")
        self.assertEqual(json.loads(out), [])


class SampleFileTests(unittest.TestCase):
    def test_sample_files_give_the_expected_findings(self):
        findings = []
        for path in ss.collect_files(["sample_files"]):
            findings.extend(ss.scan_file(path))
        self.assertEqual(
            sorted(f.rule_id for f in findings),
            ["aws-access-key-id", "aws-secret-access-key", "hardcoded-secret", "password-in-url"],
        )

    def test_clean_and_template_samples_have_no_findings(self):
        for name in ("03_clean_code.py", "04_config.example.txt"):
            self.assertEqual(ss.scan_file(Path("sample_files") / name), [], name)

    def test_ignored_line_in_backup_script_is_not_reported(self):
        titles = [f.rule_id for f in ss.scan_file(Path("sample_files/02_backup.sh"))]
        self.assertEqual(titles, ["password-in-url"])


if __name__ == "__main__":
    unittest.main()
