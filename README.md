# Secrets scanner

![tests](https://github.com/twistedsol/secrets-scanner/actions/workflows/tests.yml/badge.svg)

A small Python tool that looks through files for secrets that should never be committed: cloud keys, private keys, tokens, and passwords written straight into code. It uses the standard library only, so there is nothing to install, and nothing is sent anywhere.

The full secret is never printed. The report shows only the first 4 characters, so the report is not a leak itself.

## Run it

```bash
python3 secrets_scanner.py sample_files/
```

On Windows, use `py -3.13 secrets_scanner.py sample_files`.

Example output:

```
[CRITICAL] AWS secret access key (aws-secret-access-key)
  sample_files/01_app_settings.py:5   found: wJal****
  fix: Treat the key as stolen: deactivate it now and create a new one.

[HIGH] AWS access key ID (aws-access-key-id)
  sample_files/01_app_settings.py:4   found: AKIA****
  fix: Deactivate the key in IAM, create a new one, and keep it out of code.

[HIGH] Password inside a web address (password-in-url)
  sample_files/02_backup.sh:4   found: Hunt****
  fix: Move the password to an environment variable or a secrets manager.

[MEDIUM] Password or key written into the file (hardcoded-secret)
  sample_files/01_app_settings.py:8   found: Wint****
  fix: Read it from an environment variable or a secrets manager instead.

Scanned 4 file(s): 4 finding(s) (1 critical, 2 high, 1 medium)
```

All the values in `sample_files/` are made up, or are the public examples from AWS's documentation. None of them work.

## What it looks for

| Rule | Severity | What it catches |
| --- | --- | --- |
| aws-secret-access-key | critical | An AWS secret access key assigned to a variable |
| private-key | critical | The start of a private key (RSA, EC, DSA, OpenSSH, PGP) |
| aws-access-key-id | high | An AWS access key ID (starts with AKIA or ASIA) |
| github-token | high | A GitHub token (ghp_, gho_, ghu_, ghs_, ghr_) |
| slack-token | high | A Slack token (xoxb-, xoxp- and similar) |
| password-in-url | high | A password inside a web address, like `https://user:password@host` |
| json-web-token | medium | A JSON Web Token |
| hardcoded-secret | medium | A password, secret, key or token written in quotes in the file |

It skips obvious placeholders (like `changeme`, `<your key>` or `${TOKEN}`) and values read from the environment. To mark a known safe line, add `secrets-scanner: ignore` as a comment on that line.

## Options

```bash
python3 secrets_scanner.py my_project/ --format json          # machine-readable output
python3 secrets_scanner.py my_project/ --min-severity high    # hide lower findings
python3 secrets_scanner.py my_project/ --fail-on medium       # fail on medium and above
```

Exit codes: `0` nothing at or above the fail level, `1` something found, `2` a file could not be read. This makes it usable as a check in an automated pipeline.

## Test it

```bash
python3 -m unittest -v
```

43 tests cover each rule, the placeholder and ignore cases, the masking of secrets, skipped folders and binary files, the command-line options and the sample files. The fake secrets in the tests are built from pieces at run time, so the test file itself does not look like a leak.

## If it finds a real secret

1. Treat the secret as stolen. Deactivate or rotate it first, before cleaning up the file.
2. Remove it from the code and read it from an environment variable or a secrets manager.
3. Deleting it from the latest version does not remove it from Git history. Anyone who copied the repository still has it, which is why step 1 comes first.

## How I built it

This is part of a 30-day challenge to learn cloud security by building in public. It follows the [log detector](https://github.com/twistedsol/log-detector), the [misconfiguration scan](https://github.com/twistedsol/misconfig-scan) and the [IAM policy checker](https://github.com/twistedsol/iam-policy-checker). I wrote the code together with Claude. No cloud account is needed, so everything here runs on my own computer.

## What I learned

- **A secrets scanner must not leak the secrets it finds.** Mine shows only the first 4 characters of each finding, so the report is safe to share.
- **Fewer false alarms matter as much as finding things.** Placeholders like `changeme` and values read from the environment are skipped. A scanner that cries wolf gets ignored.
- **Where a file lives matters.** My tests failed on GitHub because three sample files ended up in the wrong folders. The error message named the missing file, and fixing the paths turned the run green.
-
- ## Limits

- It finds secrets by their shape (regular expressions). It cannot tell whether a key is still active.
- It reads the files as they are now. It does not search Git history, where an old secret may still be.
- A random-looking secret with no clear name or shape can be missed, and a harmless value that looks like a secret can be flagged.
- The rule list is short and covers the common cases. It is not a complete list.

## Next ideas

- Search Git history for old secrets
- Add a check for strings that look random (high entropy)
- Output a markdown report
