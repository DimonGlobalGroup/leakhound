# LeakHound

Find leaked secrets in a file tree — without ever printing them. One Python file, no dependencies.

## Why it's different

Most secret scanners print the match, or enough context around it, that the
secret lands in your CI log, your ticket, and your chat history — a second
leak caused by the tool that was supposed to prevent the first one.

LeakHound cannot do that. It never holds a report format that contains a
secret value. Every finding is exactly four things:

```
src/config.py:14: aws-access-key [fp:9f2c41ab07e3]
```

- the **file** and **line**,
- the **rule** that matched,
- a **fingerprint**: the first 12 hex characters of the SHA-256 of the
  matched value.

The fingerprint is enough to answer "is this the same secret I already
rotated?" and to allowlist a false positive — without the secret ever
appearing in the report, or in the allowlist file.

## Install

Download one file: `leakhound.py`. It needs Python 3.10 or newer and nothing else.

## Quick start

```sh
python3 leakhound.py .                      # scan the current tree (text report)
python3 leakhound.py . --format json        # machine-readable report
python3 leakhound.py . --allow allow.txt    # suppress known fingerprints
```

Exit codes: `0` = clean, `1` = findings, `2` = usage error. Drop it in a
pre-push hook or a CI step and a non-zero exit stops the leak.

## Allowlist

`--allow FILE` reads one entry per line (`#` comments allowed):

- a 12-character fingerprint, e.g. `9f2c41ab07e3` — suppresses that exact value anywhere;
- a `path:rule` pair, e.g. `tests/fixtures.py:aws-access-key` — suppresses a rule in one file.

You never paste a secret into the allowlist. Run the scan, copy the
fingerprint from the report, done.

## What it detects

| Rule | Detects |
| --- | --- |
| `aws-access-key` | `AKIA` / `ASIA` access key IDs |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_` tokens |
| `slack-token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` tokens |
| `private-key` | `-----BEGIN ... PRIVATE KEY-----` headers |
| `jwt` | Three-part JSON Web Tokens starting with `eyJ` |
| `generic-assignment` | `api_key`, `secret`, `token`, `password`, `passwd` or `auth` assigned a value of 12+ characters with high character diversity |

Binary files, files over 1 MB (configurable with `--max-file-bytes`),
symlinks, and `.git` / vendor / cache directories are skipped; JSON reports
list skipped files with the reason.

## Limitations

- **Pattern matching is a safety net, not a proof.** Secrets in shapes the
  rules don't recognize will be missed. Review what you share.
- **The fingerprint is a correlation aid, not encryption.** 48 bits of a
  hash cannot reconstruct a high-entropy secret, but don't use LeakHound
  fingerprints as passwords, obviously.
- **Line-based scanning.** A secret split across lines is not detected.
- **The generic rule errs toward silence on low-diversity values** — a real
  password like `passwordpassword1` may pass. The specific-format rules
  have no such gate.

## License

MIT License.

A Dimon Global Group release.
