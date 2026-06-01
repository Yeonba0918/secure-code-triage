# secure-code-triage

`secure-code-triage` is a dependency-free Python CLI for fast, defensive security review of local code repositories.

It scans source files for common risky programming patterns, hardcoded secret indicators, committed environment files, and missing security disclosure guidance. The output is designed for maintainers who need a quick first-pass report before deeper review.

This is not a replacement for full SAST, dependency auditing, or manual security review. It is a small triage tool that is easy to run in local development and CI.

## Install

From the repository root:

```bash
python3 -m pip install .
```

For one-off local use without installation:

```bash
PYTHONPATH=src python3 -m secure_code_triage --help
```

## Usage

Scan a local checkout:

```bash
secure-code-triage /path/to/repo
```

Write JSON:

```bash
secure-code-triage /path/to/repo --format json
```

Use it in CI and fail on high severity findings:

```bash
secure-code-triage . --fail-on high
```

Include hidden files and directories beyond `.github` and `.env` files:

```bash
secure-code-triage . --include-hidden
```

Ignore a deliberate test fixture on one source line:

```python
payload = "eval(user_input)"  # secure-code-triage: ignore
```

## What It Checks

Secret indicators:

- private key blocks
- AWS access keys
- GitHub tokens
- Slack tokens
- generic `password`, `token`, `secret`, and `api_key` assignments
- committed `.env` files

Risky programming patterns:

- Python `eval`, `exec`, unsafe `pickle`, `subprocess(..., shell=True)`, and `yaml.load`
- JavaScript `eval`, `child_process.exec`, and direct `innerHTML` assignment
- C/C++ `gets`, `strcpy`, `strcat`, and `sprintf`
- simple SQL execution with Python f-strings
- weak hash use through `md5` or `sha1`

Repository hygiene:

- missing `SECURITY.md`
- missing `.gitignore`

## Example Output

```text
# Secure code triage report

Target: /home/example/project

## Snapshot

- Files scanned: 42
- Files skipped: 3
- High: 1
- Medium: 2
- Low: 1

## Findings

- High secret-generic at app/settings.py:12
  Hardcoded secret-like assignment
  Evidence: [redacted]
  Fix: Move secrets to a managed secret store or runtime environment variable.
```

## Development

Run tests:

```bash
python3 -m unittest discover -s tests
```

Run the CLI from source:

```bash
PYTHONPATH=src python3 -m secure_code_triage .
```

## License

MIT
