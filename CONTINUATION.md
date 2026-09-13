# Continuation handoff

This file is the starting point for Claude Code, Codex, or another coding agent.

## Current state

- Flask application implements bounded demonstrations for OWASP Top 10 (2021).
- `LAB_MODE=true` is mandatory; otherwise requests are rejected.
- IIS deployment uses ARR/URL Rewrite to proxy to Waitress on localhost.
- Application events are JSONL and optionally sent to Splunk HEC.
- IIS and application log inputs plus Splunk saved searches are packaged.
- Standalone unit tests live in `tests/test_app.py` and run in GitHub Actions.

## Verification commands

```bash
python -m unittest discover -s tests -v
python -m py_compile app.py
```

On Windows, run `iis/Install-IIS-LabSite.ps1`, execute every command in
`OWASP_TOP10_TEST_COMMANDS.md`, and confirm the searches in
`splunk/USE_CASES.md`.

## Next safe improvements

1. Add CI jobs for Python tests and PowerShell static analysis.
2. Add a Splunk dashboard XML after validating field names in the target lab.
3. Sign release archives and publish checksums.
4. Keep SSRF bounded to lab hostnames and never add command-execution examples.
