# Whole-package scanning

Shield can inspect a ZIP containing a skill and all its supporting files without
committing the package to a repository. The operator CLI produces a JSON report
and a standalone HTML report with findings, available file/line locations, reasons,
and suggested review actions. It uses the same verified Cisco and NVIDIA engines
and completeness rules as the repository Action.

This is the scanning foundation for upload submission. **The public Pages website
does not yet accept ZIP uploads.** Public submission still needs a separately
hosted authenticated service with private storage, a job queue, isolated workers,
per-user access control, quotas and expiration. No public endpoint is provided by
this change. Repository Actions continue to evaluate committed packages only.

## Run on a disposable Linux worker

Use Ubuntu x86_64, Python 3.13 and uv. Check out a reviewed Shield commit. Choose
private state, report and temporary directories outside the checkout. Run with a
non-privileged account in a resource-limited disposable environment without
credentials, host mounts or a Docker socket. Parsing an untrusted package still
exposes the scanner itself to untrusted data; a temporary folder is not a sandbox.

```sh
python entrypoint.py resolve --state /private/shield-state
python entrypoint.py install --state /private/shield-state
python -m skill_security.submission /private/input/my-skill.zip \
  --state /private/shield-state --output /private/results/scan-1
```

Resolution installs current compatible stable releases through immutable,
verified artifacts. The report retains the exact pins. The operator owns the
trusted state directory; never let an uploader supply or modify it. Scanner
subprocesses receive a restricted environment without the operator's credentials.
NVIDIA dependency checks may contact OSV.

Open `report.html` in the new output directory or consume `report.json`. The CLI
exits 0 for `pass`, 1 for `review-required` or `incomplete`, and 2 if input/setup or
report delivery failed. Exit 2 is never evidence of safety. Existing output
directories are rejected so historical results cannot be silently overwritten.

## ZIP boundary

- Include the whole package: Markdown, scripts, references, evaluation files and
  other supporting content. Submitted scripts and installers are never executed.
- A complete `SKILL.md` is not required. When absent, Shield records a temporary
  compatibility wrapper while retaining the original draft bytes.
- A single enclosing directory containing `SKILL.md` is recognized automatically.
  Otherwise the archive root is used. `--package-root my-skill` explicitly selects
  an enclosing directory; content outside it is rejected, not silently omitted.
- Portable stored/deflated ZIP files are accepted. Unsafe paths, duplicate or
  colliding names, links, encryption, unsupported compression, corrupt data and
  resource-limit violations are rejected before analysis. See
  [archive.py](../skill_security/archive.py) for exact limits.
- Nested archives remain original package files; the ZIP stager does not expand
  them recursively. Vendor coverage and any inability to inspect them remain
  visible in the result.

The report records the archive hash, original package content hash, byte/file
counts and whether metadata was generated. Temporary extraction, raw scanner
output and logs are removed when the scan returns. The operator remains
responsible for deleting the original upload and retained reports according to
their retention policy.

## Interpret findings

`pass` means both static analyses completed without high/critical findings.
`review-required` means those findings need review. `incomplete` means missing
analysis prevents a complete verdict, even when findings were already detected.
Lower-severity findings remain available. No status is a safety certificate.

Reasons and suggestions are reviewed mappings to upstream rule definitions, not
arbitrary scanner prose. Unknown rules link to the relevant upstream project and
explicitly require manual interpretation. A missing file/line is shown as
unavailable. Review suggestions in context and rescan the revised whole package;
do not remove a legitimate safeguard simply to silence a detector.

## Public delivery remains an explicit deployment step

Repeated findings are grouped for readable guidance, with occurrence counts and
locations shown once. Presentation is limited to 500 rule/severity groups per
engine and marks truncation explicitly. The JSON engine evidence retains every
normalized finding, including those outside the presentation limit.

GitHub Pages hosts the static UI. GitHub's Actions terms restrict unrelated
hosted-runner workloads and use as a serverless application. A general public
upload scanner therefore needs its own worker service; repository-linked scans
can keep using the existing Action.

Sources: [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages),
[Actions terms](https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features#actions).
The hosting destination and account have not yet been selected. Do not deploy a
shared-token demo or a browser-held administrator credential as a public service.
