"""Runs owui_hardening_check as a GitHub Actions step (see action.yml): the report
goes to the log, the job summary and a JSON file, findings become annotations,
and the step fails at the chosen severity. Made with AI agents for MV2 of Munim, Inc."""

import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import owui_hardening_check as check  # noqa: E402

REPORT_NAME = "openwebui-hardening-check.json"
ANNOTATION = {"critical": "error", "high": "error", "medium": "warning"}


def expand(text, root=None):
    """(files, missing) for a list of paths and wildcards separated by spaces or new lines."""
    files, missing = [], []
    for pattern in text.split():
        path = os.path.join(root, pattern) if root else pattern
        if any(c in pattern for c in "*?["):
            matches = sorted(p for p in glob.glob(path) if os.path.isfile(p))
        else:
            matches = [path] if os.path.isfile(path) else []
        if not matches:
            missing.append(pattern)
        files += [p for p in matches if p not in files]
    return files, missing


def _escape(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _append(path, text):
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def main(environ=None, out=None):
    environ = os.environ if environ is None else environ
    out = out or sys.stdout
    files, missing = expand(environ.get("CHECK_FILES", ""))
    for pattern in missing:
        print("::warning::%s not found, skipped" % _escape(pattern), file=out)
    url = environ.get("CHECK_URL", "").strip() or None
    fail_on = environ.get("CHECK_FAIL_ON", "").strip().lower() or "high"
    if fail_on not in check.SEVERITIES[:4] + ["never"]:
        print("::error::fail-on must be critical, high, medium, low or never, not %s" % _escape(fail_on), file=out)
        return 2
    if not files and not url:
        print("::error::No files to check. Set the files input to your compose, .env or Kubernetes files, or set url.", file=out)
        return 2
    try:
        findings, sources, label = check.run(files, url)
    except (OSError, ValueError) as e:
        print("::error::%s" % _escape(str(e)), file=out)
        return 2

    print(check.render_text(findings, sources, label), file=out)
    for f in check._sorted(findings):
        if f["severity"] in ANNOTATION:
            print("::%s::%s" % (ANNOTATION[f["severity"]], _escape("%s: %s" % (f["severity"].upper(), f["title"]))), file=out)
    _append(environ.get("GITHUB_STEP_SUMMARY"), check.render_markdown(findings, sources, label))

    report = os.path.join(environ.get("RUNNER_TEMP") or ".", REPORT_NAME)
    with open(report, "w", encoding="utf-8") as f:
        json.dump({"tool": "openwebui-hardening-check", "version": check.__version__, "data_date": check.DATA_DATE,
                   "checked": sources, "openwebui_version": label, "counts": check.counts(findings),
                   "findings": check._sorted(findings)}, f, indent=2)
    c = check.counts(findings)
    _append(environ.get("GITHUB_OUTPUT"), "\n".join(
        ["report=%s" % report] + ["%s=%d" % (s, c[s]) for s in check.SEVERITIES[:4]]))
    if fail_on != "never" and any(check.RANK[f["severity"]] <= check.RANK[fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
