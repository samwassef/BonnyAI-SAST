"""Read public GitHub snapshots without extracting or executing repository files."""

# Imports used by the request models, services, and helpers below.
import http.client
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from app.fetcher import FetchError, PinnedConnection, resolve
from app.review import source_priority, findings_html


# Define the repository URL and optional branch, tag, or commit input.
class RepositoryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=2048)
    ref: str = Field(default="", max_length=200)


# Carry commit identity, source contents, and explicit skipped-file reasons.
@dataclass
class RepositoryEvidence:
    url: str
    commit: str
    files: list[dict]
    skipped: list[dict]


# Accept a GitHub repository root URL and normalize its owner/repository name.
def repository_name(url: str) -> str:
    match = re.fullmatch(r"https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)/?", url)
    if not match or match[2] in (".", ".."):
        raise FetchError("Use a public repository URL: https://github.com/owner/repository. Enter a branch or commit separately.")
    name = match[2].removesuffix(".git")
    if not name or name in (".", ".."):
        raise FetchError("Invalid repository name.")
    return match[1] + "/" + name


# List a fixed commit and download only eligible source files within review limits.
class RepositoryFetcher:
    # Limit listing size and model input independently of the full repository size.
    MAX_TREE = 10_000_000
    MAX_SOURCE = 1_200_000
    MAX_FILES = 400
    # Source-language allowlist; data, documentation, and configuration extensions are omitted.
    EXTENSIONS = set(".py .js .jsx .ts .tsx .mjs .cjs .php .rb .go .rs .java .kt .cs .c .h .cpp .hpp .cc .swift .scala .sh .bash .ps1 .sql .html .htm .vue .svelte .ex .exs .erl .hrl .pl .pm .lua .r .dart .sol".split())
    EXCLUDED = {"node_modules", "vendor", ".git", ".venv", "venv", "dist", "build", "__pycache__"}
    # Recognized CI, container, deployment, and documentation directories are skipped.
    AUTOMATION_DIRS = {
        ".github", ".gitlab", ".circleci", ".buildkite", ".azure-pipelines",
        ".devcontainer", ".devcontainers", "ci", "cd", "cicd", "ci-cd",
        ".ci", "pipeline", "pipelines", "docker", ".docker", "containers",
        "deploy", "deployment", "deployments", "infra", "infrastructure",
        "terraform", "ansible", "helm", "k8s", "kubernetes", "docs", "documentation",
    }
    # Also exclude automation/configuration files that use otherwise allowed source extensions.
    AUTOMATION_FILES = (
        "dockerfile", "dockerfile.*", "*.dockerfile", "containerfile", "containerfile.*",
        "*.containerfile", "docker-compose*", "compose.*", "jenkinsfile*",
        "azure-pipelines*", "bitbucket-pipelines*", "*.config.*", "*.conf.*",
        ".*rc.js", ".*rc.cjs", ".*rc.mjs", "makefile", "gnumakefile", "cmakelists.txt",
        "gemfile", "rakefile", "gulpfile.*", "gruntfile.*", "webpack.*", "rollup.*",
        "vite.config.*", "setup.py", "conanfile.py", "noxfile.py", "fabfile.py",
        "build.py", "build.rs", "build.sh", "build.ps1", "deploy.sh", "deploy.ps1",
    )

    # Filter files by directory, filename, and extension before any content download.
    @classmethod
    def source_exclusion(cls, file: PurePosixPath) -> str | None:
        """Classify using paths before downloading any file contents."""
        name = file.name.lower()
        directories = {part.lower() for part in file.parts[:-1]}
        if cls.EXCLUDED.intersection(directories) or name.endswith((".min.js", ".min.css", ".lock")):
            return "dependency, generated, or lock file"
        if (cls.AUTOMATION_DIRS.intersection(directories)
                or any(fnmatchcase(name, pattern) for pattern in cls.AUTOMATION_FILES)):
            return "pipeline, Docker, build, deployment, configuration, or documentation file"
        if file.suffix.lower() not in cls.EXTENSIONS:
            return "not a supported source-code file"
        return None

    # Perform a bounded HTTPS download using approved GitHub hosts and validated public IPs.
    def _get(self, url: str, limit: int, deadline: float, accept: str = "application/vnd.github+json") -> bytes:
        # Redirects may only reach GitHub's raw file service, never arbitrary hosts.
        for _ in range(4):
            parts = urlsplit(url)
            if (parts.scheme != "https" or parts.netloc not in {"api.github.com", "raw.githubusercontent.com"}
                    or any(ord(c) <= 32 for c in url) or "\\" in url):
                raise FetchError("GitHub returned an unsupported download destination.")
            if time.monotonic() > deadline:
                raise FetchError("Repository collection timed out.")
            connection = PinnedConnection(parts.hostname, 443, resolve(parts.hostname)[0], True)
            try:
                connection.request("GET", parts.path + ("?" + parts.query if parts.query else ""),
                                   headers={"User-Agent": "GLM-Repository-Review/1.0", "Accept-Encoding": "identity", "Accept": accept})
                response = connection.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    url = response.getheader("Location", "")
                    continue
                if response.status != 200:
                    raise FetchError("GitHub could not return this public repository/ref (it may be missing, private, or rate limited).")
                if response.getheader("Content-Encoding", "identity").lower() != "identity":
                    raise FetchError("Unexpected GitHub response encoding.")
                # Stream the response and stop once its specific byte budget is exceeded.
                body = bytearray()
                while True:
                    if time.monotonic() > deadline:
                        raise FetchError("Repository collection timed out.")
                    chunk = response.read1(min(65536, limit - len(body) + 1))
                    if not chunk:
                        if response.length is not None and response.length > 0:
                            raise FetchError("Incomplete GitHub download.")
                        return bytes(body)
                    body.extend(chunk)
                    if len(body) > limit:
                        raise FetchError(f"GitHub {'source file' if parts.hostname == 'raw.githubusercontent.com' else 'metadata'} response exceeds its {limit}-byte limit; nothing sent to GLM.")
            finally:
                connection.close()
        raise FetchError("GitHub redirect limit exceeded.")

    # Resolve a ref to a commit and tree before collecting source from that fixed snapshot.
    def fetch(self, url: str, ref: str = "", progress=None) -> RepositoryEvidence:
        name = repository_name(url)
        deadline = time.monotonic() + 300
        try:
            # Request only the SHA, avoiding the potentially huge commit diff response.
            commit = self._get(
                f"https://api.github.com/repos/{name}/commits/{quote(ref.strip() or 'HEAD', safe='')}",
                200, deadline, accept="application/vnd.github.sha").decode("ascii").strip()
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise FetchError("GitHub did not return a valid commit.")
            # Resolve the commit to its tree without requesting changed-file diffs.
            metadata = json.loads(self._get(
                f"https://api.github.com/repos/{name}/git/commits/{commit}", 2_000_000, deadline))
            tree_sha = metadata["tree"]["sha"]
            if not isinstance(tree_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
                raise FetchError("GitHub did not return a valid source tree.")
            # Request paths and sizes so ineligible files can be skipped before download.
            tree = json.loads(self._get(
                f"https://api.github.com/repos/{name}/git/trees/{tree_sha}?recursive=1",
                self.MAX_TREE, deadline))
            return self.read_tree(tree, name, commit, deadline, progress)
        except FetchError:
            raise
        except (OSError, http.client.HTTPException, ValueError, AttributeError, KeyError, TypeError):
            raise FetchError("Repository collection failed: check connectivity, repository/ref, or GitHub response format.") from None

    # Validate the file listing, choose source files, and record coverage and exclusions.
    def read_tree(self, tree: dict, name: str, commit: str, deadline: float, progress=None) -> RepositoryEvidence:
        # Require a complete listing so the report never implies unknown files were reviewed.
        if tree.get("truncated") is not False:
            raise FetchError("GitHub returned an incomplete file list; this repository is too large for the current review. Nothing sent to GLM.")
        entries = tree.get("tree")
        if not isinstance(entries, list) or len(entries) > 100000:
            raise FetchError("GitHub file list exceeds the 100000-entry limit or is invalid; nothing sent to GLM.")
        # Reject ambiguous paths and duplicates before constructing raw-content URLs.
        seen = set()
        for item in entries:
            path = item["path"]
            if (not isinstance(path, str) or "\\" in path or any(ord(c) < 32 for c in path)
                    or any(p in ("", ".", "..") for p in path.split("/")) or path in seen):
                raise FetchError("Unsafe or duplicate repository path; nothing sent to GLM.")
            seen.add(path)
        files, skipped = [], []
        discovered = sum(item['type'] != 'tree' for item in entries)
        def report_collection():
            if progress:
                progress({'phase': 'collecting', 'message': 'Collecting application source...',
                          'discovered_files': discovered, 'collected_files': len(files),
                          'reviewed_files': 0, 'skipped_files': len(skipped)})

        report_collection()
        total = 0
        attempts = 0
        # Application code precedes tests/tooling; adjacent packages stay together.
        for item in sorted(entries, key=lambda i: source_priority(i["path"])):
            if item["type"] == "tree":
                continue
            path = item["path"]
            file = PurePosixPath(path)
            size = item.get("size", 0)
            if not isinstance(size, int) or size < 0:
                raise FetchError("Invalid source file size; nothing sent to GLM.")
            reason = None
            if item.get("mode") == "120000":
                reason = "symbolic link"
            elif item["type"] != "blob" or item.get("mode") not in {"100644", "100755"}:
                reason = "submodule or unsupported entry"
            elif (exclusion := self.source_exclusion(file)) is not None:
                reason = exclusion
            elif size > 30000:
                reason = "file exceeds 30000 bytes"
            elif time.monotonic() > deadline:
                reason = "collection time limit"
            elif attempts >= self.MAX_FILES or total + size > self.MAX_SOURCE:
                reason = "review input limit"
            # Download eligible files from the pinned commit and verify their listed size.
            if reason is None:
                attempts += 1
                raw = self._get(f"https://raw.githubusercontent.com/{name}/{commit}/{quote(path, safe='/')}",
                                30000, deadline, accept="text/plain")
                if len(raw) != size:
                    raise FetchError("Downloaded source size differs from the commit file list; nothing sent to GLM.")
                # Treat source as UTF-8 text and exclude binary data and Git LFS pointers.
                try:
                    content = raw.decode("utf-8")
                    if "\x00" in content:
                        raise UnicodeError()
                except UnicodeError:
                    reason = "binary or non-UTF-8 file"
                else:
                    if content.startswith("version https://git-lfs.github.com/spec/v1"):
                        reason = "Git LFS pointer (content not fetched)"
                    else:
                        total += len(raw)
                        files.append({"path": path, "content": content})
            # Retain an explicit reason for every file omitted from the review.
            if reason:
                skipped.append({"path": path, "reason": reason})
            if (len(files) + len(skipped)) % 10 == 0:
                report_collection()
        report_collection()
        if not files:
            raise FetchError("No supported source files fit the review limits; nothing sent to GLM.")
        return RepositoryEvidence(f"https://github.com/{name}", commit, files, skipped)


def _render_findings(answer: str) -> str:
    """Render a small Markdown subset without allowing model-supplied HTML."""
    parts = []
    code = None
    fence = None
    paragraph = []

    def flush_paragraph():
        if paragraph:
            parts.append('<p>' + '<br>'.join(escape(line) for line in paragraph) + '</p>')
            paragraph.clear()

    for line in answer.splitlines():
        stripped = line.strip()
        if code is not None:
            if re.fullmatch(re.escape(fence[0]) + '{' + str(len(fence)) + ',}', stripped):
                parts.append('<pre><code>' + escape('\n'.join(code)) + '</code></pre>')
                code = None
            else:
                code.append(line)
            continue
        opening = re.match(r'^(`{3,}|~{3,})[^`~]*$', stripped)
        if opening:
            flush_paragraph()
            fence = opening.group(1)
            code = []
            continue
        heading = re.match(r'^(#{1,4})\s+(.+)$', stripped)
        severity = re.fullmatch(
            r'Severity:\s*(Critical|High|Medium|Low|Informational)', stripped, re.IGNORECASE)
        if heading:
            flush_paragraph()
            level = max(2, len(heading.group(1)))
            parts.append(f'<h{level}>' + escape(heading.group(2)) + f'</h{level}>')
        elif severity:
            flush_paragraph()
            value = severity.group(1).lower()
            parts.append(f'<p><span class="severity {value}">Severity: {value.title()}</span></p>')
        elif not stripped:
            flush_paragraph()
        else:
            paragraph.append(line)
    flush_paragraph()
    if code is not None:
        parts.append('<pre><code>' + escape('\n'.join(code)) + '</code></pre>')
    return '\n'.join(parts)


# Build a standalone HTML report with escaped findings and a coverage inventory.
def render_report(evidence: RepositoryEvidence, answer: str, finish_reason: str, model: str,
                  review: dict | None = None) -> str:
    # Escape file paths and skip reasons before placing them in HTML list items.
    def rows(items):
        return "".join("<li>" + escape(item["path"]) +
                       (" — " + escape(item["reason"]) if "reason" in item else "") + "</li>" for item in items)
    # Include model completion status separately from the review findings.
    status = "Complete model response" if finish_reason == "stop" else "Incomplete or interrupted model response: " + finish_reason
    reviewed = evidence.files
    skipped = evidence.skipped
    details = ''
    rendered = _render_findings(answer)
    if review is not None:
        reviewed = [{'path': path} for path in review['reviewed_paths']]
        skipped = review['skipped']
        status = 'Partial coverage / insufficient coverage for a repository-wide conclusion' if review['partial'] else 'Selected source review complete'
        details = (f"<p>Collected {len(evidence.files)} files; sent {len(review['sent_paths'])} unique files including context; "
                   f"completed {review['completed_batches']} of {review['planned_batches']} batches. "
                   "A reviewed file belongs to a batch with a complete, validated response; this does not prove exhaustive analysis.</p>")
        if review['failed_batches']:
            details += '<ul>' + ''.join(f"<li>Batch {f['batch']}: {escape(f['reason'])}</li>" for f in review['failed_batches']) + '</ul>'
        rendered = findings_html(review)
    # Escape all dynamic text; the report displays code rather than executing it.
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>GitHub source security review</title><style>
body{{font:16px/1.65 system-ui;max-width:1000px;margin:40px auto;padding:0 24px;color:#17212b;background:#fff}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:20px;border:1px solid #dce5e7;border-radius:8px;line-height:1.6}}
code{{font:14px/1.6 ui-monospace,Consolas,monospace}}li,p,h2,h3,h4{{overflow-wrap:anywhere}}
h1,h2{{color:#174b51}}h2{{margin-top:36px}}h3{{font-size:1.4rem;font-weight:800;border-top:2px solid #dce5e7;padding-top:24px;margin-top:36px}}
h4{{font-size:1rem;margin:24px 0 8px;color:#334155}}.severity{{display:inline-block;border:1px solid;border-radius:6px;padding:4px 12px;font-weight:750}}
.critical{{color:#991b1b;background:#fee2e2;border-color:#dc2626}}.high{{color:#9a3412;background:#ffedd5;border-color:#ea580c}}
.medium{{color:#713f12;background:#fef9c3;border-color:#ca8a04}}.low,.informational{{color:#166534;background:#dcfce7;border-color:#16a34a}}
.legend{{font-size:14px;color:#475569}}@media print{{body{{margin:0;max-width:none}}h3,h4{{break-after:avoid}}pre{{white-space:pre-wrap}}}}
</style></head>
<body><h1>GitHub source security review</h1><p>Repository: {escape(evidence.url)}</p>
<p>Commit: {escape(evidence.commit)}</p><p>Generated: {datetime.now(timezone.utc).isoformat()} · Model: {escape(model)}</p>
<p><strong>{escape(status)}</strong>. Reviewed {len(reviewed)} files; skipped {len(skipped)} files.</p>{details}
<p>Automated static review of the listed files only. Findings and proposed fixes need human validation; no code or tests were executed and no fixes were applied. No findings does not establish that the repository is secure. Submodules and Git LFS contents are not fetched.</p>
<h2>Findings and proposed fixes</h2>
<p class="legend">Severity colors: red = Critical; orange = High; yellow = Medium; green = Low / Informational. Green does not mean the code is secure.</p>
<section aria-label="Security review findings">{rendered}</section>
<details><summary>Files successfully reviewed ({len(reviewed)})</summary><ul>{rows(reviewed)}</ul></details>
<details><summary>Files not reviewed ({len(skipped)})</summary><ul>{rows(skipped)}</ul></details></body></html>"""
