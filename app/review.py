"""Bounded review batches, validated findings, and server-owned coverage."""

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from html import escape
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.operation import checkpoint


Text = Annotated[str, Field(min_length=1, max_length=16000)]


class ReviewModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SourceReference(ReviewModel):
    path: Text
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class Finding(ReviewModel):
    title: Text
    category: Literal["XSS", "SQLi", "Access control", "Credentials", "Other"]
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    confidence: Literal["High", "Medium", "Low"]
    status: Literal["confirmed", "needs_verification"]
    intentional: bool
    description: Text
    root_cause: Text
    evidence: list[SourceReference] = Field(min_length=1, max_length=20)
    source_to_sink: Text
    impact: Text
    prerequisites: Text
    exploitation_steps: list[Text] = Field(min_length=1, max_length=20)
    code_fix: Text
    regression_test: Text
    missing_evidence: str = Field(max_length=16000)


class BatchFindings(ReviewModel):
    findings: list[Finding] = Field(max_length=30)
    limitations: list[Text] = Field(max_length=20)


@dataclass
class ReviewBatch:
    files: list[dict]
    primary_paths: list[str]


def source_priority(path: str) -> tuple:
    """Production source first; tests and tooling cannot exhaust its budget."""
    file = PurePosixPath(path.lower())
    parts = set(file.parts[:-1])
    is_test = bool(parts & {"test", "tests", "it", "__tests__", "fixtures"}) or bool(
        re.search(r'(^test_|test\.|tests\.|\.test\.|\.spec\.)', file.name))
    tooling = bool(parts & {".mvn", "scripts", "config", "tools"})
    security_area = bool(re.search(
        r'(controller|endpoint|route|security|auth|permission|middleware|lesson|template|views)',
        str(file), re.I))
    return (2 if is_test else 1 if tooling else 0, 0 if security_area else 1, str(file.parent), path)


def batch_payload(evidence, batch: ReviewBatch) -> str:
    return json.dumps({"repository": evidence.url, "commit": evidence.commit,
                       "primary_paths": batch.primary_paths,
                       "files": batch.files}, ensure_ascii=False)


def plan_batches(evidence, max_batches=24, max_bytes=32000, max_chars=60000):
    """Keep directories adjacent and add bounded referenced/global security context.

    This is lexical dependency matching, not language-aware call-graph analysis.
    Every primary file gets its own review pass even if it was context elsewhere.
    """
    ordered = sorted(evidence.files, key=lambda f: source_priority(f["path"]))
    symbols = defaultdict(list)
    security = []
    for file in ordered:
        stem = PurePosixPath(file["path"]).stem
        if len(stem) >= 3:
            symbols[stem].append(file)
        if re.search(r'(security|auth|middleware|permission)', file['path'], re.I) and source_priority(file['path'])[0] == 0:
            security.append(file)
    groups, omitted = [], []
    current = []
    for file in ordered:
        candidate = current + [file]
        batch = ReviewBatch(candidate, [f['path'] for f in candidate])
        size = sum(len(f['content'].encode('utf-8')) for f in candidate)
        if current and (size > max_bytes * 0.75 or len(batch_payload(evidence, batch)) > max_chars * 0.75):
            groups.append(current)
            current = []
        current.append(file)
    if current:
        groups.append(current)
    batches = []
    for group in groups:
        batch = ReviewBatch(list(group), [f['path'] for f in group])
        if len(batches) >= max_batches:
            omitted.extend({'path': f['path'], 'reason': 'batch limit'} for f in group)
            continue
        size = sum(len(f['content'].encode('utf-8')) for f in batch.files)
        if size > max_bytes or len(batch_payload(evidence, batch)) > max_chars:
            omitted.extend({'path': f['path'], 'reason': 'serialized batch input limit'} for f in group)
            continue
        candidates = []
        for file in group:
            for symbol in sorted(set(re.findall(r'\b[A-Za-z_]\w*\b', file['content']))):
                candidates.extend(symbols.get(symbol, []))
        candidates.extend(security)
        present = set(batch.primary_paths)
        for file in candidates:
            if file['path'] in present:
                continue
            added = len(file['content'].encode('utf-8'))
            proposed = ReviewBatch(batch.files + [file], batch.primary_paths)
            if size + added <= max_bytes and len(batch_payload(evidence, proposed)) <= max_chars:
                batch.files.append(file)
                present.add(file['path'])
                size += added
        batches.append(batch)
    return batches, omitted


def validate_batch(answer: str, batch: ReviewBatch) -> BatchFindings:
    # Accept a single JSON fence, but never silently extract JSON from prose.
    value = answer.strip()
    if value.startswith('```json\n') and value.endswith('```'):
        value = value[8:-3].strip()
    result = BatchFindings.model_validate_json(value)
    sources = {f['path']: f['content'].splitlines() for f in batch.files}
    for finding in result.findings:
        if not any(ref.path in batch.primary_paths for ref in finding.evidence):
            raise ValueError('Finding does not cite primary source')
        if finding.status == 'needs_verification' and not finding.missing_evidence.strip():
            raise ValueError('Unconfirmed finding requires missing evidence')
        for ref in finding.evidence:
            if ref.path not in sources or not (ref.start_line <= ref.end_line <= len(sources[ref.path])):
                raise ValueError('Invalid source reference')
    return result


def run_review(evidence, request_batch, progress=None):
    batches, omitted = plan_batches(evidence)
    findings, completed, sent, failures, limitations = [], set(), set(), [], []
    successful = 0
    def snapshot(pending=False):
        unique = {}
        for finding in findings:
            # Only collapse identical root causes at identical source locations.
            key = (finding.category, finding.root_cause.strip().casefold(),
                   tuple(sorted((r.path, r.start_line, r.end_line) for r in finding.evidence)))
            if key not in unique or (unique[key].status != 'confirmed' and finding.status == 'confirmed'):
                unique[key] = finding
        severity = {name: i for i, name in enumerate(['Critical', 'High', 'Medium', 'Low', 'Informational'])}
        results = sorted(unique.values(), key=lambda f: (f.status != 'confirmed', severity[f.severity], f.title))
        skipped = evidence.skipped + omitted
        if pending:
            known = completed | {item['path'] for item in skipped}
            skipped += [{'path': f['path'], 'reason': 'not yet reviewed'}
                        for f in evidence.files if f['path'] not in known]
        return {'findings': [f.model_dump() for f in results], 'limitations': list(dict.fromkeys(limitations)),
                'reviewed_paths': sorted(completed), 'sent_paths': sorted(sent),
                'skipped': skipped, 'planned_batches': len(batches), 'completed_batches': successful,
                'failed_batches': failures, 'partial': bool(skipped or failures)}

    def report_progress(index, publish=False):
        checkpoint()
        if progress:
            progress({'phase': 'reviewing',
                      'message': f'Reviewing batch {index} of {len(batches)}.',
                      'collected_files': len(evidence.files), 'reviewed_files': len(completed),
                      'skipped_files': len(evidence.skipped) + len(omitted),
                      'current_batch': index, 'total_batches': len(batches),
                      'completed_batches': successful, 'failed_batches': len(failures),
                      **({'review': snapshot(pending=True)} if publish else {})})

    for index, batch in enumerate(batches, 1):
        report_progress(index)
        sent.update(f['path'] for f in batch.files)
        try:
            response = request_batch(batch)
            if response.finish_reason != 'stop':
                raise ValueError('Model response incomplete')
            result = validate_batch(response.answer, batch)
        except (ValueError, RuntimeError) as exc:
            # Never expose raw model output or validation errors containing source/secrets.
            safe_reasons = {
                'timeout': 'provider request timed out',
                'rate_limit': 'provider rate limit (HTTP 429)',
                'connection': 'provider connection failed',
                'server_error': 'provider server error (HTTP 5xx)',
                'authentication': 'provider authentication failed (HTTP 401)',
                'billing': 'provider billing or credits required (HTTP 402)',
                'permission': 'provider access denied (HTTP 403)',
            }
            reason = ('incomplete or invalid structured response' if isinstance(exc, ValueError)
                      else safe_reasons.get(str(exc), 'provider request failed'))
            failures.append({'batch': index, 'reason': reason})
            omitted.extend({'path': p, 'reason': reason} for p in batch.primary_paths)
            if isinstance(exc, RuntimeError):
                for remaining in batches[index:]:
                    omitted.extend({'path': p, 'reason': 'not attempted after provider failure'} for p in remaining.primary_paths)
                report_progress(index, publish=True)
                break
            report_progress(index, publish=True)
            continue
        successful += 1
        completed.update(batch.primary_paths)
        findings.extend(result.findings)
        limitations.extend(result.limitations)
        report_progress(index, publish=True)
    return snapshot()


def review_text(review: dict) -> str:
    lines = [f"{'Partial coverage' if review['partial'] else 'Selected source review complete'}: "
             f"{len(review['reviewed_paths'])} files reviewed; {len(review['skipped'])} skipped; "
             f"{review['completed_batches']}/{review['planned_batches']} batches completed."]
    if not review['findings']:
        lines.append('No findings established in the successfully reviewed source. '
                     'Insufficient coverage to conclude the repository is secure.')
    for finding in review['findings']:
        lines.extend(['', finding['title'], f"Severity: {finding['severity']} | {finding['status']}",
                      finding['description'], 'Root cause: ' + finding['root_cause'],
                      'Evidence: ' + ', '.join(f"{r['path']}:{r['start_line']}-{r['end_line']}" for r in finding['evidence']),
                      'Exploitation steps (proposed):', *finding['exploitation_steps'],
                      'Code fix:', finding['code_fix']])
    return '\n'.join(lines)


def findings_html(review: dict) -> str:
    parts = []
    if not review['findings']:
        parts.append('<p>No findings established in the successfully reviewed source. '
                     'This does not establish that the repository is secure.</p>')
    for finding in review['findings']:
        severity = finding['severity'].lower()
        # All text is escaped, and CSS class values come from the validated enum.
        parts.append('<article><h3>' + escape(finding['title']) + '</h3>'
                     f'<p><span class="severity {severity}">Severity: {escape(finding["severity"])}</span></p>'
                     '<p>Status: ' + escape(finding['status'].replace('_', ' ')) +
                     ' | Confidence: ' + escape(finding['confidence']) + '</p>')
        if finding['intentional']:
            parts.append('<p><strong>Intentional educational vulnerability</strong></p>')
        for field, title in [('description', 'Description'), ('root_cause', 'Root cause'),
                             ('source_to_sink', 'Source-to-sink trace'), ('impact', 'Impact'),
                             ('prerequisites', 'Prerequisites')]:
            parts.append('<h4>' + title + '</h4><p>' + escape(finding[field]).replace('\n', '<br>') + '</p>')
        parts.append('<h4>Evidence</h4><ul>' + ''.join(
            '<li>' + escape(r['path']) + f":{r['start_line']}-{r['end_line']}</li>" for r in finding['evidence']) + '</ul>')
        parts.append('<h4>Exploitation steps (proposed, not executed)</h4><ol>' + ''.join(
            '<li>' + escape(step) + '</li>' for step in finding['exploitation_steps']) + '</ol>')
        parts.append('<h4>Code fix</h4><pre><code>' + escape(finding['code_fix']) + '</code></pre>')
        parts.append('<h4>Regression test</h4><p>' + escape(finding['regression_test']) + '</p>')
        if finding['missing_evidence']:
            parts.append('<h4>Needs verification</h4><p>' + escape(finding['missing_evidence']) + '</p>')
        parts.append('</article>')
    if review['limitations']:
        parts.append('<h2>Model-noted limitations</h2><ul>' + ''.join(
            '<li>' + escape(value) + '</li>' for value in review['limitations']) + '</ul>')
    return '\n'.join(parts)
