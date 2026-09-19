"use strict";

// Model and repository text only enter the DOM through textContent.
window.RepositoryReviewUI = (() => {
  const severities = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }
  function section(card, title, value, code = false) {
    card.append(element('h4', title));
    if (code) {
      const pre = element('pre');
      pre.append(element('code', value));
      card.append(pre);
    } else {
      card.append(element('p', value));
    }
  }
  function inventory(parent, title, values, format) {
    const details = element('details');
    details.append(element('summary', `${title} (${values.length})`));
    const list = element('ul');
    for (const value of values) list.append(element('li', format(value)));
    details.append(list);
    parent.append(details);
  }
  function render(container, data) {
    container.replaceChildren();
    const review = data.review;
    if (!review) {
      container.append(element('p', data.answer));
      return;
    }
    const summary = element('div', undefined, 'review-summary');
    summary.append(element('h3', review.partial ? 'Review finished with partial coverage' : 'Selected source review complete'));
    summary.append(element('p', `${data.repository}\nCommit: ${data.commit}`));
    const counts = element('dl', undefined, 'review-counts');
    for (const [name, value] of [
      ['Files reviewed', review.reviewed_paths.length], ['Files skipped', review.skipped.length],
      ['Batches completed', `${review.completed_batches} / ${review.planned_batches}`],
      ['Findings', review.findings.length]
    ]) {
      const group = element('div');
      group.append(element('dt', name), element('dd', String(value)));
      counts.append(group);
    }
    summary.append(counts);
    summary.append(element('p', review.partial
      ? 'Coverage is incomplete. Review the skipped files and batch failures below; no findings does not mean the repository is secure.'
      : 'This is a static review of selected source. Findings and proposed fixes need human validation.', 'review-notice'));
    container.append(summary);
    if (review.failed_batches.length) {
      const notice = element('div', undefined, 'review-warning');
      notice.append(element('h3', 'Some batches could not be reviewed'));
      notice.append(element('p', 'Findings from successful batches are preserved. Failed batches are not counted as reviewed.'));
      const list = element('ul');
      for (const failure of review.failed_batches) list.append(element('li', `Batch ${failure.batch}: ${failure.reason}`));
      notice.append(list);
      container.append(notice);
    }
    if (!review.findings.length) {
      container.append(element('p', 'No findings established in the successfully reviewed source.', 'review-empty'));
    }
    for (const status of ['confirmed', 'needs_verification']) {
      const findings = review.findings.filter(finding => finding.status === status);
      if (!findings.length) continue;
      container.append(element('h3', status === 'confirmed' ? 'Confirmed findings' : 'Needs verification', 'review-group-title'));
      for (const finding of findings) {
        const card = element('article', undefined, 'review-finding');
        card.append(element('h3', finding.title));
        const severity = severities.includes(finding.severity) ? finding.severity : 'Unknown';
        card.append(element('span', `Severity: ${severity}`, `severity severity-${severity.toLowerCase()}`));
        card.append(element('p', `Confidence: ${finding.confidence} · ${status === 'confirmed' ? 'Confirmed' : 'Unconfirmed — needs verification'}`, 'review-meta'));
        if (finding.intentional) card.append(element('p', 'Intentional educational vulnerability', 'review-context'));
        section(card, 'Description', finding.description);
        section(card, 'Root cause', finding.root_cause);
        section(card, 'Source-to-sink trace', finding.source_to_sink);
        section(card, 'Impact', finding.impact);
        section(card, 'Prerequisites', finding.prerequisites);
        card.append(element('h4', 'Evidence'));
        const references = element('ul');
        for (const ref of finding.evidence) references.append(element('li', `${ref.path}:${ref.start_line}–${ref.end_line}`));
        card.append(references, element('h4', 'Exploitation steps (proposed, not executed)'));
        const steps = element('ol');
        for (const step of finding.exploitation_steps) steps.append(element('li', step));
        card.append(steps);
        section(card, 'Code fix', finding.code_fix, true);
        section(card, 'Regression test', finding.regression_test);
        if (finding.missing_evidence) section(card, 'Missing evidence', finding.missing_evidence);
        container.append(card);
      }
    }
    if (review.limitations.length) inventory(container, 'Model-noted limitations', review.limitations, value => value);
    inventory(container, 'Files successfully reviewed', review.reviewed_paths, value => value);
    inventory(container, 'Files not reviewed', review.skipped, item => `${item.path} — ${item.reason}`);
  }
  function progress(container, state) {
    container.hidden = false;
    container.replaceChildren();
    const meter = element('progress');
    meter.setAttribute('aria-label', state.phase === 'collecting' ? 'Source collection progress' : 'Batch review progress');
    if (state.phase === 'collecting' && state.discovered_files > 0) {
      meter.max = state.discovered_files;
      meter.value = (state.collected_files || 0) + (state.skipped_files || 0);
    } else if (state.total_batches > 0) {
      meter.max = state.total_batches;
      meter.value = (state.completed_batches || 0) + (state.failed_batches || 0);
    }
    container.append(meter);
    const stats = [];
    if (Number.isInteger(state.collected_files)) stats.push(`${state.collected_files} collected`);
    if (Number.isInteger(state.reviewed_files)) stats.push(`${state.reviewed_files} reviewed`);
    if (Number.isInteger(state.skipped_files)) stats.push(`${state.skipped_files} skipped`);
    if (state.total_batches) stats.push(`Batch ${state.current_batch} of ${state.total_batches}`);
    container.append(element('p', stats.join(' · ')));
  }
  return {render, progress};
})();
