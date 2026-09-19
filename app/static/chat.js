"use strict";
const messages = document.querySelector('#messages');
const promptBox = document.querySelector('#prompt');
const statusLine = document.querySelector('#status');
const send = document.querySelector('#send');
const clear = document.querySelector('#clear');
let history = [];
let busy = false;
let repositoryReport = null;

document.querySelector('#download-report').addEventListener('click', () => {
  if (!repositoryReport) return;
  const url = URL.createObjectURL(new Blob([repositoryReport.html], {type: 'text/html;charset=utf-8'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = `github-security-review-${repositoryReport.commit.slice(0, 12)}.html`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

document.querySelector('#repository-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const button = document.querySelector('#review-repository');
  const status = document.querySelector('#repository-status');
  const result = document.querySelector('#repository-result');
  const download = document.querySelector('#download-report');
  busy = true;
  button.disabled = send.disabled = clear.disabled = document.querySelector('#analyze').disabled = true;
  repositoryReport = null;
  download.hidden = true;
  result.textContent = '';
  result.setAttribute('aria-busy', 'true');
  const progressPanel = document.querySelector('#repository-progress');
  RepositoryReviewUI.progress(progressPanel, {phase: 'collecting'});
  const urlInput = document.querySelector('#repository-url');
  const refInput = document.querySelector('#repository-ref');
  urlInput.disabled = refInput.disabled = true;
  status.textContent = 'Downloading repository and reviewing source with GLM. This may take a few minutes.';
  let reviewing = true;
  let polling = false;
  const progressTimer = setInterval(async () => {
    if (polling) return;
    polling = true;
    try {
      const response = await fetch('/api/review-progress', {headers: {'X-Chat-Request': '1'}});
      if (response.ok) {
        const progress = await response.json();
        if (reviewing) {
          status.textContent = progress.message;
          RepositoryReviewUI.progress(progressPanel, progress);
        }
      }
    } catch (_) {
      // The main request reports connection errors; progress is best effort.
    } finally {
      polling = false;
    }
  }, 1500);
  try {
    const response = await fetch('/api/review-repository', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-Chat-Request': '1'},
      body: JSON.stringify({url: document.querySelector('#repository-url').value.trim(),
        ref: document.querySelector('#repository-ref').value.trim()})
    });
    const data = await response.json();
    reviewing = false;
    if (!response.ok) throw new Error(data.detail || 'Repository review failed.');
    RepositoryReviewUI.render(result, data);
    status.textContent = `${data.repository} · Commit ${data.commit.slice(0, 12)} · ${data.reviewed_files} files reviewed · ${data.skipped_files} skipped`
      + (data.finish_reason !== 'stop' ? ' · Model response incomplete or interrupted.' : ' · Report ready.');
    repositoryReport = {html: data.report_html, commit: data.commit};
    if (data.review?.partial) status.textContent += ' Partial coverage; see skipped files and batch status in the report.';
    download.hidden = false;
  } catch (error) {
    status.textContent = error.message || 'Connection failed.';
  } finally {
    reviewing = false;
    clearInterval(progressTimer);
    progressPanel.hidden = true;
    result.setAttribute('aria-busy', 'false');
    urlInput.disabled = refInput.disabled = false;
    busy = false;
    button.disabled = send.disabled = clear.disabled = document.querySelector('#analyze').disabled = false;
  }
});

function append(role, content) {
  document.querySelector('#welcome')?.remove();
  const article = document.createElement('article');
  article.className = role;
  const label = document.createElement('strong');
  label.textContent = role === 'user' ? 'You' : 'GLM 5.3';
  const text = document.createElement('p');
  text.textContent = content; // Never render model or user text as HTML.
  article.append(label, text);
  messages.append(article);
  messages.scrollTop = messages.scrollHeight;
  return article;
}

document.querySelector('#composer').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy || !promptBox.value.trim()) return;
  const content = promptBox.value.trim();
  const pending = [...history, {role: 'user', content}];
  if (pending.length > 21 || pending.reduce((n, m) => n + m.content.length, 0) > 40000) {
    statusLine.textContent = 'Conversation limit reached. Start a new chat to continue.';
    return;
  }
  busy = true;
  send.disabled = clear.disabled = promptBox.disabled = true;
  const userEntry = append('user', content);
  statusLine.textContent = 'GLM is thinking…';
  try {
    const response = await fetch('/api/chat', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-Chat-Request': '1'},
      body: JSON.stringify({messages: pending})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Request failed. Please try again.');
    append('assistant', data.answer);
    history = [...pending, {role: 'assistant', content: data.answer}];
    promptBox.value = '';
    statusLine.textContent = data.finish_reason === 'length'
      ? 'Output limit reached; this answer may be incomplete.' : 'Ready';
  } catch (error) {
    userEntry.remove();
    statusLine.textContent = error.message || 'Connection failed. Check that the server is running.';
  } finally {
    busy = false;
    send.disabled = clear.disabled = promptBox.disabled = false;
    promptBox.focus();
  }
});
promptBox.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    document.querySelector('#composer').requestSubmit();
  }
});
clear.addEventListener('click', () => {
  repositoryReport = null;
  document.querySelector('#download-report').hidden = true;
  document.querySelector('#repository-result').textContent = '';
  document.querySelector('#repository-progress').hidden = true;
  document.querySelector('#repository-status').textContent = '';
  history = [];
  messages.replaceChildren();
  promptBox.value = '';
  statusLine.textContent = 'New conversation. Ready.';
  promptBox.focus();
  document.querySelector('#analysis-result').textContent = '';
  document.querySelector('#analysis-status').textContent = '';
});

document.querySelector('#analysis-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const button = document.querySelector('#analyze');
  const status = document.querySelector('#analysis-status');
  const result = document.querySelector('#analysis-result');
  busy = true;
  button.disabled = send.disabled = clear.disabled = true;
  result.textContent = '';
  status.textContent = 'Fetching response and asking GLM to analyze it…';
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-Chat-Request': '1'},
      body: JSON.stringify({url: document.querySelector('#target-url').value,
        question: document.querySelector('#analysis-question').value})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Analysis failed.');
    result.textContent = data.answer;
    status.textContent = `HTTP ${data.status} · ${data.responses} response(s) · ${data.body_bytes} body bytes · ${data.final_url}`
      + (data.finish_reason === 'length' ? ' · Answer may be incomplete (output limit).' : '');
  } catch (error) {
    status.textContent = error.message || 'Connection failed.';
  } finally {
    busy = false;
    button.disabled = send.disabled = clear.disabled = false;
  }
});
