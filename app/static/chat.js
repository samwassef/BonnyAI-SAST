"use strict";
const messages = document.querySelector('#messages');
const promptBox = document.querySelector('#prompt');
const statusLine = document.querySelector('#status');
const tokenBox = document.querySelector('#hf-token');
const send = document.querySelector('#send');
const clear = document.querySelector('#clear');
const cancel = document.querySelector('#cancel');
let history = [];
let busy = false;
let repositoryReport = null;
let activeRequest = null;
let pageGeneration = 0;
const config = fetch('/api/config', {cache: 'no-store'})
  .then(r => r.ok ? r.json() : {token_required: true})
  .catch(() => ({token_required: true}));

function setBusy(value) {
  busy = value;
  for (const id of ['review-repository', 'analyze', 'send', 'clear', 'hf-token', 'repository-url', 'repository-ref']) {
    document.getElementById(id).disabled = value;
  }
  promptBox.disabled = value;
  cancel.hidden = !value;
}

async function request(path, body, onEvent = () => {}) {
  const generation = pageGeneration;
  const settings = await config;
  if (generation !== pageGeneration) throw new Error('Page closed.');
  const token = tokenBox.value.trim();
  if (settings.token_required && !token) throw new Error('Enter your Hugging Face token to continue.');
  activeRequest = new AbortController();
  let reader;
  let completed = false;
  let result;
  try {
    const response = await fetch(path, {
      method: 'POST', signal: activeRequest.signal, cache: 'no-store',
      headers: {'Content-Type': 'application/json', 'X-Chat-Request': '1',
        'Accept': 'application/x-ndjson', ...(token ? {'X-HF-Token': token} : {})},
      body: JSON.stringify(body)
    });
    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.detail || 'Request failed.');
    }
    reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    while (true) {
      const {value, done} = await reader.read();
      if (generation !== pageGeneration) throw new Error('Page closed.');
      buffer += decoder.decode(value, {stream: !done});
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        if (!line.trim()) continue;
        const event = JSON.parse(line);
        if (event.type === 'error') throw new Error(event.data.detail);
        if (event.type === 'complete') { completed = true; result = event.data; }
        else onEvent(event);
      }
      if (done) break;
    }
    if (!completed) throw new Error('Connection ended before completion. Any partial report below remains downloadable.');
    return result;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Cancelled. Any partial report below remains downloadable.');
    throw error;
  } finally {
    if (reader) await reader.cancel().catch(() => {});
    activeRequest = null;
  }
}

cancel.addEventListener('click', () => activeRequest?.abort());

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

function showReport(data) {
  RepositoryReviewUI.render(document.querySelector('#repository-result'), data);
  repositoryReport = {html: data.report_html, commit: data.commit};
  document.querySelector('#download-report').hidden = false;
}

document.querySelector('#repository-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const status = document.querySelector('#repository-status');
  const result = document.querySelector('#repository-result');
  const progressPanel = document.querySelector('#repository-progress');
  setBusy(true);
  repositoryReport = null;
  document.querySelector('#download-report').hidden = true;
  result.textContent = '';
  result.setAttribute('aria-busy', 'true');
  RepositoryReviewUI.progress(progressPanel, {phase: 'collecting'});
  status.textContent = 'Downloading repository and reviewing source with GLM. This may take a few minutes.';
  try {
    const data = await request('/api/review-repository', {
      url: document.querySelector('#repository-url').value.trim(),
      ref: document.querySelector('#repository-ref').value.trim()
    }, event => {
      if (event.type === 'progress') {
        status.textContent = event.data.message;
        RepositoryReviewUI.progress(progressPanel, event.data);
      } else if (event.type === 'snapshot') showReport(event.data);
    });
    showReport(data);
    status.textContent = `${data.repository} · Commit ${data.commit.slice(0, 12)} · ${data.reviewed_files} files reviewed · ${data.skipped_files} skipped`
      + (data.finish_reason !== 'stop' ? ' · Model response incomplete or interrupted.' : ' · Report ready.');
    if (data.review?.partial) status.textContent += ' Partial coverage; see skipped files and batch status in the report.';
  } catch (error) {
    status.textContent = error.message || 'Connection failed.';
    if (repositoryReport) status.textContent += ' Download the partial report before leaving this page.';
  } finally {
    progressPanel.hidden = true;
    result.setAttribute('aria-busy', 'false');
    setBusy(false);
  }
});

function append(role, content) {
  document.querySelector('#welcome')?.remove();
  const article = document.createElement('article');
  article.className = role;
  const label = document.createElement('strong');
  label.textContent = role === 'user' ? 'You' : 'GLM 5.3';
  const text = document.createElement('p');
  text.textContent = content;
  article.append(label, text);
  messages.append(article);
  messages.scrollTop = messages.scrollHeight;
  return article;
}

document.querySelector('#composer').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy || !promptBox.value.trim()) return;
  const pending = [...history, {role: 'user', content: promptBox.value.trim()}];
  if (pending.length > 21 || pending.reduce((n, m) => n + m.content.length, 0) > 40000) {
    statusLine.textContent = 'Conversation limit reached. Start a new chat to continue.';
    return;
  }
  setBusy(true);
  const entry = append('user', promptBox.value.trim());
  statusLine.textContent = 'GLM is thinking…';
  try {
    const data = await request('/api/chat', {messages: pending});
    append('assistant', data.answer);
    history = [...pending, {role: 'assistant', content: data.answer}];
    promptBox.value = '';
    statusLine.textContent = data.finish_reason === 'length' ? 'Output limit reached; this answer may be incomplete.' : 'Ready';
  } catch (error) {
    entry.remove();
    statusLine.textContent = error.message || 'Connection failed.';
  } finally {
    setBusy(false);
    promptBox.focus();
  }
});
promptBox.addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    document.querySelector('#composer').requestSubmit();
  }
});

function resetSession() {
  pageGeneration++;
  activeRequest?.abort();
  tokenBox.value = '';
  repositoryReport = null;
  history = [];
  messages.replaceChildren();
  promptBox.value = '';
  document.querySelector('#download-report').hidden = true;
  document.querySelector('#repository-progress').hidden = true;
  document.querySelector('#repository-result').setAttribute('aria-busy', 'false');
  for (const id of ['repository-result', 'repository-status', 'analysis-result', 'analysis-status']) {
    document.getElementById(id).textContent = '';
  }
  for (const form of document.querySelectorAll('form')) form.reset();
  statusLine.textContent = 'Session cleared. Enter your token to continue.';
  setBusy(false);
}
clear.addEventListener('click', resetSession);
window.addEventListener('pagehide', resetSession);
window.addEventListener('pageshow', event => { if (event.persisted) resetSession(); });
// Clear any browser-restored form values on a fresh navigation too.
tokenBox.value = '';

document.querySelector('#analysis-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  const status = document.querySelector('#analysis-status');
  const result = document.querySelector('#analysis-result');
  setBusy(true);
  result.textContent = '';
  status.textContent = 'Fetching response and asking GLM to analyze it…';
  try {
    const data = await request('/api/analyze', {
      url: document.querySelector('#target-url').value,
      question: document.querySelector('#analysis-question').value
    }, event => { if (event.type === 'progress') status.textContent = event.data.message; });
    result.textContent = data.answer;
    status.textContent = `HTTP ${data.status} · ${data.responses} response(s) · ${data.body_bytes} body bytes · ${data.final_url}`
      + (data.finish_reason === 'length' ? ' · Answer may be incomplete (output limit).' : '');
  } catch (error) {
    status.textContent = error.message || 'Connection failed.';
  } finally {
    setBusy(false);
  }
});
