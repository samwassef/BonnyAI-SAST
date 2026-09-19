// Browser integration checks using local Edge/Chrome and Node's built-in CDP client.
// GitHub and inference are replaced by browser_test_server.py fixtures.
const assert = require('node:assert/strict');
const {spawn, spawnSync} = require('node:child_process');
const {mkdtempSync, existsSync} = require('node:fs');
const {tmpdir} = require('node:os');
const path = require('node:path');
const net = require('node:net');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function port() {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const value = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return value;
}
async function until(check, timeout = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try { const result = await check(); if (result) return result; } catch (_) {}
    await delay(100);
  }
  throw new Error('Timed out waiting for browser condition');
}
async function main() {
  const browserPath = process.env.BROWSER_PATH || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  assert.ok(existsSync(browserPath), 'Set BROWSER_PATH to a Chromium browser executable.');
  const appPort = await port();
  const debugPort = await port();
  const python = process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python';
  const server = spawn(python, ['browser_test_server.py', String(appPort)], {cwd: __dirname, windowsHide: true, stdio: 'ignore'});
  let browser, ws;
  try {
    await until(async () => (await fetch(`http://127.0.0.1:${appPort}/`)).ok);
    const profile = mkdtempSync(path.join(tmpdir(), 'repository-browser-test-'));
    browser = spawn(browserPath, ['--headless=new', '--no-first-run', '--no-default-browser-check',
      '--disable-gpu', '--disable-extensions', '--disable-background-networking',
      `--user-data-dir=${profile}`, `--remote-debugging-port=${debugPort}`, 'about:blank'],
      {windowsHide: true, stdio: 'ignore'});
    const targets = await until(async () => (await fetch(`http://127.0.0.1:${debugPort}/json/list`)).json());
    const target = targets.find(value => value.type === 'page');
    ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
    let nextId = 0;
    const pending = new Map();
    ws.onmessage = event => {
      const value = JSON.parse(event.data);
      if (value.method === 'Runtime.exceptionThrown') console.error('Browser script error:', JSON.stringify(value.params));
      if (pending.has(value.id)) {
        const {resolve, reject, timer} = pending.get(value.id);
        clearTimeout(timer); pending.delete(value.id);
        value.error ? reject(new Error(JSON.stringify(value.error))) : resolve(value.result);
      }
    };
    function send(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = ++nextId;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
        pending.set(id, {resolve, reject, timer});
        ws.send(JSON.stringify({id, method, params}));
      });
    }
    async function evaluate(expression) {
      const result = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
      if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
      return result.result.value;
    }
    await send('Runtime.enable');
    const navigation = await send('Page.navigate', {url: `http://127.0.0.1:${appPort}/`});
    assert.ok(!navigation.errorText, navigation.errorText);
    try {
      await until(() => evaluate(`!!document.querySelector('#repository-url') && !!window.RepositoryReviewUI`));
    } catch (error) {
      console.error(await evaluate(`JSON.stringify({url: location.href, body: document.body?.innerText.slice(0, 1500), ui: typeof window.RepositoryReviewUI})`));
      throw error;
    }
    assert.equal(await evaluate(`document.querySelector('#panel-sast').hidden === false &&
      document.querySelector('#panel-http').hidden && document.querySelector('#panel-chat').hidden`), true);
    await evaluate(`document.querySelector('#hf-token').value = 'hf_browserFixture123';
      document.querySelector('#tab-http').click()`);
    assert.equal(await evaluate(`document.querySelector('#panel-http').hidden === false &&
      document.querySelector('#panel-sast').hidden && document.querySelector('#hf-token').value === 'hf_browserFixture123'`), true);
    await evaluate(`document.querySelector('#tab-http').dispatchEvent(new KeyboardEvent('keydown', {key:'ArrowRight', bubbles:true}))`);
    assert.equal(await evaluate(`document.querySelector('#panel-chat').hidden === false &&
      document.activeElement.id === 'tab-chat' && document.querySelector('#hf-access').hidden === false`), true);
    await evaluate(`document.querySelector('#tab-sast').click()`);
    async function scan(repo, expectProgress = true) {
      await evaluate(`document.querySelector('#repository-url').value = ${JSON.stringify(`https://github.com/example/${repo}`)};
        document.querySelector('#repository-ref').value = 'feature/security';
        document.querySelector('#hf-token').value = 'hf_browserFixture123';
        document.querySelector('#repository-form').requestSubmit();`);
      if (expectProgress) {
        await until(() => evaluate(`document.querySelector('#repository-progress').textContent.includes('Batch')`));
        assert.equal(await evaluate(`document.querySelector('#repository-url').disabled`), true);
      }
      await until(() => evaluate(`!document.querySelector('#review-repository').disabled`));
      assert.equal(await evaluate(`document.querySelector('#repository-result').getAttribute('aria-busy')`), 'false');
      return evaluate(`document.querySelector('#repository-result').textContent`);
    }
    let text = await scan('full-python');
    assert.ok(text.includes('Root cause') && text.includes('Code fix') && text.includes('Exploitation steps'));
    assert.equal(await evaluate(`document.querySelectorAll('.review-finding').length`), 2);
    assert.equal(await evaluate(`document.querySelectorAll('.severity-high').length`), 2);
    assert.equal(await evaluate(`document.querySelector('#repository-result img, #repository-result script') === null && !window.pwned`), true);
    assert.equal(await evaluate(`document.querySelector('#download-report').hidden`), false);
    assert.equal(await evaluate(`repositoryReport.html.includes('class="severity high"') && repositoryReport.html.includes('&lt;script&gt;')`), true);
    // Exercise the actual download button without writing an artifact to Downloads.
    assert.equal(await evaluate(`(() => {
      let clicked = false;
      const original = HTMLAnchorElement.prototype.click;
      HTMLAnchorElement.prototype.click = function() { clicked = this.download.endsWith('.html') && this.href.startsWith('blob:'); };
      document.querySelector('#download-report').click();
      HTMLAnchorElement.prototype.click = original;
      return clicked;
    })()`), true);
    text = await scan('empty-javascript');
    assert.ok(text.includes('No findings established'));
    assert.equal(await evaluate(`document.querySelectorAll('.review-finding').length`), 0);
    text = await scan('partial-java');
    assert.ok(text.includes('partial coverage') && text.includes('Some batches could not be reviewed'));
    assert.equal(await evaluate(`document.querySelectorAll('.review-finding').length`), 1);
    assert.ok(text.includes('Files successfully reviewed (2)') && text.includes('Files not reviewed (2)'));
    text = await scan('provider-error');
    assert.ok(text.includes('provider request failed') && text.includes('Files successfully reviewed (0)'));
    await scan('collect-error', false);
    assert.equal(await evaluate(`document.querySelector('#download-report').hidden`), true);
    assert.equal(await evaluate(`document.querySelector('#repository-status').textContent`), 'Fixture collection failure.');
    await send('Emulation.setDeviceMetricsOverride', {width: 390, height: 844, deviceScaleFactor: 1, mobile: true});
    await scan('full-python');
    assert.equal(await evaluate(`document.documentElement.scrollWidth <= window.innerWidth`), true);
    await evaluate(`document.querySelector('#tab-chat').click()`);
    assert.equal(await evaluate(`document.documentElement.scrollWidth <= window.innerWidth`), true);
    await evaluate(`document.querySelector('#clear').click()`);
    assert.equal(await evaluate(`document.querySelector('#repository-result').textContent`), '');
    assert.equal(await evaluate(`document.querySelector('#download-report').hidden`), true);
    assert.equal(await evaluate(`document.querySelector('#hf-token').value`), '');
    assert.equal(await evaluate(`localStorage.length + sessionStorage.length`), 0);
    await evaluate(`document.querySelector('#hf-token').value = 'hf_browserFixture123';
      document.querySelector('#repository-url').value = 'https://github.com/example/full-python';
      document.querySelector('#repository-form').requestSubmit();`);
    await until(() => evaluate(`!document.querySelector('#download-report').hidden && busy`));
    await evaluate(`document.querySelector('#cancel').click()`);
    await until(() => evaluate(`!busy`));
    assert.equal(await evaluate(`document.querySelector('#download-report').hidden`), false);
    assert.ok((await evaluate(`document.querySelector('#repository-status').textContent`)).includes('Cancelled'));
    // Page lifecycle discards the report and token, including history-cache restore.
    await evaluate(`window.dispatchEvent(new PageTransitionEvent('pagehide'))`);
    assert.equal(await evaluate(`repositoryReport === null && history.length === 0 && document.querySelector('#hf-token').value === ''`), true);
    console.log('Browser checks passed: progress, generic repositories, formatted findings, escaping, download, empty/partial/error states, mobile layout, and reset.');
    await send('Browser.close').catch(() => {});
  } finally {
    if (ws) ws.close();
    if (browser) browser.kill();
    // The Windows virtualenv launcher can own a child interpreter.
    if (process.platform === 'win32' && server.pid) {
      spawnSync('taskkill.exe', ['/pid', String(server.pid), '/t', '/f'], {windowsHide: true, stdio: 'ignore'});
    } else {
      server.kill();
    }
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
