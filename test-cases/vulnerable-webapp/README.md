# Deliberately vulnerable web application

A small, executable security-scanner fixture containing six intentional issues.
It uses only Python's standard library, SQLite in memory, and synthetic records.
Run it locally; it is excluded from the BonnyAI AWS application image.

## Run

From the repository root (Python 3.12+):

```powershell
.venv/Scripts/python.exe test-cases/vulnerable-webapp/app.py
```

Or, with any suitable Python installation:

```bash
python test-cases/vulnerable-webapp/app.py
```

- Target application: **http://127.0.0.1:8001**
- Attacker demonstration pages: **http://127.0.0.1:8002**
- Synthetic administrator: **`admin` / `LabOnly123!`**

Both servers bind only to `127.0.0.1`. No packages, HF token, external services,
or disk database are needed. Change ports with `--port 8101 --attacker-port 8102`.
Use `127.0.0.1` consistently rather than mixing it with `localhost`.
Press Ctrl+C to stop both servers. Restart clears sessions, email changes and
newsletter state. **Reset demo account** restores account fields without logging out.

## Expected vulnerabilities

| ID | Issue | Entry point / source | Root cause and expected evidence |
| --- | --- | --- | --- |
| VULN-01 | Reflected XSS | `GET /search?q=...`, `app.py` | Raw query text is concatenated into the HTML response and executes in the target origin. |
| VULN-02 | CSRF | `POST /profile/email`, `app.py`; demonstration at attacker `/csrf` | Cookie-authenticated mutation accepts another origin's form without a CSRF token or Origin/Referer check. |
| VULN-03 | Clickjacking | `GET /account?frame=1`, `app.py`; demonstration at attacker `/clickjacking` | No `X-Frame-Options` or CSP `frame-ancestors`; an overlay tricks the user into activating the authenticated newsletter button. |
| VULN-04 | SQL injection | `GET /products?category=...`, `app.py` | Category input is concatenated into an executed SQLite query; injection returns an otherwise hidden record. |
| VULN-05 | Hardcoded credentials | `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `/login`, `app.py` | Fixed plaintext credentials in source actually authenticate the administrator. |
| VULN-06 | Sensitive comments | `static/index.html`, served at `/` | HTML comments disclose the working lab login and fictional internal notes, reset token and backup path. |

These are expected findings, not measured detection results. A scanner may group
overlapping findings, such as the credential also disclosed in the HTML comment.
The existing structured review schema places CSRF, clickjacking and sensitive
comments in its `Other` category while retaining their specific vulnerability titles.

## Reproduce with a browser

### 1. XSS

Open `/search` and enter this harmless payload in the search field:

```html
<script>document.body.dataset.xss='executed';alert('LAB XSS')</script>
```

Submit. The alert demonstrates script execution. Inspecting the document body also
shows `data-xss="executed"`. No cookies or external data are collected.

### 2. CSRF

1. Log in at `http://127.0.0.1:8001/login` with the sample credentials.
2. Visit `http://127.0.0.1:8002/csrf`.
3. Press **View sample offer**. The form submits an email change to the target.
4. The target account now shows `attacker@example.test`.

Different ports are **different origins but the same browser site**. The example
therefore works with the lab's `SameSite=Lax` cookie: that setting does not defend
against a malicious same-site origin. This demonstration does not claim that the
cookie would be sent on a cross-site POST from an unrelated domain. The page uses
a deliberate click to make the state change easy to observe; there is no CORS
permission or CSRF token involved.

### 3. Clickjacking

1. Log in and reset the demo account so the newsletter is disabled.
2. Visit `http://127.0.0.1:8002/clickjacking`.
3. Click **Claim sample reward**. A nearly transparent iframe overlays that area,
   so the click actually activates **Enable newsletter** on the target.
4. Open the target account and verify **Newsletter: enabled**.

Both origins are local and same-site, keeping browser third-party cookie blocking
from obscuring the missing frame protection. No real subscription is created.

### 4. SQL injection

Open `/products?category=office`. It returns two public products. Enter this value
in the category filter and submit:

```sql
' OR 1=1 --
```

The result includes **Unreleased demo product**, which the normal query excludes
with `hidden = 0`. This modifies a SELECT expression; it does not delete records.

### 5. Hardcoded credentials

Read the constants in `app.py`, then log in with `admin` / `LabOnly123!`. Access to
`/account` demonstrates that these source-visible values are active credentials,
not unused strings. They are valid only for this intentionally vulnerable lab.

### 6. Sensitive comments

Use **View page source** on the home page and find `VULN-06`. It exposes a lab
password, a synthetic reset token, an internal backup path and a release note.
The reset token/path are fictional, and no backup download endpoint exists.

## Verification

```powershell
.venv/Scripts/python.exe test-cases/vulnerable-webapp/verify_lab.py
```

Seven checks start temporary local servers on random ports, exercise the six
vulnerabilities and account reset, then stop the servers. These HTTP checks verify
the unescaped XSS payload and frame headers; use the browser steps above to observe
actual JavaScript execution, automatic session-cookie handling, and click redirection.

To automate those browser checks, use Node 22+, this repository's `.venv`, and
Microsoft Edge (or set `BROWSER_PATH` to a Chromium executable):

```powershell
node test-cases/vulnerable-webapp/verify_browser.cjs
```

It starts the lab on temporary ports, verifies all six cases in a real headless
browser, and stops the processes. Both the seven HTTP checks and the six-case
browser run passed when this fixture was added.

## Use with the scanner

The GitHub review feature reads source without running the application. Scan
`https://github.com/samwassef/BonnyAI-SAST` with ref `feature/aws-test-deployment`
to include this lab after these files are pushed.
Check that `test-cases/vulnerable-webapp/app.py` and its HTML files appear in the
reviewed-file inventory; a bounded scan of the entire repository may omit files.
For a focused evaluation, publish this folder's contents as a separate test repo.

The deployed HTTP inspector intentionally refuses localhost/private targets, and
performs GET collection without executing JavaScript or logging in. It cannot
exercise these interactive cases against your local lab. Use the browser demos
for runtime reproduction and GitHub review for source analysis.

## Expected remediation (do not apply to this vulnerable fixture)

- XSS: context-aware output escaping or an autoescaping template engine.
- CSRF: validated anti-CSRF tokens plus an Origin allowlist; cookie attributes
  provide additional protection, not a replacement for those controls.
- Clickjacking: CSP `frame-ancestors 'none'` or a tightly scoped allowlist, with
  `X-Frame-Options: DENY` where appropriate.
- SQL injection: bind category as a parameter instead of concatenating SQL.
- Credentials: per-user authentication with password hashing and external secret
  configuration rather than a fixed source-visible administrator password.
- Sensitive comments: remove internal notes and credential values from delivered
  HTML; rotate any real exposed secret in an actual application.
