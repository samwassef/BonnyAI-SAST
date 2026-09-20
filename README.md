# BonnyAI: GLM-5.3 security review and chat

GitHub source review, HTTP inspection, and chat through Hugging Face Inference
Providers, served by FastAPI on AWS Lightsail.

**Web app:** [https://3-211-234-215.sslip.io](https://3-211-234-215.sslip.io).
Open it directly in your browser and enter your own Hugging Face token. No SSH
tunnel, local server, registration, or domain purchase is required. Reports remain
in the page until cleared, refreshed, or closed; download any report you want to keep.
The token field stays above three workspace tabs: **SAST scanning** for GitHub source
reviews, **HTTP analysis** for a webpage response, and **General chat**. Switching
tabs keeps each tab's in-page results and uses the same token field.

See [architecture and deployment steps](#aws-lightsail-test-deployment).
The original terminal-token local mode remains available for development.

## Analyze a webpage (Step 3)

Restart the server after updating dependencies with the commands below. In the
**HTTP analysis** tab, enter an HTTP(S) URL and your question, then click
**Fetch and analyze**. Python collects the response and sends it to GLM-5.3 through
Hugging Face. The result shows the final URL, HTTP status, number of responses,
body byte count, and model analysis. This analysis is separate from chat history;
submitting again fetches again. No evidence is saved to disk.

**Headers and small HTML responses are sent without redaction or summarization**.
For larger responses, the analyzer sends a bounded excerpt from the beginning and
end of the collected HTML and marks the evidence partial. This can include cookie
values and any credentials or sensitive content returned by the website. The app does not forward its Hugging Face token, browser
cookies, or user-supplied request headers to the target. The token is used only by
the inference client. The user question and untrusted evidence are separate
messages; the model receives no tools and cannot initiate additional requests.

Repeated response headers (including Set-Cookie) are preserved as ordered name/value
pairs. Each redirect response is included, with at most 5000 HTML characters from
its body. The final response receives the remaining excerpt budget. Within each
excerpt, whitespace, inline scripts, and comments are retained. The payload uses
JSON encoding, which preserves these values after decoding. This is not a raw wire capture: the HTTP library parses
headers and removes transfer framing; body bytes are strictly decoded with the
declared charset, or UTF-8 when absent. Unsupported/invalid text encodings fail
instead of replacing characters. Compressed responses are rejected if a server
ignores `Accept-Encoding: identity`. No scripts run and no linked assets are fetched.

Only public DNS hostnames on standard HTTP/HTTPS ports are supported. IP-literal,
credential-bearing, private, loopback, metadata, and transition-IP destinations are
blocked. All A/AAAA answers are checked before connecting directly to one approved
IP. HTTPS certificates and SNI use the original hostname. Environment proxies and
automatic redirect following are not used. A request authorizes only the submitted
hostname; redirects to another hostname require submitting that URL separately.
Targets are supplied per request; the app keeps no persistent target registry.

Limits: five redirects, 100000 bytes of response headers, 1000000 downloaded body
bytes across responses, 30000 HTML characters in the combined excerpts, and 140000
characters of serialized model evidence. Large bodies are clipped explicitly and the
result is labeled partial; oversized headers still fail before the LLM call. The
analyzer does not fetch or infer omitted content. DNS queries have a three-second
lifetime per address family. Sockets have a ten-second inactivity timeout, with a
45-second collection budget checked between hops and body reads (an in-flight
operation can exceed that budget). Provider context limits may still reject a
payload; application size limits are not exact tokenizer limits.

The collection and LLM paths are tested with mocks; no automated tests contact
external websites. Live analysis requires your token and an authorized target.

## Start the chat webpage

From this repository in the VS Code PowerShell terminal:

```powershell
uv --cache-dir .uv-cache pip install --python .venv/Scripts/python.exe -r requirements.txt
.venv/Scripts/python.exe run_chat.py --prompt-token
```

Paste your token at `Hugging Face token (hidden):` and press Enter. No characters
appear while pasting. The token stays in server memory and is not saved or sent to
the browser. Open **http://127.0.0.1:8000** to chat. Press Ctrl+C in the terminal to
stop the server. If port 8000 is busy, add `--port 8001` and open the printed URL.
An existing `HF_TOKEN` environment variable also works without `--prompt-token`.

Type a message and click **Send message**, or press Enter. Shift+Enter inserts a
newline. **New chat** clears the conversation; refreshing the page also clears it.
History is kept in tab memory, with no browser local storage or server database.
Each request sends the current conversation to Hugging Face and the selected
provider; inference uses account credits. Clearing the UI does not delete provider
records. Answers are shown as plain text, including any code or Markdown.

The model is `zai-org/GLM-5.3`, with provider `novita` by default; `--provider NAME`
selects another supported route. Each request uses low reasoning effort, a
2048-token output budget, and a 90-second HTTP timeout. No application retries or
fallback models are used. The page reports errors and incomplete token-limited
answers. It permits 10 previous exchanges, 20000 characters per message and 40000
characters total; start a new chat when these limits are reached. Character bounds
are conservative application limits, not an exact tokenizer/context calculation.

`run_chat.py` is the original single-user, loopback-only mode with a terminal token.
For visitor tokens on localhost, run `.venv/Scripts/python.exe run_server.py --local`.
For the AWS container entry point, use the deployment instructions below. Host and
Origin checks, a single-operation limit, sanitized errors, and escaped output apply
in all modes. Only the Python collector fetches submitted targets; GLM has no tools.

## Offline tests

```powershell
.venv/Scripts/python.exe -m unittest -v
```

Tests mock inference and cover the original checker, chat history validation,
static assets, source checks, body size limits, provider errors and token redaction.
No real tokens or external inference calls are used by the tests.

## AWS Lightsail test deployment

One Ubuntu 24.04 Lightsail instance in `us-east-1`, using the public IPv4 2 GB / 2 vCPU
bundle (`small_3_0`, USD 12/month before taxes and excess usage). No NAT gateway,
load balancer, registration, database, queues, or report bucket. Visitors pay their
own Hugging Face inference charges. See [Lightsail pricing](https://aws.amazon.com/lightsail/pricing/).

The current deployment is **public HTTPS** at
[https://3-211-234-215.sslip.io](https://3-211-234-215.sslip.io), served by
`bonnyai-test-server` at static IPv4 `3.211.234.215`. The free `sslip.io` hostname
resolves its embedded IP address to the server; no purchased domain or DNS account
is needed. It depends on the third-party [sslip.io DNS service](https://sslip.io/).
Caddy obtains and renews a publicly trusted certificate. Visitors connect directly
to AWS; SSH is used only for administration.

| Network entry | Access |
| --- | --- |
| TCP 443 | Public HTTPS webpage, API, progress and report responses |
| TCP 80 | Public certificate validation and GET/HEAD redirects to HTTPS; other HTTP requests are rejected |
| TCP 22 | SSH restricted to the administrative public IP |
| TCP 8000 | Internal Docker network only |
| TCP 8080 | Not published in the current deployment |

### Architecture

```mermaid
flowchart LR
    Browser["Visitor browser: HF token, progress, findings"]
    DNS["sslip.io DNS: hostname resolves to 3.211.234.215"]
    Download["HTML report saved on visitor device"]
    Admin["Administrator"]
    subgraph AWS["Lightsail: bonnyai-test-server / us-east-1"]
        Caddy["Caddy: public HTTPS 443 / HTTP 80 redirects and certificate validation"]
        App["FastAPI: Docker-only port 8000 / one active operation"]
        Certificates["Persistent TLS certificates only"]
        SSH["SSH 22: administrative IP only"]
        Caddy <-->|"Internal Docker network"| App
        Caddy --- Certificates
        SSH -.->|"Manage deployment"| App
    end
    Browser -->|"Resolve hostname"| DNS
    Browser <-->|"HTTPS: 3-211-234-215.sslip.io"| Caddy
    Browser -->|"Optional download"| Download
    Admin -->|"SSH administration"| SSH
    App -->|"Collect public source"| GitHub["GitHub API and raw source"]
    App -->|"Collect headers and HTML"| Website["Submitted public website"]
    App -->|"Visitor token and inference input"| HF["Hugging Face / Novita / GLM"]
```

- Docker Compose runs one `app` process and `caddy`; both restart automatically.
- The app accepts one operation at a time across GitHub scanning, HTTP inspection,
  and chat. Other requests receive HTTP 429 with a server-busy message.
- Visitors enter their own HF token in a masked field. Tokens travel over HTTPS in a request
  header, never in URLs or prompts. Each operation creates its own inference client.
- Tokens, conversation, source, findings and generated reports use memory only.
  There is no history, job ID, progress lookup, report storage or retrieval API.
  Browser refresh/close/Clear session discards results and tokens, including restored
  history pages. Downloaded HTML remains on the visitor's device.
- NDJSON events (`progress`, `snapshot`, `complete`, `error`, `heartbeat`) carry
  request-local progress and validated partial reports over the same response.
  Completed batches remain downloadable after cancellation or a later error.
- A bounded event queue connects the worker to the response stream. Heartbeats
  occur while idle; downloads and batch boundaries check cancellation and a
  two-hour deadline. An in-flight HTTP/provider call may finish or time out first;
  the busy slot remains held until its worker exits. Nothing resumes after restart.
- App filesystem is read-only, temporary filesystems are memory-backed, and Docker
  logs are disabled for both services. Host bootstrap disables swap and core dumps.
  Caddy also discards its logs, so request headers cannot enter proxy logs.
  The only persistent runtime volume is `caddy_data`, for TLS certificates and
  ACME account state; it contains no visitor tokens or reports.
- Source limits, provider timeouts, source citation validation, HTML escaping, and
  blocking of private/cloud metadata destinations remain in place.

### Public HTTPS deployment (current mode)

1. Create an Ubuntu 24.04 Lightsail instance and attach a static IP. The current
   instance is `bonnyai-test-server`, with static IP resource `bonnyai-test-ip`.
   Keep TCP 22 restricted to your administrative IP; allow TCP 80/443 publicly.
   Do not open TCP 8000 or 8080.
2. Supply `deploy/bootstrap.sh` as Lightsail user data, or copy it to the server
   and run `sudo sh deploy/bootstrap.sh`. It installs Git and Docker Engine/Compose
   using [Docker's Ubuntu repository](https://docs.docker.com/engine/install/ubuntu/)
   and disables swap/core dumps. It is POSIX-compatible with Lightsail's `/bin/sh`
   user-data wrapper.
3. Copy `feature/aws-test-deployment` to `/home/ubuntu/bonnyai` on the server.
   Clone if the repository is publicly readable, or upload a Git archive from your
   authenticated checkout. Do not copy SSH/AWS credentials, `.venv` or local reports.
4. Choose the hostname. For the current static IP, use `3-211-234-215.sslip.io`.
   Verify it resolves to `3.211.234.215`. For a different IP, change the embedded
   address; alternatively, point your own domain's DNS A record to the static IP.
5. In the server repository directory, create the deployment configuration:

   ```bash
   cp .env.example .env
   # APP_DOMAIN=3-211-234-215.sslip.io for this deployment.
   # For another server, edit APP_DOMAIN to its lowercase DNS hostname.
   sudo docker compose config --quiet
   ```

   `.env` contains the hostname only. Visitors supply HF tokens through the browser;
   never configure a shared `HF_TOKEN` here.
6. If migrating from the old tunnel deployment, stop that stack once, preserving
   volumes. Then start the public configuration:

   ```bash
   sudo docker compose -f compose.yaml -f compose.tunnel.yaml down
   sudo docker compose up -d --build --wait --wait-timeout 120
   sudo docker compose ps
   ```

   For a fresh deployment, omit the `down` command. Do not include
   `compose.tunnel.yaml` in subsequent public startup/update commands.
7. Caddy provisions the certificate automatically. Verify normal browser trust,
   HTTPS health, and HTTP redirects:

   ```bash
   curl --fail https://3-211-234-215.sslip.io/healthz
   curl --head http://3-211-234-215.sslip.io/
   ```

8. Open [the web app](https://3-211-234-215.sslip.io) from any browser and enter an
   HF token with Inference Providers permission. No local process or SSH tunnel is
   needed. The test app has no sign-up/login; each visitor supplies their own token.
   Its single-operation limit applies across all visitors.

Caddy keeps certificates and ACME state in `caddy_data`; preserve this volume during
updates to avoid unnecessary certificate reissuance. Public app mode requires
`APP_DOMAIN`, validates HTTPS origins, and runs one process. Plain HTTP API requests
are rejected before reaching the app. Certificate issuance/renewal requires working
DNS and reachable challenge ports; see [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https).

### Optional private SSH-tunnel mode

`compose.tunnel.yaml` remains available for private testing but is **not active**.
To use it, stop the public stack, close public TCP 80/443 in the Lightsail firewall,
and start the override:

```bash
sudo docker compose down
sudo docker compose -f compose.yaml -f compose.tunnel.yaml up -d --build --wait
```

This publishes only server loopback `127.0.0.1:8080`. It uses no public certificate
and needs no `APP_DOMAIN`. From your computer, keep this command running and open
`http://127.0.0.1:8080`:

```powershell
ssh -i "$env:USERPROFILE\.ssh\bonnyai-lightsail.pem" -N -L 127.0.0.1:8080:127.0.0.1:8080 -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 ubuntu@3.211.234.215
```

Compose 2.24.4+ is required for the tunnel override. When returning to public HTTPS,
stop the tunnel stack, reopen TCP 80/443, and start the base Compose file as above.

### Updates and checks

Wait for any active operation to finish, update the checkout/archive, and rerun the
public Compose build command below. For a Git clone, first run
`git pull --ff-only origin feature/aws-test-deployment`. This deployment was installed
from a Git archive, so updates require uploading/extracting a new committed archive
into `/home/ubuntu/bonnyai`, preserving its `.env` and the `caddy_data` volume.

```bash
sudo docker compose config --quiet
sudo docker compose up -d --build --wait --wait-timeout 120
curl --fail https://3-211-234-215.sslip.io/healthz
```

Container/server restart interrupts scans; visitors must resubmit them.

Offline verification: `.venv/Scripts/python.exe -m unittest -q` and
`node test_browser.cjs`. Tests use simulated providers and repositories and cover
visitor token isolation, same-origin restrictions, streaming partial reports,
busy-slot release, deadlines, cancellation, rendering, download and page cleanup.
Live inference requires a visitor's funded HF token; offline tests do not establish
model detection accuracy. Check container health and `/healthz` after deployment.
The public deployment was verified on 2026-09-19: trusted TLS, HTTPS page/assets and
health, HTTP redirects, rejection of plaintext API submissions, visitor-token and
origin enforcement, and a real Edge browser check including mobile layout. These
checks passed after stopping the local SSH tunnel. No paid inference calls were
made; live GLM scanning still requires a visitor token.

For startup diagnosis, use `docker compose ps` and `docker inspect`; persistent
application/proxy logs are intentionally disabled.

## Setup (Python 3.12+)

Run from this repository in PowerShell:

```powershell
uv --cache-dir .uv-cache venv .venv
uv --cache-dir .uv-cache pip install --python .venv/Scripts/python.exe -r requirements.txt
.venv/Scripts/python.exe check_llm.py --prompt-token
```

Create a token in [Hugging Face settings](https://huggingface.co/settings/tokens)
with permission to call Inference Providers. Enter it at the hidden terminal prompt;
the script does not save it. Do not paste your token into chat or commit it to Git.
Alternatively, supply `HF_TOKEN` through your environment or secret manager.
The script does not load `.env` files or cached CLI credentials.

The request uses `zai-org/GLM-5.3` with `novita` through the Hugging Face SDK,
a 90-second HTTP timeout, low reasoning effort, and a 256-token output limit.
Inference can consume account credits. Provider availability and parameter support
can change; use `--provider NAME` to select another supported Hugging Face provider.
No fallback model or automatic application retries are configured.

A successful call prints the model, provider, answer, and finish reason. An empty
answer is not treated as success. Exit codes: 0 = answer received, 1 = inference
failure, 2 = missing credentials or invalid CLI usage. A token-limited response
does not imply the model completed its answer.

## Verification status

The user verified the connection checker with `Connection successful` and finish
reason `stop` through Novita. The new web chat is tested offline; its live inference
must be exercised with a visitor token in the browser (or a terminal token in local mode).

References: [GLM-5.3](https://huggingface.co/zai-org/GLM-5.3),
[Hugging Face chat completion](https://huggingface.co/docs/inference-providers/en/tasks/chat-completion).

## Review a GitHub repository

Use **Review GitHub source code** with any public repository URL such as
`https://github.com/owner/repository`. Optionally enter a branch, tag, or commit;
leaving it blank reviews the default branch. Click **Scan repository**. Collection
and batch progress appear on the page with collected, reviewed, and skipped counts.
Results appear directly below the form as readable finding cards: bold titles,
colored severity, description, root cause, evidence, proposed exploitation steps,
code fixes, and regression tests. Confirmed findings and findings needing verification
are separated. Expand the coverage lists to inspect skipped files or failures.
**Download HTML report** saves the same findings and coverage as a standalone report.
Restart the server and refresh the page after updating. No scan CLI is required;
WebGoat is only an optional evaluation example, not a scanner-specific target.

The collector requests only the commit SHA, lists that commit's files using the
[GitHub trees API](https://docs.github.com/en/rest/git/trees), and downloads selected
source files from raw.githubusercontent.com. It never downloads a repository ZIP,
so large assets do not count toward a whole-repository download limit.
GLM receives selected UTF-8 source-code files with paths and original contents.
Application endpoints, security code, lessons, and templates are prioritized, followed
by other application source; tests and tooling come last. Pipeline, Docker/container, build/deployment, configuration,
and documentation files are excluded before downloading. This includes CI directories
(such as `.github`, `.gitlab`, `.circleci`, and `pipelines`), Dockerfile variants,
container/deployment directories, known build scripts and `*.config.*` files.
JSON, YAML, XML, TOML, Terraform, Gradle, Markdown, and text files are excluded.
Application source, templates, tests, and ordinary shell scripts remain eligible.
Selection uses extensions and known path/name conventions; unusually named automation
scripts with a source-code extension may still be included.
GLM is asked for severity, confidence, file/line evidence, impact and prerequisites,
concrete proposed fixes (preferably diffs), and suggested regression tests.
Intentional training vulnerabilities (including WebGoat lessons) remain in scope and
are labeled explicitly. Each batch must return validated JSON findings with a title,
severity, confidence, description, root cause, source references, input-to-sink trace,
impact, prerequisites, proposed exploitation steps, code fix, and regression test.
References must cite supplied files and valid line ranges. Validation checks structure
and reference bounds; it cannot prove that a model's security conclusions are correct.
The styled HTML report is generated from those fields, with colored severity badges,
code blocks, and collapsible coverage inventories. Counts are calculated by Python.

This is a bounded static review: up to 400 source download attempts, 30000 bytes per
file, and 1200000 collected source bytes overall. Source is reviewed in up to 24
batches, each bounded to 32000 source bytes and 60000 serialized input characters.
Primary files occupy roughly three quarters of each batch, reserving space for
referenced helpers and security context. Files stay adjacent by directory where
possible; context uses lexical symbol matching, not a language-aware call graph.
Every primary file receives its own review even if used as context in another batch.
Batch progress is displayed in the page. Each batch makes one provider request and
retries once after a timeout, rate limit, connection failure, or provider HTTP 5xx.
This permits up to 48 requests for 24 batches and can consume additional credits;
larger scans can take many minutes. Authentication, billing, and permission failures
are not retried. Files that do not
fit are listed as skipped, without truncating file contents. Dependency/build
folders, recognized lockfiles, minified files, symlinks, binary/non-UTF-8 files, and
unsupported extensions are skipped. File-list metadata over 10 MB, more than 100000 entries, or a truncated
GitHub file list fail explicitly before inference. The collection budget is
300 seconds checked between reads/requests, with existing DNS and socket timeouts;
an in-flight operation may exceed the budget. The review uses an 8192-token output
budget and the existing 90-second provider timeout per batch. Truncated or invalid
structured answers are recorded as failed batches, never clean scans; unvalidated
output is not rendered as findings. After a provider failure, the report records a
safe category (timeout, HTTP status class, or connection failure) without provider
response bodies, tokens, or source contents. Provider errors stop subsequent requests and
preserve already validated findings. Duplicates with identical root causes and source
locations are collapsed. Files are counted as reviewed only after their primary batch
returns a complete validated response. Skipped files or failed batches make coverage
explicitly partial; no findings does not mean the repository is safe.

Only public repositories on github.com are supported; no GitHub credentials are
used. GitHub rate limits and unavailable refs produce a visible error. Downloads
use validated public IPs and HTTPS, and redirects are restricted to api.github.com
and raw.githubusercontent.com. No archives are extracted, code executed, dependencies
installed, or fixes applied. Submodules and Git LFS contents are not fetched.
Repository instructions are treated as untrusted input, and GLM has no tools.
Source contents, including any embedded secrets, are sent to Hugging Face and the
configured inference provider. The server does not persist source or reports;
the generated report stays in tab memory until cleared/refreshed/closed, and the download
saves it using your browser. Model output and filenames are HTML-escaped in the
report. Findings and patches require human review; no findings does not prove
that the repository is secure.

Repository tests use mocked file lists, source downloads, and inference responses. They
cover URL and redirect boundaries, size limits, file selection, unsafe repository
paths, commit pinning, prompt construction, escaped HTML reports, API validation,
and recovery after failures. Live repository review with GLM has not been verified.

Browser regression checks use simulated GitHub and model responses for Python,
JavaScript, and Java repository layouts. Run `node test_browser.cjs` with Node 22+
and Microsoft Edge installed (or set `BROWSER_PATH` to a Chromium executable).
These exercise the page, streamed progress, formatted findings, safe code display,
download action, partial/empty/error states, reset, and mobile layout without tokens
or external requests. They validate the interface, not live vulnerability detection.

### Evaluate detection with GLM

For a runnable target with six intentional vulnerabilities, see the
[test-cases web application](test-cases/vulnerable-webapp/README.md). It includes
XSS, CSRF, clickjacking, SQL injection, hardcoded credentials and sensitive comments,
plus local attacker demonstrations. It is excluded from the AWS application image.

The opt-in evaluation uses eight synthetic source fixtures: vulnerable and mitigated
examples of SQLi, XSS, access control, and credentials. It checks the expected category
and false positives for each paired control. These are live model evaluations, separate
from the offline pipeline tests, and consume provider credits. The optional WebGoat
pass reviews the exact commit from the supplied report and exports a new HTML report;
inspect its findings and coverage manually. Source fixtures are never executed.

```powershell
.venv/Scripts/python.exe evaluate_review.py --prompt-token --webgoat
```

The evaluation saves `review-evaluation.json` and, with `--webgoat`,
`review-evaluation.webgoat.html` locally. These files contain findings and code fixes;
they are ignored by Git by default. No live accuracy score is claimed until this runs.
