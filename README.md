# GLM-5.3 local chat

Text chat through Hugging Face Inference Providers, with a local FastAPI webpage.
Step 1 connectivity was confirmed by the user's successful Novita response. Step 2
adds the chat interface and bounded conversation history. Step 3 adds HTTP GET
collection and analysis of response headers and HTML.

## Analyze a webpage (Step 3)

Restart the server after updating dependencies with the commands below. In the
**Analyze a webpage** form, enter an HTTP(S) URL and your question, then click
**Fetch and analyze**. Python collects the response and sends it to GLM-5.3 through
Hugging Face. The result shows the final URL, HTTP status, number of responses,
body byte count, and model analysis. This analysis is separate from chat history;
submitting again fetches again. No evidence is saved to disk.

**Headers and HTML are sent without redaction, extraction, or summarization**, as
requested. This includes cookie values and any credentials or sensitive content
returned by the website. The app does not forward its Hugging Face token, browser
cookies, or user-supplied request headers to the target. The token is used only by
the inference client. The user question and untrusted evidence are separate
messages; the model receives no tools and cannot initiate additional requests.

Repeated response headers (including Set-Cookie) are preserved as ordered name/value
pairs. Each redirect response and its body are included. HTML whitespace, inline
scripts, and comments are retained. The payload uses JSON encoding, which preserves
these values after decoding. This is not a raw wire capture: the HTTP library parses
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
This is a local single-user tool, not a persistent organizational target registry.

Limits: five redirects, 100000 bytes across response bodies and header names/values,
and 140000 characters of serialized evidence. Exceeding a limit fails before the
LLM call; there is no silent truncation or chunking. DNS queries have a three-second
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

This is a single-user local application, bound to `127.0.0.1`. Host and Origin
checks protect the local endpoint from unrelated websites; it is not a public,
authenticated deployment. The server accepts one inference request at a time,
disables access logging, sanitizes provider failures, and never executes model text.
Do not expose it using a tunnel or reverse proxy without adding authentication and
deployment-specific controls. Only the Python collector fetches the explicitly
submitted URL; the LLM cannot browse URLs or execute tools.

## Offline tests

```powershell
.venv/Scripts/python.exe -m unittest -v
```

Tests mock inference and cover the original checker, chat history validation,
static assets, source checks, body size limits, provider errors and token redaction.
No real tokens or external inference calls are used by the tests.

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
must be exercised after entering a token when starting the server.

References: [GLM-5.3](https://huggingface.co/zai-org/GLM-5.3),
[Hugging Face chat completion](https://huggingface.co/docs/inference-providers/en/tasks/chat-completion).

## Review a GitHub repository

Use **Review GitHub source code** with a public URL such as
`https://github.com/owner/repository`. Optionally enter a branch, tag, or commit in
the separate field; leaving it blank reviews the default branch. Click **Review
and create HTML report**, then **Download HTML report** to save the generated
standalone report. Restart the server to load this feature.

The collector requests only the commit SHA, lists that commit's files using the
[GitHub trees API](https://docs.github.com/en/rest/git/trees), and downloads selected
source files from raw.githubusercontent.com. It never downloads a repository ZIP,
so large assets do not count toward a whole-repository download limit.
GLM receives only selected UTF-8 source-code files with paths and original contents,
in alphabetical path order. Pipeline, Docker/container, build/deployment, configuration,
and documentation files are excluded before downloading. This includes CI directories
(such as `.github`, `.gitlab`, `.circleci`, and `pipelines`), Dockerfile variants,
container/deployment directories, known build scripts and `*.config.*` files.
JSON, YAML, XML, TOML, Terraform, Gradle, Markdown, and text files are excluded.
Application source, templates, tests, and ordinary shell scripts remain eligible.
Selection uses extensions and known path/name conventions; unusually named automation
scripts with a source-code extension may still be included.
GLM is asked for severity, confidence, file/line evidence, impact and prerequisites,
concrete proposed fixes (preferably diffs), and suggested regression tests.
The report contains the commit, timestamp, model, completion status, full model
answer, reviewed file list, and every skipped file with its reason.

This is a bounded static review: up to 100 files, 30000 bytes per file, 80000 source
bytes overall, and 140000 characters of serialized model input. Files that do not
fit are listed as skipped, without truncating file contents. Dependency/build
folders, recognized lockfiles, minified files, symlinks, binary/non-UTF-8 files, and
unsupported extensions are skipped. File-list metadata over 10 MB, more than 100000 entries, or a truncated
GitHub file list fail explicitly before inference. Up to 100 individual source
downloads are attempted per review. The collection budget is
120 seconds checked between reads/requests, with existing DNS and socket timeouts;
an in-flight operation may exceed the budget. The review uses an 8192-token output
budget and the existing 90-second provider timeout. Partial model answers are
clearly labeled and remain downloadable.

Only public repositories on github.com are supported; no GitHub credentials are
used. GitHub rate limits and unavailable refs produce a visible error. Downloads
use validated public IPs and HTTPS, and redirects are restricted to api.github.com
and raw.githubusercontent.com. No archives are extracted, code executed, dependencies
installed, or fixes applied. Submodules and Git LFS contents are not fetched.
Repository instructions are treated as untrusted input, and GLM has no tools.
Source contents, including any embedded secrets, are sent to Hugging Face and the
configured inference provider. The server does not persist source or reports;
the generated report stays in tab memory until cleared/refreshed, and the download
saves it using your browser. Model output and filenames are HTML-escaped in the
report. Findings and patches require human review; no findings does not prove
that the repository is secure.

Repository tests use mocked file lists, source downloads, and inference responses. They
cover URL and redirect boundaries, size limits, file selection, unsafe repository
paths, commit pinning, prompt construction, escaped HTML reports, API validation,
and recovery after failures. Live repository review with GLM has not been verified.
