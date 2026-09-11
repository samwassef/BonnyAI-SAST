"""Serve a loopback-only chat UI with same-origin request checks."""

# Imports used by the request models, services, and helpers below.
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.chat import ChatError, ChatReply, ChatRequest, HFChat
from app.analysis import AnalysisRequest
from app.fetcher import HTTPFetcher, FetchError
from app.repository import RepositoryFetcher, RepositoryRequest, render_report
from app.chat import MODEL


# Build the web app, shared services, and local-browser access rules.
def create_app(chat: HFChat, port: int = 8000, fetcher: HTTPFetcher | None = None,
               repository_fetcher: RepositoryFetcher | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    static = Path(__file__).parent / "static"
    # Share a single lock across chat, webpage analysis, and repository review.
    lock = Lock()
    collector = fetcher or HTTPFetcher()
    repositories = repository_fetcher or RepositoryFetcher()
    authorities = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"http://{host}" for host in authorities}

    # Validate incoming browser requests and apply security headers to responses.
    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.headers.get("host") not in authorities:
            return JSONResponse({"detail": "Invalid host"}, status_code=403)
        if request.method == "POST":
            if (request.headers.get("origin") not in origins
                    or request.headers.get("x-chat-request") != "1"):
                return JSONResponse({"detail": "Same-origin browser request required"}, status_code=403)
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse({"detail": "JSON required"}, status_code=415)
            # Enforce the request-body limit while reading, before JSON validation.
            size = 0
            chunks = []
            async for chunk in request.stream():
                size += len(chunk)
                if size > 300000:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        # Run the matched route, then restrict browser loading and response caching.
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    # Translate validation failures into useful messages without echoing submitted data.
    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        # Do not echo user text or raw validation input into errors.
        if request.url.path == "/api/review-repository":
            return JSONResponse({"detail": "Provide a GitHub repository URL (up to 2048 characters) and optional ref (up to 200 characters)."}, status_code=422)
        if request.url.path == "/api/analyze":
            return JSONResponse({"detail": "Provide a URL (up to 8192 characters) and a question "
                                 "(up to 4000 characters)."}, status_code=422)
        return JSONResponse({"detail": "Invalid conversation. Use nonempty messages, at most "
                             "10 previous exchanges, 20000 characters per message and 40000 total."},
                            status_code=422)

    # Serve the HTML page that contains chat, webpage analysis, and repository review.
    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    # Allow one inference request at a time and release the lock even on failure.
    @app.post("/api/chat", response_model=ChatReply)
    def send_message(body: ChatRequest):
        if not lock.acquire(blocking=False):
            return JSONResponse({"detail": "An answer is already being generated. Please wait."},
                                status_code=429)
        try:
            return chat.reply(body)
        except ChatError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=502)
        finally:
            lock.release()

    # Collect webpage evidence, ask GLM to analyze it, and return collection details.
    @app.post("/api/analyze")
    def analyze_url(body: AnalysisRequest):
        if not lock.acquire(blocking=False):
            return JSONResponse({"detail": "Another request is running. Please wait."}, status_code=429)
        try:
            evidence = collector.fetch(body.url)
            answer = chat.analyze(body.question, evidence)
            return {**answer.model_dump(), "final_url": evidence.final_url,
                    "status": evidence.responses[-1]["status"],
                    "responses": len(evidence.responses),
                    "body_bytes": sum(r["body_bytes"] for r in evidence.responses)}
        except FetchError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        except ChatError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=502)
        finally:
            lock.release()

    # Collect source, request findings and fixes, and return a downloadable HTML report.
    @app.post("/api/review-repository")
    def review_repository(body: RepositoryRequest):
        if not lock.acquire(blocking=False):
            return JSONResponse({"detail": "Another request is running. Please wait."}, status_code=429)
        try:
            evidence = repositories.fetch(body.url, body.ref)
            answer = chat.review_repository(evidence)
            return {**answer.model_dump(), "repository": evidence.url, "commit": evidence.commit,
                    "reviewed_files": len(evidence.files), "skipped_files": len(evidence.skipped),
                    "report_html": render_report(evidence, answer.answer, answer.finish_reason, MODEL)}
        except FetchError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        except ChatError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=502)
        finally:
            lock.release()

    # Expose the CSS and JavaScript used by the local HTML page.
    app.mount("/static", StaticFiles(directory=static), name="static")
    return app
