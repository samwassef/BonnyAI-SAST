"""Same-origin browser API with request-scoped credentials and results."""

from pathlib import Path
import re
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.chat import ChatRequest, HFChat, MODEL
from app.analysis import AnalysisRequest
from app.fetcher import HTTPFetcher
from app.operation import Operation, checkpoint
from app.repository import RepositoryFetcher, RepositoryRequest, render_report
from app.review import review_text


def create_app(chat: HFChat | None = None, port: int = 8000,
               fetcher: HTTPFetcher | None = None,
               repository_fetcher: RepositoryFetcher | None = None,
               domain: str | None = None, client_factory=HFChat) -> FastAPI:
    if domain and chat is not None:
        raise ValueError("Public deployments require visitor credentials")
    if domain and (len(domain) > 253 or not re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", domain)):
        raise ValueError("APP_DOMAIN must be a DNS hostname without a scheme, port or path")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    static = Path(__file__).parent / "static"
    lock = Lock()
    collector = fetcher or HTTPFetcher()
    repositories = repository_fetcher or RepositoryFetcher()
    authorities = {domain} if domain else {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"https://{domain}"} if domain else {f"http://{host}" for host in authorities}

    @app.middleware("http")
    async def browser_boundary(request: Request, call_next):
        if request.headers.get("host") not in authorities:
            return JSONResponse({"detail": "Invalid host"}, status_code=403)
        if request.method == "POST":
            if (request.headers.get("origin") not in origins
                    or request.headers.get("x-chat-request") != "1"):
                return JSONResponse({"detail": "Same-origin browser request required"}, status_code=403)
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse({"detail": "JSON required"}, status_code=415)
            size, chunks = 0, []
            async for chunk in request.stream():
                size += len(chunk)
                if size > 300000:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        return JSONResponse({"detail": "Invalid input. Check required fields and input limits."}, status_code=422)

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    @app.get("/api/config")
    def config():
        return {"token_required": chat is None}

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    async def dispatch(request, make_work):
        token = request.headers.get("x-hf-token", "").strip()
        if token and not re.fullmatch(r"hf_[A-Za-z0-9]{8,200}", token):
            return JSONResponse({"detail": "Enter a valid Hugging Face token."}, status_code=401)
        if not token and chat is None:
            return JSONResponse({"detail": "Enter your Hugging Face token to continue."}, status_code=401)
        if not lock.acquire(blocking=False):
            return JSONResponse({"detail": "Server busy. Another operation is running; please try again shortly."}, status_code=429)
        try:
            client = client_factory(token) if token else chat
            operation = Operation(make_work(client), lock)
            operation.thread.start()
        except Exception:
            lock.release()
            return JSONResponse({"detail": "Unable to start operation."}, status_code=502)
        if "application/x-ndjson" in request.headers.get("accept", ""):
            return operation.response()
        async for event in operation.events_async():
            if event["type"] == "complete":
                return JSONResponse(event["data"])
            if event["type"] == "error":
                return JSONResponse({"detail": event["data"]["detail"]}, status_code=event["data"]["status"])
        return JSONResponse({"detail": "Operation interrupted."}, status_code=502)

    @app.post("/api/chat")
    async def send_message(body: ChatRequest, request: Request):
        return await dispatch(request, lambda client: lambda emit: client.reply(body).model_dump())

    @app.post("/api/analyze")
    async def analyze_url(body: AnalysisRequest, request: Request):
        def work(client):
            def run(emit):
                emit("progress", {"message": "Fetching webpage..."})
                evidence = collector.fetch(body.url)
                checkpoint()
                emit("progress", {"message": "Analyzing HTTP headers and HTML..."})
                answer = client.analyze(body.question, evidence)
                return {**answer.model_dump(), "final_url": evidence.final_url,
                            "status": evidence.responses[-1]["status"], "responses": len(evidence.responses),
                            "body_bytes": sum(r["body_bytes"] for r in evidence.responses),
                            "evidence_partial": any(r.get("html_truncated") for r in evidence.responses),
                            "scripts": evidence.scripts, "scripts_skipped": evidence.scripts_skipped,
                            "script_discovery_partial": evidence.script_discovery_partial}
            return run
        return await dispatch(request, work)

    @app.post("/api/review-repository")
    async def review_repository(body: RepositoryRequest, request: Request):
        def work(client):
            def run(emit):
                emit("progress", {"phase": "collecting", "message": "Resolving repository and commit..."})
                evidence = repositories.fetch(body.url, body.ref, progress=lambda value: emit("progress", value))

                def result(review, answer, finish):
                    return {"answer": answer, "finish_reason": finish, "review": review,
                            "repository": evidence.url, "commit": evidence.commit,
                            "reviewed_files": len(review['reviewed_paths']) if review else len(evidence.files),
                            "skipped_files": len(review['skipped']) if review else len(evidence.skipped),
                            "report_html": render_report(evidence, answer, finish, MODEL, review)}

                def progress(value):
                    checkpoint()
                    state = dict(value)
                    snapshot = state.pop("review", None)
                    emit("progress", state)
                    if snapshot is not None:
                        emit("snapshot", result(snapshot, review_text(snapshot), "incomplete"))

                checkpoint()
                answer = client.review_repository(evidence, progress=progress)
                return result(answer.review, answer.answer, answer.finish_reason)
            return run
        return await dispatch(request, work)

    app.mount("/static", StaticFiles(directory=static), name="static")
    return app
