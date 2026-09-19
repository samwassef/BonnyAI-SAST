"""Intentionally vulnerable localhost training app. All data is synthetic.

Run: python test-cases/vulnerable-webapp/app.py
The second port serves attacker demonstrations from a different browser origin.
"""

import argparse
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html import escape
from pathlib import Path
import secrets
import sqlite3
from threading import RLock, Thread
from time import sleep
from urllib.parse import parse_qs, urlsplit


# VULN-05: These fixed credentials actually authenticate the lab administrator.
# They are fake lab values; never reuse them for a real account.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "LabOnly123!"
STATIC = Path(__file__).parent / "static"


class LabState:
    def __init__(self):
        self.lock = RLock()
        self.sessions = set()
        self.email = "admin@example.test"
        self.subscribed = False
        self.database = sqlite3.connect(":memory:", check_same_thread=False)
        self.database.executescript("""
            CREATE TABLE products (
                id INTEGER PRIMARY KEY, name TEXT, category TEXT,
                price INTEGER, hidden INTEGER
            );
            INSERT INTO products VALUES
                (1, 'Sample notebook', 'office', 8, 0),
                (2, 'Sample pen', 'office', 2, 0),
                (3, 'Sample mug', 'kitchen', 5, 0),
                (4, 'Unreleased demo product', 'internal', 99, 1);
        """)


def page(title, content):
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} | Vulnerable lab</title>
<style>body{{font:17px system-ui;max-width:850px;margin:40px auto;padding:0 20px}}
input,button{{font:inherit;padding:10px;margin:5px 0}} input{{max-width:100%}}
code,pre{{background:#f1f3f5;padding:4px;overflow:auto}} .notice{{color:#9b2500}}
td,th{{padding:10px;text-align:left}} nav{{margin-bottom:24px}}</style></head>
<body><nav><a href="/">Lab home</a> | <a href="/account">Account</a></nav>
<p class="notice">Deliberately vulnerable local lab. Synthetic data only.</p>
<h1>{escape(title)}</h1>{content}</body></html>"""


def make_handler(state, target_origin, attacker_origin, *, attacker=False):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def respond(self, html, status=200, headers=None):
            data = html.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            # VULN-03: No X-Frame-Options or CSP frame-ancestors protection.
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def respond_script(self, filename):
            data = (STATIC / "vendor" / filename).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def redirect(self, location, headers=None):
            self.respond("", 303, {"Location": location, **(headers or {})})

        def logged_in(self):
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except CookieError:
                return False
            session = cookie.get("lab_session")
            with state.lock:
                return session is not None and session.value in state.sessions

        def form(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 16384:
                    raise ValueError
                return parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
            except (ValueError, UnicodeError):
                return None

        def do_GET(self):
            url = urlsplit(self.path)
            query = parse_qs(url.query, keep_blank_values=True)
            if attacker:
                files = {"/": "attacker.html", "/csrf": "csrf.html", "/clickjacking": "clickjacking.html"}
                filename = files.get(url.path)
                if not filename:
                    self.respond(page("Not found", "Unknown demonstration."), 404)
                    return
                html = (STATIC / filename).read_text(encoding="utf-8")
                self.respond(html.replace("{{TARGET_ORIGIN}}", target_origin))
                return
            if url.path == "/":
                # VULN-06: Sensitive comments in this HTML reach the browser unchanged.
                html = (STATIC / "index.html").read_text(encoding="utf-8")
                self.respond(html.replace("{{ATTACKER_ORIGIN}}", attacker_origin))
            elif url.path == "/vendor/jquery-3.4.1.min.js":
                self.respond_script("jquery-3.4.1.min.js")
            elif url.path == "/jquery":
                self.respond((STATIC / "jquery.html").read_text(encoding="utf-8"))
            elif url.path == "/search":
                term = query.get("q", [""])[0]
                # VULN-01: Untrusted query text enters HTML without escaping.
                self.respond(page("Search", '<form><input name="q" placeholder="Search term">'
                                  '<button>Search</button></form><p>You searched for: ' + term + '</p>'))
            elif url.path == "/products":
                category = query.get("category", ["office"])[0]
                # VULN-04: Attacker input is concatenated into a real SQLite query.
                sql = "SELECT id, name, price FROM products WHERE category = '" + category + "' AND hidden = 0"
                try:
                    with state.lock:
                        rows = state.database.execute(sql).fetchall()
                except sqlite3.Error:
                    self.respond(page("Query failed", "Invalid SQL query. Try another category."), 400)
                    return
                table = ''.join('<tr>' + ''.join(f'<td>{escape(str(value))}</td>' for value in row) + '</tr>' for row in rows)
                self.respond(page("Products", '<form><input name="category" value="office">'
                                  '<button>Filter</button></form><table><tr><th>ID</th><th>Name</th>'
                                  '<th>Price</th></tr>' + table + '</table>'))
            elif url.path == "/login":
                self.respond(page("Login", '<form method="post" action="/login">'
                                  '<p><label>Username <input name="username" required></label></p>'
                                  '<p><label>Password <input name="password" type="password" required></label></p>'
                                  '<button>Log in</button></form>'))
            elif url.path == "/account":
                if not self.logged_in():
                    self.redirect("/login")
                    return
                if query.get("frame") == ["1"]:
                    # Same authenticated action, presented in a predictable frame for the PoC.
                    self.respond('''<!doctype html><html><head><title>Account action</title></head>
<body style="margin:0"><form method="post" action="/profile/subscribe">
<button style="width:320px;height:100px;font:20px system-ui">Enable newsletter</button>
</form></body></html>''')
                    return
                with state.lock:
                    email, subscribed = state.email, state.subscribed
                self.respond(page("Account", f'<p>Signed in as {escape(ADMIN_USERNAME)}</p>'
                    f'<p id="email">Email: {escape(email)}</p>'
                    f'<p id="subscription">Newsletter: {"enabled" if subscribed else "disabled"}</p>'
                    '<form method="post" action="/profile/email"><label>New email '
                    '<input name="email" type="email" value="admin@example.test" required></label>'
                    '<button>Save email</button></form>'
                    '<form method="post" action="/profile/subscribe"><button>Enable newsletter</button></form>'
                    '<form method="post" action="/profile/reset"><button>Reset demo account</button></form>'))
            else:
                self.respond(page("Not found", "Unknown route."), 404)

        def do_POST(self):
            if attacker:
                self.respond(page("Not found", "Unknown route."), 404)
                return
            path = urlsplit(self.path).path
            data = self.form()
            if data is None:
                self.respond(page("Bad input", "Invalid or oversized form."), 400)
                return
            if path == "/login":
                if data.get("username") == [ADMIN_USERNAME] and data.get("password") == [ADMIN_PASSWORD]:
                    session = secrets.token_urlsafe(24)
                    with state.lock:
                        state.sessions.add(session)
                    self.redirect("/account", {"Set-Cookie": f"lab_session={session}; HttpOnly; SameSite=Lax; Path=/"})
                else:
                    self.respond(page("Login failed", "Invalid credentials."), 401)
                return
            if path not in {"/profile/email", "/profile/subscribe", "/profile/reset"}:
                self.respond(page("Not found", "Unknown route."), 404)
                return
            if not self.logged_in():
                self.respond(page("Login required", '<a href="/login">Log in first.</a>'), 401)
                return
            # VULN-02: Cookie-authenticated state changes have no CSRF token or
            # Origin/Referer validation. The other local port is a different origin.
            with state.lock:
                if path == "/profile/email":
                    email = data.get("email", [""])[0]
                    if not email or len(email) > 200:
                        self.respond(page("Bad input", "Supply an email up to 200 characters."), 400)
                        return
                    state.email = email
                elif path == "/profile/subscribe":
                    state.subscribed = True
                else:
                    state.email, state.subscribed = "admin@example.test", False
            self.redirect("/account")

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--attacker-port", type=int, default=8002)
    args = parser.parse_args()
    if not all(1 <= port <= 65535 for port in (args.port, args.attacker_port)) or args.port == args.attacker_port:
        parser.error("Choose two different ports between 1 and 65535")
    target = f"http://127.0.0.1:{args.port}"
    attacker = f"http://127.0.0.1:{args.attacker_port}"
    state = LabState()
    servers = []
    running = []
    try:
        servers.append(ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(state, target, attacker)))
        servers.append(ThreadingHTTPServer(("127.0.0.1", args.attacker_port), make_handler(state, target, attacker, attacker=True)))
        for server in servers:
            Thread(target=server.serve_forever, daemon=True).start()
            running.append(server)
        print(f"Deliberately vulnerable lab: {target}", flush=True)
        print(f"Attacker demonstrations:    {attacker}", flush=True)
        print(f"Synthetic login: {ADMIN_USERNAME} / {ADMIN_PASSWORD}", flush=True)
        print("Localhost only. Ctrl+C stops both servers; all data is discarded.", flush=True)
        # Stay interruptible without using a blocking join on Windows.
        while True:
            sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for server in running:
            server.shutdown()
        for server in servers:
            server.server_close()
        state.database.close()


if __name__ == "__main__":
    main()
