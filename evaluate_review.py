"""Opt-in live detection evaluation with synthetic fixtures and a pinned WebGoat scan.

Uses provider credits. Source is reviewed as text, never executed. No token is saved.
"""
import argparse
import getpass
import json
import os
from pathlib import Path

from app.chat import HFChat
from app.repository import RepositoryEvidence, RepositoryFetcher, render_report
from app.chat import MODEL


CASES = [
    ('sqli_vulnerable', 'SQLi', '''from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.get('/users')
def users():
    db = sqlite3.connect('synthetic.db')
    return {'rows': db.execute("SELECT name FROM users WHERE name = '" + request.args['name'] + "'").fetchall()}
'''),
    ('sqli_secure', None, '''from flask import Flask, request
import sqlite3
app = Flask(__name__)
@app.get('/users')
def users():
    db = sqlite3.connect('synthetic.db')
    return {'rows': db.execute('SELECT name FROM users WHERE name = ?', (request.args['name'],)).fetchall()}
'''),
    ('xss_vulnerable', 'XSS', '''from flask import Flask, request, Response
app = Flask(__name__)
@app.get('/greet')
def greet():
    return Response('<h1>Hello ' + request.args['name'] + '</h1>', mimetype='text/html')
'''),
    ('xss_secure', None, '''from flask import Flask, request, Response
from html import escape
app = Flask(__name__)
@app.get('/greet')
def greet():
    return Response('<h1>Hello ' + escape(request.args['name']) + '</h1>', mimetype='text/html')
'''),
    ('access_vulnerable', 'Access control', '''from flask import Flask, request, abort
import os
app = Flask(__name__)
# Synthetic private documents. Authentication tokens are provisioned outside this code.
TOKENS = {os.environ['ALICE_TOKEN']: 'alice', os.environ['BOB_TOKEN']: 'bob'}
DOCS = {'1': {'owner': 'alice', 'body': 'Private synthetic Alice document'}}
@app.get('/documents/<doc_id>')
def document(doc_id):
    user = TOKENS.get(request.headers.get('Authorization', ''))
    if not user: abort(401)
    doc = DOCS.get(doc_id)
    if not doc: abort(404)
    return doc
'''),
    ('access_secure', None, '''from flask import Flask, request, abort
import os
app = Flask(__name__)
TOKENS = {os.environ['ALICE_TOKEN']: 'alice', os.environ['BOB_TOKEN']: 'bob'}
DOCS = {'1': {'owner': 'alice', 'body': 'Private synthetic Alice document'}}
@app.get('/documents/<doc_id>')
def document(doc_id):
    user = TOKENS.get(request.headers.get('Authorization', ''))
    if not user: abort(401)
    doc = DOCS.get(doc_id)
    if not doc or doc['owner'] != user: abort(404)
    return doc
'''),
    ('credentials_vulnerable', 'Credentials', '''from flask import Flask, request, abort
from hmac import compare_digest
app = Flask(__name__)
# Intentional educational default password for this synthetic evaluation only.
ADMIN_PASSWORD = 'synthetic-training-password'
@app.get('/admin')
def admin():
    auth = request.authorization
    if not auth or auth.username != 'admin' or not compare_digest(auth.password, ADMIN_PASSWORD): abort(401)
    return {'private': 'synthetic admin data'}
'''),
    ('credentials_secure', None, '''from flask import Flask, request, abort
from hmac import compare_digest
import os
app = Flask(__name__)
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']
if len(ADMIN_PASSWORD) < 32: raise RuntimeError('Strong password required')
@app.get('/admin')
def admin():
    auth = request.authorization
    if not auth or auth.username != 'admin' or not compare_digest(auth.password, ADMIN_PASSWORD): abort(401)
    return {'private': 'synthetic admin data'}
'''),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prompt-token', action='store_true')
    parser.add_argument('--webgoat', action='store_true', help='Also scan WebGoat at the commit from the supplied report.')
    parser.add_argument('--provider', default='novita')
    parser.add_argument('--output', default='review-evaluation.json')
    args = parser.parse_args()
    token = getpass.getpass('Hugging Face token (hidden): ') if args.prompt_token else os.environ.get('HF_TOKEN', '')
    if not token.strip():
        parser.error('Set HF_TOKEN or use --prompt-token in an interactive terminal.')
    chat = HFChat(token.strip(), args.provider)
    scores = []
    for name, expected, source in CASES:
        evidence = RepositoryEvidence('synthetic-evaluation', 'local-fixture',
                                      [{'path': name + '.py', 'content': source}], [])
        result = chat.review_repository(evidence, progress=lambda event: print(name + ': ' + event['message'])).review
        actual = sorted({f['category'] for f in result['findings'] if f['status'] == 'confirmed'})
        # Negative controls target the paired vulnerability category, not unrelated observations.
        target = {'sqli': 'SQLi', 'xss': 'XSS', 'access': 'Access control', 'credentials': 'Credentials'}[name.split('_')[0]]
        passed = not result['failed_batches'] and len(result['reviewed_paths']) == 1 and (
            expected in actual if expected else target not in actual)
        scores.append({'case': name, 'target': target, 'expected_vulnerable': expected is not None,
                       'confirmed_categories': actual, 'passed': passed, 'review': result})
    if args.webgoat:
        evidence = RepositoryFetcher().fetch('https://github.com/samwassef/WebGoat',
                                              '685a4b9df91fb456fc74628343d01615cd29a66a')
        reply = chat.review_repository(evidence, progress=lambda event: print(event['message']))
        report_path = Path(args.output).with_suffix('.webgoat.html')
        report_path.write_text(render_report(evidence, reply.answer, reply.finish_reason, MODEL, reply.review), encoding='utf-8')
        scores.append({'case': 'webgoat', 'commit': evidence.commit, 'review': reply.review,
                       'note': 'Inspect evidence and coverage manually; fixture scores do not prove WebGoat coverage.'})
    Path(args.output).write_text(json.dumps(scores, indent=2), encoding='utf-8')
    failed = sum(not score['passed'] for score in scores if 'passed' in score)
    print(f'{len(CASES) - failed}/{len(CASES)} synthetic detection checks passed. Results: {args.output}')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
