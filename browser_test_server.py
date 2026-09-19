"""Local browser-test fixture: simulated GitHub and model responses; no network calls."""
import json
import sys
import time

import uvicorn

from app.chat import HFChat, ChatReply, ChatError
from app.fetcher import FetchError
from app.main import create_app
from app.repository import RepositoryEvidence, repository_name


class FixtureCollector:
    def fetch(self, url, ref='', progress=None):
        name = repository_name(url)
        if name.endswith('collect-error'):
            raise FetchError('Fixture collection failure.')
        extension = '.js' if 'javascript' in name else '.java' if 'java' in name else '.py'
        files = [{'path': f'src/routes/Endpoint{index}{extension}',
                  'content': 'fixture_source()\n' + '# padding\n' * 2990} for index in range(4)]
        if progress:
            progress({'phase': 'collecting', 'message': 'Collecting fixture source...',
                      'discovered_files': 4, 'collected_files': 2, 'reviewed_files': 0, 'skipped_files': 0})
        time.sleep(0.1)
        return RepositoryEvidence('https://github.com/' + name, 'b' * 40, files, [])


class FixtureChat(HFChat):
    def _complete(self, messages, max_tokens=2048):
        payload = json.loads(messages[-1]['content'])
        time.sleep(1.7)  # Let the browser exercise real progress polling.
        name = payload['repository']
        path = payload['primary_paths'][0]
        if 'provider-error' in name:
            raise ChatError('Fixture provider failure.')
        if 'partial-java' in name and 'Endpoint2' in path:
            return ChatReply(answer='{"findings": [', finish_reason='length')
        findings = []
        if 'empty-javascript' not in name:
            findings.append(dict(
                title='<img src=x onerror="window.pwned=1"> Synthetic SQL injection',
                category='SQLi', severity='High', confidence='High', status='confirmed', intentional=False,
                description='Synthetic finding to test browser rendering.', root_cause='Synthetic unsafe query.',
                evidence=[dict(path=path, start_line=1, end_line=1)], source_to_sink='Input reaches query.',
                impact='Synthetic impact.', prerequisites='Local fixture only.',
                exploitation_steps=['Create a synthetic record.', 'Run the proposed local check.'],
                code_fix='<script>window.pwned=1</script>\nUse bound parameters.',
                regression_test='Assert parameters are bound.', missing_evidence=''))
        return ChatReply(answer=json.dumps({'findings': findings, 'limitations': []}), finish_reason='stop')


if __name__ == '__main__':
    port = int(sys.argv[1])
    uvicorn.run(create_app(FixtureChat('fake-token'), port=port, repository_fetcher=FixtureCollector()),
                host='127.0.0.1', port=port, access_log=False, log_level='error')
