"""A service error or unsupported status cannot produce a model candidate."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from threading import Event, Thread
import unittest

from edgeguardra.agents import LocalOllama, authorize_candidate
from edgeguardra.demo import setup
from edgeguardra.sandbox import Sandbox

NOW = 1_700_000_000


def completed_response():
    return {'done': True, 'done_reason': 'stop', 'message': {
        'role': 'assistant', 'content': json.dumps({
            'action': 'inspect', 'target': 'pump-01', 'reason': 'fixture'})}}


class ModelErrorContractTests(unittest.TestCase):
    def setUp(self):
        self.status = 200
        self.doc = completed_response()
        self.framing = 'length'
        self.hold_body = False
        self.release_body = Event()
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.requests.append(request)
                body = json.dumps(owner.doc).encode()
                if owner.framing == 'chunked':
                    body = f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n'
                self.send_response(owner.status)
                self.send_header('Content-Type', 'application/json')
                if owner.framing == 'length':
                    self.send_header('Content-Length', str(len(body)))
                elif owner.framing == 'chunked':
                    self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                if owner.hold_body:
                    owner.release_body.wait(timeout=2)
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.worker = Thread(target=lambda: self.server.serve_forever(poll_interval=.01), daemon=True)
        self.worker.start()
        self.addCleanup(self.close_server)
        self.url = f'http://127.0.0.1:{self.server.server_port}/api/chat'
        self.client = LocalOllama(self.url, 'fixture', timeout=2)

    def close_server(self):
        self.release_body.set()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)

    def test_error_overrides_completed_assistant_content_without_echoing_details(self):
        self.doc['error'] = 'fixture-sensitive-service-details'
        with self.assertRaisesRegex(ValueError, 'service reported an error') as caught:
            self.client.propose('synthetic')
        self.assertNotIn('fixture-sensitive-service-details', str(caught.exception))
        self.assertEqual(len(self.requests), 1)

    def test_empty_and_nonstring_error_fields_are_rejected_by_presence(self):
        for error in ('', None, False, 0, [], {}, True, {'detail': 'fixture'}):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, 'service reported an error'):
                self.doc['error'] = error
                self.client.propose('synthetic')

    def test_only_http_200_can_return_a_completed_candidate(self):
        for status in (201, 202, 203, 206, 207, 208, 226, 301, 307, 400, 429, 500):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'HTTP status rejected'):
                self.status = status
                self.client.propose('synthetic')

    def test_success_metadata_and_reason_text_remain_usable(self):
        self.doc.update(model='fixture', total_duration=1000, eval_count=2)
        self.doc['message']['content'] = json.dumps({
            'action': 'inspect', 'target': 'pump-01', 'reason': 'Investigate a reported error'})
        result = self.client.propose('synthetic')
        self.assertEqual(result['reason'], 'Investigate a reported error')
        self.assertIs(self.requests[0]['stream'], False)
        self.assertEqual(self.requests[0]['format'], 'json')
        del self.doc['done_reason']
        self.assertEqual(self.client.propose('synthetic')['target'], 'pump-01')

    def test_error_is_rejected_with_every_supported_body_framing(self):
        self.doc['error'] = 'fixture failure'
        for framing in ('length', 'chunked', 'close'):
            with self.subTest(framing=framing), self.assertRaisesRegex(ValueError, 'service reported an error'):
                self.framing = framing
                self.client.propose('synthetic')

    def test_unsupported_status_is_rejected_before_waiting_for_body(self):
        self.status, self.hold_body = 202, True
        client = LocalOllama(self.url, 'fixture', timeout=.15)
        try:
            # The body is held until this call ends, so success here depends
            # on status rejection rather than a body timeout or JSON failure.
            with self.assertRaisesRegex(ValueError, 'HTTP status rejected'):
                client.propose('synthetic')
        finally:
            self.release_body.set()

    def test_cli_rejects_service_error_without_candidate_or_sensitive_details(self):
        self.doc['error'] = 'fixture-sensitive-cli-details'
        result = subprocess.run([sys.executable, '-m', 'edgeguardra', 'llm-demo',
            '--url', self.url, '--model', 'fixture', '--telemetry', 'synthetic', '--execute-simulated'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertEqual(result.stdout, '')
        self.assertIn('service reported an error', result.stderr)
        self.assertNotIn('fixture-sensitive-cli-details', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(len(self.requests), 1)

    def test_error_stops_pipeline_and_later_success_requires_normal_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate, keys = setup(Path(tmp) / 'state.db', NOW)
            head = gate.store.audit_head()

            def propose_and_authorize():
                candidate = self.client.propose('synthetic')
                envelope = authorize_candidate(candidate, agent_id='defender', key_id='v1',
                    request_id='model-request', nonce='model-nonce', issued_at=NOW,
                    agent_key=keys['defender'])
                return gate.evaluate(envelope)

            self.doc['error'] = 'fixture failure'
            with self.assertRaisesRegex(ValueError, 'service reported an error'):
                propose_and_authorize()
            self.assertIsNone(gate.store.decision('model-request', agent_id='defender'))
            self.assertEqual(gate.store.audit_head(), head)
            del self.doc['error']
            self.assertEqual(propose_and_authorize().outcome, 'allow')
            broker = Sandbox(gate)
            self.assertTrue(broker.execute('model-request', agent_id='defender')['executed'])
            self.assertFalse(broker.execute('model-request', agent_id='defender')['executed'])


if __name__ == '__main__':
    unittest.main()
