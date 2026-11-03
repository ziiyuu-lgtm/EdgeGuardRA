"""The local model adapter supports unencoded JSON response content only."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import gzip
import json
import unittest

from edgeguardra.agents import LocalOllama


def response_body():
    candidate = {'action': 'inspect', 'target': 'pump-01', 'reason': 'fixture'}
    return json.dumps({'done': True, 'done_reason': 'stop', 'message': {
        'role': 'assistant', 'content': json.dumps(candidate)}}).encode()


class ModelContentEncodingTests(unittest.TestCase):
    def setUp(self):
        self.encoding = []
        self.compressed = False
        self.chunked = False
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                body = response_body()
                if owner.compressed:
                    body = gzip.compress(body)
                self.send_response(200)
                for encoding in owner.encoding:
                    self.send_header('Content-Encoding', encoding)
                if owner.chunked:
                    self.send_header('Transfer-Encoding', 'chunked')
                    body = f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n'
                else:
                    self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def log_message(self, *_):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.client = LocalOllama(f'http://127.0.0.1:{self.server.server_port}/api/chat', 'fixture', timeout=2)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_absent_and_single_identity_encoding_are_accepted(self):
        for headers in ([], ['identity'], [' IDENTITY\t']):
            with self.subTest(headers=headers):
                self.encoding = headers
                self.assertEqual(self.client.propose('fixture')['action'], 'inspect')

    def test_mislabelled_plaintext_with_unsupported_encoding_is_rejected(self):
        for encoding in ('gzip', 'br', 'deflate', '', 'identity, gzip', 'identity, identity'):
            with self.subTest(encoding=encoding), self.assertRaisesRegex(ValueError, 'content encoding'):
                self.encoding = [encoding]
                self.client.propose('fixture')

    def test_duplicate_content_encoding_headers_are_rejected(self):
        for headers in (['identity', 'identity'], ['identity', 'gzip']):
            with self.subTest(headers=headers), self.assertRaisesRegex(ValueError, 'content encoding'):
                self.encoding = headers
                self.client.propose('fixture')

    def test_real_gzip_body_is_rejected_without_decompression(self):
        self.encoding, self.compressed = ['gzip'], True
        with self.assertRaisesRegex(ValueError, 'content encoding'):
            self.client.propose('fixture')

    def test_chunked_identity_is_accepted_but_chunked_gzip_is_rejected(self):
        self.chunked, self.encoding = True, ['identity']
        self.assertEqual(self.client.propose('fixture')['action'], 'inspect')
        self.encoding = ['gzip']
        with self.assertRaisesRegex(ValueError, 'content encoding'):
            self.client.propose('fixture')


if __name__ == '__main__':
    unittest.main()
