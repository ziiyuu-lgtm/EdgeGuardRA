"""Only completed assistant responses should become model candidates."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest

from edgeguardra.agents import LocalOllama


class ResponseHandler(BaseHTTPRequestHandler):
    response = {}
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        body = json.dumps(type(self).response).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass


class ModelResponseCompletionTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), ResponseHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.adapter = LocalOllama(f'http://127.0.0.1:{self.server.server_port}/api/chat', 'fixture', timeout=2)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def response(self):
        return {'done': True, 'done_reason': 'stop', 'message': {'role': 'assistant',
                'content': json.dumps({'action': 'inspect', 'target': 'pump-01', 'reason': 'fixture'})}}

    def test_response_explicitly_marked_incomplete_is_rejected(self):
        for value in (False, None, 'true', 1):
            ResponseHandler.response = self.response(); ResponseHandler.response['done'] = value
            with self.subTest(done=value), self.assertRaises(ValueError):
                self.adapter.propose('synthetic')

    def test_missing_completion_flag_is_rejected(self):
        ResponseHandler.response = self.response(); del ResponseHandler.response['done']
        with self.assertRaises(ValueError):
            self.adapter.propose('synthetic')

    def test_non_assistant_or_missing_role_is_rejected(self):
        for role in ('user', 'system', None):
            ResponseHandler.response = self.response(); ResponseHandler.response['message']['role'] = role
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.adapter.propose('synthetic')
        ResponseHandler.response = self.response(); del ResponseHandler.response['message']['role']
        with self.assertRaises(ValueError):
            self.adapter.propose('synthetic')

    def test_non_stop_or_invalid_finish_reason_is_rejected(self):
        for reason in ('length', 'load', 'unknown', None, 5):
            ResponseHandler.response = self.response(); ResponseHandler.response['done_reason'] = reason
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                self.adapter.propose('synthetic')

    def test_complete_assistant_response_with_or_without_optional_reason(self):
        ResponseHandler.response = self.response()
        self.assertEqual(self.adapter.propose('synthetic')['action'], 'inspect')
        del ResponseHandler.response['done_reason']
        self.assertEqual(self.adapter.propose('synthetic')['target'], 'pump-01')


if __name__ == '__main__':
    unittest.main()
