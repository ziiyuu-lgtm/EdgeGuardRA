import json
from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from edgeguardra.agents import LocalOllama, ScriptedAgent, authorize_candidate, validate_candidate
from edgeguardra.demo import setup
from edgeguardra.sandbox import Sandbox


class Handler(BaseHTTPRequestHandler):
    last_request = None
    def do_POST(self):
        Handler.last_request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        payload={'message':{'role':'assistant','content':json.dumps({'action':'inspect','target':'pump-01','reason':'observe'})},'done':True}
        body=json.dumps(payload).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def log_message(self,*args): pass


def model_body():
    return json.dumps({'done':True,'message':{'role':'assistant','content':json.dumps({'action':'inspect','target':'pump-01','reason':'observe'})}}).encode()


class SlowBodyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        body=model_body()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
        for b in body:
            try: self.wfile.write(bytes([b]));self.wfile.flush()
            except OSError: break
            time.sleep(.015)
    def log_message(self,*args): pass


class SlowHeadersHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        body=model_body()
        header=f'HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n'.encode()
        for b in header:
            try: self.connection.sendall(bytes([b]))
            except OSError: return
            time.sleep(.015)
        try:self.connection.sendall(body)
        except OSError:pass
    def log_message(self,*args): pass


class TruncatedHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        body=model_body()
        self.send_response(200);self.send_header('Content-Length',str(len(body)+10));self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args):pass


class ChunkedHandler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        body=model_body()
        self.send_response(200);self.send_header('Transfer-Encoding','chunked');self.end_headers()
        for chunk in (body[:13],body[13:]):
            self.wfile.write(f'{len(chunk):x}\r\n'.encode()+chunk+b'\r\n')
        self.wfile.write(b'0\r\n\r\n');self.wfile.flush()
    def log_message(self,*args):pass


class MixedHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        slow=data['messages'][1]['content']=='slow'
        body=model_body()
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
        if not slow:self.wfile.write(body);return
        for b in body:
            try:self.wfile.write(bytes([b]));self.wfile.flush()
            except OSError:break
            time.sleep(.015)
    def log_message(self,*args):pass


class RedirectHandler(BaseHTTPRequestHandler):
    hits=0
    def do_POST(self):
        type(self).hits+=1
        self.send_response(302);self.send_header('Location','http://127.0.0.1:9/api/chat');self.end_headers()
    def log_message(self,*args):pass


def framing_handler(mode):
    class FramingHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            body=model_body()
            self.send_response(200)
            if mode=='duplicate_conflicting':
                self.send_header('Content-Length',str(len(body)))
                self.send_header('Content-Length',str(len(body)+10))
            elif mode=='duplicate_identical':
                self.send_header('Content-Length',str(len(body)))
                self.send_header('Content-Length',str(len(body)))
            elif mode=='negative':self.send_header('Content-Length','-1')
            elif mode=='signed':self.send_header('Content-Length','+'+str(len(body)))
            elif mode=='nondigit':self.send_header('Content-Length','invalid')
            elif mode=='transfer_conflict':
                self.send_header('Transfer-Encoding','chunked')
                self.send_header('Content-Length',str(len(body)))
                body=f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n'
            elif mode=='unknown_transfer':self.send_header('Transfer-Encoding','gzip')
            self.end_headers()
            try:self.wfile.write(body)
            except OSError:pass
        def log_message(self,*args):pass
    return FramingHandler


class AgentTests(unittest.TestCase):
    def serve(self,handler):
        server=ThreadingHTTPServer(('127.0.0.1',0),handler)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.02},daemon=True)
        thread.start()
        def cleanup():server.shutdown();server.server_close();thread.join(timeout=3)
        self.addCleanup(cleanup)
        return f'http://127.0.0.1:{server.server_port}/api/chat'

    def test_scripted_agent_is_only_a_test_double(self):
        c={'action':'inspect','target':'pump-01','reason':'observe'}
        self.assertEqual(ScriptedAgent(c).propose('sample telemetry'),c)

    def test_extra_or_invalid_candidate_field_rejected(self):
        with self.assertRaises(ValueError): validate_candidate({'action':'inspect','target':'pump-01','reason':'x','agent_id':'admin'})
        with self.assertRaises(ValueError): validate_candidate({'action':'destroy','target':'pump-01','reason':'x'})

    def test_signing_wrapper_assigns_identity_not_the_model(self):
        c={'action':'inspect','target':'pump-01','reason':'observe'}
        e=authorize_candidate(c,agent_id='defender',key_id='v1',request_id='r',nonce='n',issued_at=1700000000,agent_key=b'A'*32)
        self.assertEqual(e['payload']['agent_id'],'defender')
        self.assertEqual(len(e['signature']),64)

    def test_non_loopback_or_credentials_are_rejected(self):
        for url in ['http://example.com:11434/api/chat','http://192.0.2.1:80/api/chat',
                    'http://user:pass@127.0.0.1:80/api/chat','http://127.0.0.1:80/api/chat?other=1']:
            with self.subTest(url=url), self.assertRaises(ValueError): LocalOllama(url,'model')

    def test_invalid_resource_limit_types_are_rejected_at_construction(self):
        url='http://127.0.0.1:1234/api/chat'
        for kwargs in ({'timeout':True},{'timeout':float('nan')},{'timeout':0},
                       {'max_response_bytes':1024.5},{'max_response_bytes':True}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):LocalOllama(url,'test',**kwargs)

    def test_slow_body_cannot_reset_the_overall_network_deadline(self):
        url=self.serve(SlowBodyHandler);start=time.monotonic()
        with self.assertRaises(ValueError):LocalOllama(url,'test',timeout=.15).propose('sample')
        self.assertLess(time.monotonic()-start,1.5)

    def test_slow_headers_cannot_reset_the_overall_network_deadline(self):
        url=self.serve(SlowHeadersHandler);start=time.monotonic()
        with self.assertRaises(ValueError):LocalOllama(url,'test',timeout=.15).propose('sample')
        self.assertLess(time.monotonic()-start,1.5)

    def test_truncated_declared_body_is_rejected(self):
        with self.assertRaises(ValueError):LocalOllama(self.serve(TruncatedHandler),'test').propose('sample')

    def test_complete_chunked_response_is_accepted(self):
        self.assertEqual(LocalOllama(self.serve(ChunkedHandler),'test').propose('sample')['action'],'inspect')

    def test_ambiguous_or_invalid_response_framing_is_rejected(self):
        modes=('duplicate_conflicting','duplicate_identical','negative','signed','nondigit',
               'transfer_conflict','unknown_transfer')
        for mode in modes:
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                LocalOllama(self.serve(framing_handler(mode)),'test',timeout=2).propose('sample')

    def test_close_delimited_response_without_length_is_accepted(self):
        candidate=LocalOllama(self.serve(framing_handler('no_length')),'test',timeout=2).propose('sample')
        self.assertEqual(candidate['target'],'pump-01')

    def test_concurrent_fast_and_slow_requests_have_independent_deadlines(self):
        adapter=LocalOllama(self.serve(MixedHandler),'test',timeout=.2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            fast=pool.submit(adapter.propose,'fast')
            slow=pool.submit(adapter.propose,'slow')
            self.assertEqual(fast.result(timeout=2)['target'],'pump-01')
            with self.assertRaises(ValueError):slow.result(timeout=2)

    def test_http_redirect_is_rejected(self):
        RedirectHandler.hits=0
        with self.assertRaises(ValueError):LocalOllama(self.serve(RedirectHandler),'test').propose('sample')
        self.assertEqual(RedirectHandler.hits,1)

    def test_local_http_protocol_with_fake_server(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            c=LocalOllama(f'http://127.0.0.1:{server.server_port}/api/chat','test-model').propose('synthetic telemetry')
            self.assertEqual(c['target'],'pump-01')
            self.assertEqual(Handler.last_request['stream'],False)
            self.assertEqual(Handler.last_request['format'],'json')
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)

    def test_scripted_agent_gate_and_simulated_device_form_a_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            now=1700000000;gate,keys=setup(Path(tmp)/'state.db',now)
            candidate=ScriptedAgent({'action':'quarantine','target':'pump-01','reason':'test'}).propose('synthetic telemetry')
            envelope=authorize_candidate(candidate,agent_id='defender',key_id='v1',request_id='r',nonce='n',issued_at=now,agent_key=keys['defender'])
            self.assertEqual(gate.evaluate(envelope).outcome,'allow')
            self.assertTrue(Sandbox(gate).execute('r',agent_id='defender')['executed'])


if __name__=='__main__': unittest.main()

