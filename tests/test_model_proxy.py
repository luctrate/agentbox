import importlib.util
import ipaddress
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
fake=types.SimpleNamespace(http=types.SimpleNamespace(Response=types.SimpleNamespace(
    make=lambda status,body:types.SimpleNamespace(status_code=status))))
with patch.dict(sys.modules,{'mitmproxy':fake}):
    spec=importlib.util.spec_from_file_location('model_proxy_fixture',ROOT/'security/model_proxy.py')
    proxy=importlib.util.module_from_spec(spec);spec.loader.exec_module(proxy)


class ModelProxyTests(unittest.TestCase):
    def setUp(self):
        self.proxy=proxy.ModelProxy({'networks':{'offline':{'subnet':'172.29.42.0/24',
            'httpsProxy':{'allowedHosts':['api.anthropic.com','chatgpt.com']}}}})
    def flow(self,host='api.anthropic.com',method='CONNECT',scheme='https',authority=None):
        return types.SimpleNamespace(client_conn=types.SimpleNamespace(id='worker',peername=('172.29.42.2',34567)),
            request=types.SimpleNamespace(host=host,port=443,method=method,scheme=scheme,
                authority=authority or host,headers={'host':authority or host}),response=None)
    def test_connect_and_each_decrypted_authority_must_match_exact_allowlist(self):
        for host in ['example.com','api.anthropic.com.evil.example','1.1.1.1','vault.example.test']:
            flow=self.flow(host);self.proxy.http_connect(flow);self.assertEqual(flow.response.status_code,403)
        flow=self.flow();self.proxy.http_connect(flow);self.assertIsNone(flow.response)
        good=self.flow(method='POST');self.proxy.requestheaders(good);self.assertIsNone(good.response)
        for flow in [self.flow(host='chatgpt.com',method='POST'),self.flow(method='CONNECT'),
                     self.flow(method='GET',scheme='http'),self.flow(method='GET',authority='example.com')]:
            self.proxy.requestheaders(flow);self.assertEqual(flow.response.status_code,403)
    def test_proxy_rejects_non_worker_clients(self):
        client=types.SimpleNamespace(peername=('10.77.0.30',1234),error=None)
        self.proxy.client_connected(client);self.assertIsNotNone(client.error)
    def test_dns_is_only_resolved_for_allowlisted_names_and_pinned_to_public_ip(self):
        for host in ['vault.example.test','example.com']:
            data=types.SimpleNamespace(server=types.SimpleNamespace(address=(host,443),error=None))
            with patch.object(proxy.socket,'getaddrinfo') as dns:self.proxy.server_connect(data);dns.assert_not_called()
            self.assertIsNotNone(data.server.error)
        for address in ['127.0.0.1','10.77.0.10','169.254.169.254','172.29.42.1']:
            data=types.SimpleNamespace(server=types.SimpleNamespace(address=('api.anthropic.com',443),error=None))
            with patch.object(proxy.socket,'getaddrinfo',return_value=[(None,None,None,None,(address,443))]):self.proxy.server_connect(data)
            self.assertIsNotNone(data.server.error)
        data=types.SimpleNamespace(server=types.SimpleNamespace(address=('api.anthropic.com',443),error=None))
        with patch.object(proxy.socket,'getaddrinfo',return_value=[(None,None,None,None,('1.1.1.1',443))]):self.proxy.server_connect(data)
        self.assertEqual(data.server.address,('1.1.1.1',443));self.assertEqual(data.server.sni,'api.anthropic.com')


if __name__=='__main__':unittest.main()
