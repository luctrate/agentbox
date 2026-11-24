"""mitmproxy addon: exact model-service HTTPS destinations, no tunnel bypass.

TLS is terminated by the trusted host proxy so an allowed CONNECT hostname
cannot conceal a different HTTP Host/:authority on a shared CDN address.
Neither model tokens nor request/response bodies are logged or persisted here.
"""
import ipaddress
import json
import os
from pathlib import Path
import socket

from mitmproxy import http


class ModelProxy:
    def __init__(self,policy=None):
        if policy is None:policy=json.loads(Path(os.environ.get('AGENTBOX_POLICY','/etc/agentbox/security.json')).read_text())
        entries=[n for n in policy['networks'].values() if n.get('httpsProxy')]
        if len(entries)!=1:raise ValueError('Exactly one dedicated model proxy is supported')
        entry=entries[0];self.subnet=ipaddress.ip_network(entry['subnet'])
        self.hosts=set(entry['httpsProxy']['allowedHosts']);self.connections={}

    def client_connected(self,client):
        if ipaddress.ip_address(client.peername[0]) not in self.subnet:client.error='Source network denied'

    def client_disconnected(self,client):self.connections.pop(client.id,None)

    def http_connect(self,flow):
        if flow.request.host not in self.hosts or flow.request.port!=443:
            flow.response=http.Response.make(403,b'Model endpoint denied\n');return
        self.connections[flow.client_conn.id]=flow.request.host

    def requestheaders(self,flow):
        request=flow.request;expected=self.connections.get(flow.client_conn.id)
        authority=request.authority or request.headers.get('host','')
        valid_authorities=(expected,expected+':443') if expected else ()
        if (request.scheme!='https' or request.method=='CONNECT' or request.host!=expected or
                expected not in self.hosts or request.port!=443 or authority not in valid_authorities or
                request.headers.get('host',expected) not in valid_authorities):
            flow.response=http.Response.make(403,b'Model endpoint denied\n');return
        request.stream=True

    def responseheaders(self,flow):flow.response.stream=True

    def server_connect(self,data):
        host,port=data.server.address
        if host not in self.hosts or port!=443:
            data.server.error='Upstream endpoint denied';return
        # Resolve only approved names, reject private/rebound answers, and pin
        # the actual socket address while retaining hostname TLS verification.
        try:
            addresses={row[4][0] for row in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)}
            if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):raise ValueError()
        except (OSError,ValueError):data.server.error='Upstream resolution denied';return
        data.server.sni=host;data.server.address=(sorted(addresses)[0],443)


# Unit fixtures import the class with a stub mitmproxy module; no live policy
# read occurs unless the actual service explicitly enables this addon.
addons=[ModelProxy()] if os.environ.get('AGENTBOX_MODEL_PROXY')=='1' else []
