#!/usr/bin/env python3
"""Disposable real-Docker command-gateway smoke; no model/provider credentials.

Run as a non-root Docker-capable Linux account with catalog test dependencies.
Only the generated test container and temporary project are mutated.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from agentbox_config.compiler import compile_catalog
from test_commands import command_catalog,command_platform
from test_broker_catalog import Backend
spec=importlib.util.spec_from_file_location('docker_smoke_broker',ROOT/'security/broker.py')
broker=importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',default='agentbox/ephemeral:local')
    args=parser.parse_args()
    if os.getuid()==0:raise RuntimeError('Run the smoke as a non-root Docker-capable account')
    ident=str(uuid.uuid4());name='agentbox-restricted-command-smoke-'+str(os.getpid())
    with tempfile.TemporaryDirectory(prefix='agentbox-command-smoke-') as temporary:
        base=Path(temporary).resolve();projects=base/'projects';cwd=projects/'demo';cwd.mkdir(parents=True)
        doc=command_catalog();policy=compile_catalog(doc,command_platform())['runtime_policy']
        policy.update(roots=[str(projects)],uid=os.getuid(),gid=os.getgid())
        policy['command_policies']['safe']['rules'].append({'argv':['/usr/bin/printf','literal ; $(touch injected)'],'action':'allow'})
        backend=Backend();b=broker.Broker(base/'state.sqlite3',[projects],backend,limit=8,policy=policy)
        server=broker.HTTPServer(('127.0.0.1',0),broker.make_http_handler(b))
        threading.Thread(target=server.serve_forever,daemon=True).start()
        token=b.register({'id':ident,'cwd':str(cwd),'definition_id':'worker-a','catalog_revision':b.revision,'container':name})['token']
        def call(operation,data,credential=token):
            request=urllib.request.Request('http://127.0.0.1:'+str(server.server_port)+'/v1/'+operation,json.dumps(data).encode(),
                {'Content-Type':'application/json','Authorization':'Bearer '+credential})
            with urllib.request.urlopen(request,timeout=20) as response:return json.load(response)
        command=['/usr/bin/docker','run','--rm','-d','--name',name,'--network','none','--read-only',
                 '--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','256m','--pids-limit','64',
                 '--user',str(os.getuid())+':'+str(os.getgid()),'--workdir',str(cwd),
                 '--volume',str(cwd)+':'+str(cwd),'--tmpfs','/tmp:rw,nosuid,nodev,size=64m',
                 '--label','agentbox.restricted=true','--label','agentbox.agent='+ident,
                 '--label','agentbox.role=worker-a','--label','asp.now.revision='+b.revision,
                 '--entrypoint','/bin/sleep',args.image,'180']
        try:
            subprocess.run(command,check=True,capture_output=True,text=True,timeout=30)
            key=str(uuid.uuid4())
            value=call('command',{'argv':['/usr/bin/printf','literal ; $(touch injected)'],'requestId':key})
            assert value['status']=='executed' and value['exitCode']==0 and value['output']=='literal ; $(touch injected)',value
            assert not (cwd/'injected').exists()
            assert call('command',{'argv':['/usr/bin/printf','literal ; $(touch injected)'],'requestId':key})==value
            denied=call('command',{'argv':['/bin/sh','-c','touch denied'],'requestId':str(uuid.uuid4())})
            assert denied['status']=='denied' and not (cwd/'denied').exists()
            review=call('command',{'argv':['/usr/bin/touch','reviewed.txt'],'requestId':str(uuid.uuid4())})
            assert review['status']=='pending_review' and not (cwd/'reviewed.txt').exists()
            row=b.db.execute('SELECT * FROM command_requests WHERE id=?',(review['id'],)).fetchone()
            reviewer=b.register({'id':review['reviewerId'],'cwd':str(cwd),'definition_id':'reviewer','catalog_revision':b.revision,
                                 'review_request_id':review['id'],'review_nonce':row['review_nonce']})['token']
            decision={'id':review['id'],'fingerprint':review['fingerprint'],'decision':'allow','reason':'Smoke fixture policy checked'}
            try:call('review-decision',decision)
            except urllib.error.HTTPError as error:assert error.code==403
            else:raise AssertionError('Worker approved itself')
            assert call('review-decision',decision,reviewer)['status']=='approved'
            assert call('command-status',{'id':review['id']})['status']=='approved'
            assert not (cwd/'reviewed.txt').exists()
            assert call('command-execute',{'id':review['id']})['status']=='executed'
            assert (cwd/'reviewed.txt').is_file()
            assert call('command-execute',{'id':review['id']})['status']=='executed'
            print(json.dumps({'passed':True,'realDockerExecution':True,'literalArguments':True,
                              'denyBeforeExecution':True,'workerSelfApprovalDenied':True,
                              'reviewBeforeWrite':True,'readOnlyStatus':True,'idempotentReplay':True}))
        finally:
            subprocess.run(['/usr/bin/docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
            server.shutdown();server.server_close();b.db.close()


if __name__=='__main__':main()
