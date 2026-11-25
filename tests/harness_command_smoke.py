#!/usr/bin/env python3
"""Pinned-binary smoke with local fake model/broker endpoints; no real credentials.

Run inside the rebuilt ephemeral image with --network none and temporary HOME.
The only HTTP traffic is container loopback. Does not contact model providers.
"""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('mediation_fixture',ROOT/'security/mediation.py')
mediation=importlib.util.module_from_spec(spec);spec.loader.exec_module(mediation)
requests=[]
gateway_calls=[]
review_mode=False
REVIEW_ID='00000000-0000-4000-8000-000000000001'


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if self.path=='/v1/command-tools':return self.json({'tools':['review_request','decide_command'] if review_mode else ['command_policy','run_command','command_status','execute_command']})
        if self.path.endswith('/count_tokens'):return self.json({'input_tokens':100})
        if self.path in ('/v1/command','/v1/review-request','/v1/review-decision'):
            gateway_calls.append({'operation':self.path,'data':data})
            if self.path=='/v1/review-request':return self.json({'id':REVIEW_ID,'fingerprint':'fixture-fingerprint','argv':['/usr/bin/printf','fixture'],'status':'pending_review'})
            return self.json({'status':'approved' if review_mode else 'executed','exitCode':0,'output':'fixture command output'})
        requests.append({'path':self.path,'tools':data.get('tools',[])})
        self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
        call_name=None;call_args=None
        if not review_mode and not gateway_calls:
            call_name='run_command';call_args={'argv':['/usr/bin/printf','fixture']}
        elif review_mode and not gateway_calls:
            call_name='review_request';call_args={}
        elif review_mode and len(gateway_calls)==1:
            call_name='decide_command';call_args={'id':REVIEW_ID,'fingerprint':'fixture-fingerprint','decision':'allow','reason':'Fixture policy checked'}
        if 'messages' in self.path:
            events=[('message_start',{'type':'message_start','message':{'id':'msg_fixture','type':'message','role':'assistant','model':'fixture','content':[],
                        'stop_reason':None,'stop_sequence':None,'usage':{'input_tokens':100,'output_tokens':0}}}),
                    ('content_block_start',{'type':'content_block_start','index':0,'content_block':{'type':'text','text':''}}),
                    ('content_block_delta',{'type':'content_block_delta','index':0,'delta':{'type':'text_delta','text':'Fixture complete.'}}),
                    ('content_block_stop',{'type':'content_block_stop','index':0}),
                    ('message_delta',{'type':'message_delta','delta':{'stop_reason':'end_turn','stop_sequence':None},'usage':{'output_tokens':4}}),
                    ('message_stop',{'type':'message_stop'})]
        else:
            item={'id':'msg_fixture','type':'message','role':'assistant','status':'completed','content':[{'type':'output_text','text':'Fixture complete.','annotations':[]}]}
            base={'id':'resp_fixture','object':'response','created_at':0,'model':'fixture','status':'in_progress','output':[]}
            events=[('response.created',{'type':'response.created','response':base}),
                    ('response.output_item.added',{'type':'response.output_item.added','output_index':0,'item':dict(item,content=[])}),
                    ('response.output_text.delta',{'type':'response.output_text.delta','item_id':'msg_fixture','output_index':0,'content_index':0,'delta':'Fixture complete.'}),
                    ('response.output_item.done',{'type':'response.output_item.done','output_index':0,'item':item}),
                    ('response.completed',{'type':'response.completed','response':dict(base,status='completed',output=[item],usage={'input_tokens':100,'output_tokens':4,'total_tokens':104})})]
        if call_name and 'messages' in self.path:
            events=[events[0],
                ('content_block_start',{'type':'content_block_start','index':0,'content_block':{'type':'tool_use','id':'tool_fixture_'+str(len(gateway_calls)),'name':'mcp__agentbox__'+call_name,'input':{}}}),
                ('content_block_delta',{'type':'content_block_delta','index':0,'delta':{'type':'input_json_delta','partial_json':json.dumps(call_args)}}),
                ('content_block_stop',{'type':'content_block_stop','index':0}),
                ('message_delta',{'type':'message_delta','delta':{'stop_reason':'tool_use','stop_sequence':None},'usage':{'output_tokens':40}}),events[-1]]
        elif call_name:
            item={'id':'fc_fixture_'+str(len(gateway_calls)),'type':'function_call','name':call_name,'namespace':'mcp__agentbox',
                  'arguments':json.dumps(call_args),'call_id':'call_fixture_'+str(len(gateway_calls)),'status':'completed'}
            events=[('response.created',{'type':'response.created','response':base}),
                    ('response.output_item.added',{'type':'response.output_item.added','output_index':0,'item':dict(item,arguments='')}),
                    ('response.function_call_arguments.delta',{'type':'response.function_call_arguments.delta','item_id':item['id'],'output_index':0,'delta':json.dumps(call_args)}),
                    ('response.function_call_arguments.done',{'type':'response.function_call_arguments.done','item_id':item['id'],'output_index':0,'arguments':json.dumps(call_args)}),
                    ('response.output_item.done',{'type':'response.output_item.done','output_index':0,'item':item}),
                    ('response.completed',{'type':'response.completed','response':dict(base,status='completed',output=[item],usage={'input_tokens':100,'output_tokens':40,'total_tokens':140})})]
        for kind,event in events:self.wfile.write(('event: '+kind+'\ndata: '+json.dumps(event)+'\n\n').encode())
        self.wfile.flush()
    def json(self,data):
        payload=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)


def tool_names(tools):
    names=[]
    for tool in tools:
        if isinstance(tool.get('name'),str):names.append(tool['name'])
        if isinstance(tool.get('function'),dict):names.append(tool['function'].get('name',''))
        if isinstance(tool.get('tools'),list):names+=tool_names(tool['tools'])
        if isinstance(tool.get('functions'),list):names+=tool_names(tool['functions'])
    return names


def claude(role,env):
    args=mediation.prepare_args(role,['--print','--output-format','json'],'/tmp')
    run=subprocess.run(['claude',*args,'Reply briefly.'],env=env,cwd='/tmp',capture_output=True,text=True,timeout=90)
    if run.returncode:raise RuntimeError('Claude fixture exited: '+run.stderr[-2000:])


def codex(role,env):
    args=mediation.prepare_args(role,['app-server'],'/tmp')
    args+=['-c','model_provider="fixture"','-c','model="fixture"',
           '-c','model_providers.fixture.name="Fixture"',
           '-c','model_providers.fixture.base_url="'+env['FIXTURE_URL']+'/v1"',
           '-c','model_providers.fixture.wire_api="responses"',
           '-c','model_providers.fixture.requires_openai_auth=false']
    process=subprocess.Popen(['codex',*args],env=env,cwd='/tmp',stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    received=queue.Queue()
    def reader():
        for line in process.stdout:
            try:received.put(json.loads(line))
            except ValueError:pass
    threading.Thread(target=reader,daemon=True).start()
    def send(message):
        message=mediation.guard_message(role,message)
        process.stdin.write(json.dumps(message)+'\n');process.stdin.flush()
    def response(ident):
        deadline=time.monotonic()+60
        while time.monotonic()<deadline:
            if process.poll() is not None:raise RuntimeError('Codex fixture process exited before its RPC response')
            try:message=received.get(timeout=min(1,max(.1,deadline-time.monotonic())))
            except queue.Empty:continue
            if message.get('id')==ident:
                if 'error' in message:raise RuntimeError('Codex RPC fixture rejected: '+json.dumps(message['error']))
                return message['result']
        raise RuntimeError('Codex RPC fixture timed out')
    try:
        send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'clientInfo':{'name':'agentbox-fixture','version':'1.0'}}})
        response(1);send({'jsonrpc':'2.0','method':'initialized'})
        result=response_after(send,response,2,'thread/start',{'cwd':'/tmp','model':'fixture'})
        ident=result['thread']['id']
        response_after(send,response,3,'turn/start',{'threadId':ident,'input':[{'type':'text','text':'Reply briefly.'}]})
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            message=received.get(timeout=max(.1,deadline-time.monotonic()))
            if message.get('method')=='turn/completed':return
        raise RuntimeError('Codex fixture turn timed out')
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        if process.returncode not in (0,-15):
            error=process.stderr.read()[-2000:]
            if error:print('Codex fixture stderr:',error,file=sys.stderr)


def response_after(send,response,ident,method,params):
    send({'jsonrpc':'2.0','id':ident,'method':method,'params':params});return response(ident)


def main():
    home=Path.home();(home/'.config/agentbox').mkdir(parents=True,exist_ok=True)
    (home/'.codex').mkdir(exist_ok=True)
    (home/'.claude').mkdir(exist_ok=True)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    url='http://127.0.0.1:'+str(server.server_port)
    (home/'.config/agentbox/broker.json').write_text(json.dumps({'url':url,'token':'fixture-local-only'}))
    env=dict(os.environ,ANTHROPIC_API_KEY='fixture-local-only',ANTHROPIC_BASE_URL=url,
             OPENAI_API_KEY='fixture-local-only',FIXTURE_URL=url,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1')
    forbidden={'Bash','PowerShell','shell','shell_command','exec_command','write_stdin','node_repl','spawn_agent','spawn_agents_on_csv','computer','browser','computer_use'}
    summaries=[]
    global review_mode
    for engine in ['claude','codex']:
      for reviewer in [False,True]:
        requests.clear();gateway_calls.clear();review_mode=reviewer
        role={'agent':engine,'harness_version':'2.1.329' if engine=='claude' else '0.171.0',
              'workspace_access':'none' if reviewer else 'readWrite',
              'cli':{'mode':'disabled' if reviewer else 'mediated'}}
        if reviewer:role['role']='approver'
        (claude if engine=='claude' else codex)(role,env)
        all_names=sorted(set(name for request in requests for name in tool_names(request['tools'])))
        if not requests:raise RuntimeError(engine+' did not reach the local model fixture')
        safe_native={'claude':{'DeferredToolPlaceholder','Read','Glob','Grep','AskUserQuestion','Edit','Write'},
                     'codex':{'create_goal','get_goal','update_goal','update_plan','view_image','request_user_input',
                              'list_mcp_resources','list_mcp_resource_templates','read_mcp_resource','mcp__agentbox'}}
        if reviewer and engine=='claude':safe_native['claude']={'DeferredToolPlaceholder'}
        gateway={'review_request','decide_command'} if reviewer else {'command_policy','run_command','command_status','execute_command'}
        expected_names=safe_native[engine]|{('mcp__agentbox__'+name if engine=='claude' else name) for name in gateway}
        if set(all_names)-expected_names:raise RuntimeError(engine+' exposed unexpected tools: '+json.dumps(sorted(set(all_names)-expected_names)))
        if any(name in forbidden for name in all_names):raise RuntimeError(engine+' retained native execution tools: '+json.dumps(all_names))
        expected='review_request' if reviewer else 'run_command'
        if not any(expected in name for name in all_names):raise RuntimeError(engine+' did not load its gateway tools: '+json.dumps(all_names))
        expected_ops=['/v1/review-request','/v1/review-decision'] if reviewer else ['/v1/command']
        if [call['operation'] for call in gateway_calls]!=expected_ops:raise RuntimeError(engine+' gateway roundtrip failed: '+json.dumps(gateway_calls))
        summaries.append({'engine':engine,'role':'approver' if reviewer else 'mediated-worker',
                          'nativeExecutionTools':False,'gatewayRoundtrip':True,'toolNames':all_names})
    print(json.dumps({'passed':True,'checks':summaries},indent=2))
    server.shutdown()


if __name__=='__main__':main()
