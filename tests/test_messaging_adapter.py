"""Exercise the trusted JS adapter against a fake native daemon client."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class MessagingAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.cwd=str(Path(self.temp.name).resolve())
        self.agent={'id':'worker','provider':'codex-box','cwd':self.cwd,'archivedAt':None,
                    'labels':{'paseo.parent-agent-id':'manager'},'pendingPermissions':[]}
        self.input={'operation':'send','id':'worker','owner':'manager','provider':'codex-box',
                    'cwd':self.cwd,'message':'--env X=bad; $(do-not-execute)'}
        self.script="""
import { perform } from %s;
let text=''; for await (const chunk of process.stdin) text+=chunk;
const fixture=JSON.parse(text),calls=[];
const client={fetchAgent:async()=>({agent:fixture.agent}),
 sendAgentMessage:async(...args)=>{calls.push(['send',...args]);return {deliveryStatus:'queued'};},
 respondToPermissionAndWait:async(...args)=>{calls.push(['answer',...args]);}};
try { console.log(JSON.stringify({result:await perform(client,fixture.input),calls})); }
catch(e) { console.log(JSON.stringify({denied:e.denied===true,calls})); }
""" % json.dumps((ROOT/'security/paseo-messaging.mjs').as_uri())
    def invoke(self):
        result=subprocess.run(['node','--input-type=module','-e',self.script],
                              input=json.dumps({'input':self.input,'agent':self.agent}),
                              text=True,capture_output=True,timeout=10,check=True)
        return json.loads(result.stdout)
    def question(self,name='request_user_input',kind='question',request_id='permission-1'):
        row={'id':request_id,'name':name,'kind':kind,'input':{'questions':[
            {'id':'color','header':'Color','question':'Which color?','options':[{'label':'Blue'}]}]}}
        self.agent['pendingPermissions']=[row]
        return row

    def test_send_uses_manager_attribution_and_steer_without_permission_response(self):
        result=self.invoke()
        self.assertEqual(result['result']['status'],'queued')
        self.assertEqual(result['calls'],[['send','worker',self.input['message'],
            {'sourceAgentId':'manager','activeTurnBehavior':'steer'}]])

    def test_native_identity_and_archival_are_rechecked_before_delivery(self):
        original=dict(self.agent)
        for field,value in [('id','other'),('provider','codex'),('cwd','/'),('archivedAt','now'),
                            ('labels',{'paseo.parent-agent-id':'other'})]:
            self.agent=dict(original,**{field:value})
            with self.subTest(field=field):
                result=self.invoke();self.assertTrue(result['denied']);self.assertEqual(result['calls'],[])

    def test_question_listing_returns_keys_and_separates_tool_approvals(self):
        self.question();self.agent['pendingPermissions'].append({'id':'shell','name':'Bash','kind':'tool'})
        self.input['operation']='questions';result=self.invoke()['result']
        self.assertEqual(result['questions'][0]['questions'][0]['key'],'Color')
        self.assertEqual(result['blockedPermissions'],[{'id':'shell','tool':'Bash'}])
        self.input['operation']='send';self.assertTrue(self.invoke()['denied'])

    def test_both_harness_question_answers_preserve_original_question_input(self):
        for name,key in [('request_user_input','Color'),('AskUserQuestion','Which color?')]:
            request=self.question(name)
            self.input.update(operation='answer',questionId=request['id'],answers={key:'Blue'})
            result=self.invoke()
            self.assertEqual(result['result']['status'],'answered')
            self.assertEqual(result['calls'],[['answer','worker','permission-1',
                {'behavior':'allow','updatedInput':dict(request['input'],answers={key:'Blue'})}]])

    def test_answer_rejects_permissions_plan_approval_prefixes_and_partial_answers(self):
        self.input.update(operation='answer',questionId='permission-1',answers={'Color':'Blue'})
        for name,kind in [('Bash','tool'),('CodexFileChange','tool'),('ExitPlanMode','question'),
                          ('AskUserQuestion','tool')]:
            self.question(name,kind);result=self.invoke()
            self.assertTrue(result['denied']);self.assertEqual(result['calls'],[])
        self.question();self.input['questionId']='permission-';self.assertTrue(self.invoke()['denied'])
        self.input['questionId']='permission-1'
        for answers in [{},{'Color':'Blue','behavior':'allow'},{'Color':[]},{'Color':' '}]:
            self.input['answers']=answers;self.assertTrue(self.invoke()['denied'])


if __name__=='__main__':unittest.main()
