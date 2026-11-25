"""Authorization, replay, review races and execution boundary checks."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
import uuid

from agentbox_config.compiler import compile_catalog
from agentbox_config.loader import CatalogError
from agentbox_config.model import validate_catalog
from security.commands import validate_argv, validate_policy
from security import mediation
from test_catalog import catalog, definition, platform
from test_broker_catalog import Backend

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('command_test_broker', ROOT/'security/broker.py')
broker = importlib.util.module_from_spec(spec);spec.loader.exec_module(broker)


def command_catalog():
    value = catalog()
    worker = value['agents'][1]
    worker['harness']['authStorage'] = 'ephemeral'
    worker['workspace'] = {'source': 'callerWorkspace', 'access': 'readWrite'}
    worker['tools'] = {'cli': {'mode': 'mediated', 'policyRef': 'safe'}}
    worker['networkPolicyRef'] = 'model'
    reviewer = definition('reviewer', 'approver', 'codex')
    reviewer['networkPolicyRef'] = 'model'
    reviewer['workspace'] = {'source': 'none', 'access': 'none'}
    reviewer['harness']['authStorage'] = 'ephemeral'
    reviewer['tools'] = {'cli': {'mode': 'disabled'}}
    value['agents'].append(reviewer)
    value['networkPolicies']['model'] = {'mode': 'denyAll', 'dns': [], 'brokerAccess': True,
                                        'httpsProxy': {'allowedHosts': ['api.openai.com']}}
    value['commandPolicies'] = {'safe': {'default': 'deny', 'approverRef': 'reviewer',
        'rules': [{'argv': ['/usr/bin/git', 'status', '--short'], 'action': 'allow'},
                  {'argv': ['/usr/bin/touch', 'reviewed.txt'], 'action': 'review'},
                  {'argv': ['/bin/false'], 'action': 'deny'}],
        'instructions': 'Only allow creating reviewed.txt in the assigned workspace.'}}
    return value


def command_platform():
    value = platform()
    value['authRefs']['reviewer'] = '/srv/auth/reviewer'
    value['networkBindings']['model'] = {'name': 'asp-model', 'subnet': '172.30.12.0/24',
                                         'gateway': '172.30.12.1', 'bridge': 'asp-model', 'internal': True}
    value['proxyBindings'] = {'model': {'port': 3128, 'caFile': '/etc/asp/ca.pem'}}
    return value


class CommandCatalogTests(unittest.TestCase):
    def test_catalog_compiles_fixed_roles_and_policies(self):
        result = compile_catalog(command_catalog(), command_platform())
        roles = result['runtime_policy']['roles']
        self.assertEqual(roles['worker-a']['cli'], {'mode': 'mediated', 'policyRef': 'safe'})
        self.assertEqual(roles['reviewer']['role'], 'approver')
        self.assertEqual(result['runtime_policy']['command_policies']['safe']['default'], 'deny')
        self.assertEqual(roles['reviewer']['delegation']['allowed_workers'], [])

    def test_unknown_policy_invalid_reviewer_and_delegation_to_approver_rejected(self):
        for mutate in [lambda c:c['agents'][1]['tools']['cli'].update(policyRef='missing'),
                       lambda c:c['commandPolicies']['safe'].update(approverRef='worker-a'),
                       lambda c:c['commandPolicies']['safe'].update(approverRef='missing'),
                       lambda c:c['agents'][2].update(enabled=False),
                       lambda c:c['agents'][0]['tools']['launchAgent'].update(allowedWorkers=['reviewer'])]:
            c=command_catalog();mutate(c)
            with self.assertRaises(CatalogError):validate_catalog(c)

    def test_controlled_roles_require_immutable_execution_and_clean_auth(self):
        for mutate in [lambda w:w['harness'].update(authStorage='persistent'),
                       lambda w:w['harness'].update(version='9.9.9'),
                       lambda w:w.update(execution={'readOnlyRoot':False}),
                       lambda w:w.update(execution={'allowPrivilegeEscalation':True,'capabilities':{'drop':[]}})]:
            c=command_catalog();mutate(c['agents'][1])
            with self.assertRaises(CatalogError):validate_catalog(c)

    def test_approver_has_no_workspace_secrets_delegation_or_general_internet(self):
        for mutate in [lambda c:c['agents'][2].update(workspace={'source':'callerWorkspace','access':'readOnly'}),
                       lambda c:c['agents'][2]['tools']['cli'].update(mode='unrestrictedWithinContainer'),
                       lambda c:c['agents'][2]['tools'].update(launchAgent={'allowedWorkers':['worker-a']}),
                       lambda c:c['agents'][2].update(vaultPathToEnv=[{'vaultPath':'kv/test','field':'token','env':'TOKEN'}]),
                       lambda c:c['networkPolicies']['model'].update(brokerAccess=False),
                       lambda c:c['networkPolicies']['model'].update(mode='publicExceptPrivate')]:
            c=command_catalog();mutate(c)
            with self.assertRaises(CatalogError):validate_catalog(c)

    def test_mediated_project_workers_can_use_selected_vault_credentials(self):
        c=command_catalog();c['agents'][1]['vaultPathToEnv']=[{'vaultPath':'kv/test','field':'token','env':'CRM_TOKEN'}]
        self.assertEqual(validate_catalog(c)['agents'][1]['vaultPathToEnv'][0]['env'],'CRM_TOKEN')

    def test_command_rules_are_exact_argv_and_never_unrestricted_default(self):
        invalid=[{'default':'allow'}, {'rules':[{'argv':['git','status'],'action':'allow'}]},
                 {'rules':[{'argv':['/bin/echo','ok'],'action':'allow','prefix':True}]},
                 {'rules':[{'argv':['/bin/echo','ok'],'action':'review'}]},
                 {'rules':[{'argv':['/bin/echo'],'action':'allow'}]*2},
                 {'executionSeconds':True}, {'maxPending':0}]
        for value in invalid:
            with self.subTest(value=value),self.assertRaises(ValueError):validate_policy(value)
        for argv in ['echo ok', [], ['../bin/sh'], ['/bin/../bin/sh'], ['/bin/echo','\0']]:
            with self.assertRaises(ValueError):validate_argv(argv)


class Executor:
    def __init__(self):self.calls=[];self.fail=False
    def execute(self,binding,owner,argv,timeout,start_guard=None):
        with start_guard():pass
        self.calls.append((dict(binding),dict(owner),list(argv),timeout))
        if self.fail:raise OSError('uncertain fixture result')
        return {'status':'executed','exitCode':0,'output':'fixture output','truncated':False}


class CommandBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.projects=self.root/'projects';self.cwd=self.projects/'demo';self.cwd.mkdir(parents=True)
        self.policy=compile_catalog(command_catalog(),command_platform())['runtime_policy']
        self.policy['roots']=[str(self.projects)]
        self.backend=Backend();self.state=self.root/'state.sqlite3'
        self.b=broker.Broker(self.state,[self.projects],self.backend,limit=8,policy=self.policy)
        self.addCleanup(lambda:self.b.db.close())
        self.executor=Executor();self.b.commands.executor=self.executor
        self.worker=str(uuid.uuid4());self.token=self.register(self.worker)
    def register(self,ident,role='worker-a',**extra):
        request={'id':ident,'cwd':str(self.cwd),'definition_id':role,'catalog_revision':self.b.revision}
        if role=='worker-a':request['container']='agentbox-restricted-worker-a-12345'
        request.update(extra)
        return self.b.register(request)['token']
    def submit(self,argv=None,key=None):
        return self.b.handle(self.token,'command',{'argv':argv or ['/usr/bin/touch','reviewed.txt'],'requestId':key or str(uuid.uuid4())})
    def review_token(self,result):
        row=self.b.db.execute('SELECT * FROM command_requests WHERE id=?',(result['id'],)).fetchone()
        return self.register(result['reviewerId'],'reviewer',review_request_id=result['id'],review_nonce=row['review_nonce'])
    def decide(self,result,token,decision='allow',**extra):
        data={'id':result['id'],'fingerprint':result['fingerprint'],'decision':decision,'reason':'Fixture policy checked'}
        data.update(extra)
        return self.b.handle(token,'review-decision',data)

    def test_exact_allowlist_runs_once_and_status_is_read_only(self):
        key=str(uuid.uuid4());argv=['/usr/bin/git','status','--short']
        result=self.submit(argv,key)
        self.assertEqual(result['status'],'executed');self.assertEqual(len(self.executor.calls),1)
        self.assertEqual(self.submit(argv,key),result)
        self.assertEqual(self.b.handle(self.token,'command-execute',{'id':result['id']}),result)
        self.b.handle(self.token,'command-status',{'id':result['id']})
        self.assertEqual(len(self.executor.calls),1)
        with self.assertRaises(broker.Denied):self.submit(['/usr/bin/git','status','--porcelain'],key)

    def test_shell_injection_and_extra_arguments_do_not_match_allowlist(self):
        for argv in [['/usr/bin/git','status','--short; touch injected'],['/bin/sh','-c','touch injected'],
                     ['/usr/bin/git','status','--short','&&','/bin/echo','bad'],['/usr/bin/git','-c','core.fsmonitor=evil','status','--short']]:
            self.assertEqual(self.submit(argv)['status'],'denied')
        self.assertEqual(self.executor.calls,[])

    def test_review_is_visible_then_exact_one_shot_decision_can_execute(self):
        result=self.submit();self.assertEqual(result['status'],'pending_review')
        self.assertIn(result['reviewerId'],self.backend.records)
        reviewer=self.review_token(result)
        request=self.b.handle(reviewer,'review-request',{})
        self.assertEqual(request['argv'],['/usr/bin/touch','reviewed.txt'])
        self.assertEqual(request['workerId'],self.worker)
        self.assertEqual(self.decide(result,reviewer)['status'],'approved')
        self.b.handle(self.token,'command-status',{'id':result['id']})
        self.assertFalse(self.executor.calls)
        executed=self.b.handle(self.token,'command-execute',{'id':result['id']})
        self.assertEqual(executed['status'],'executed');self.assertEqual(len(self.executor.calls),1)
        self.assertTrue(self.backend.records[result['reviewerId']]['Archived'])
        with self.assertRaises(broker.Denied):self.decide(result,reviewer)
        audit=[x[0] for x in self.b.db.execute('SELECT event FROM command_audit WHERE request_id=? ORDER BY seq',(result['id'],))]
        self.assertIn('review_allow',audit);self.assertIn('execution_reserved',audit)

    def test_worker_and_manager_cannot_self_approve_or_supply_execution_overrides(self):
        result=self.submit()
        for token in [self.token,self.register(str(uuid.uuid4()),'manager-a')]:
            with self.assertRaises(broker.Denied):self.decide(result,token)
        for operation,data in [('command',{'argv':['/bin/echo'],'requestId':str(uuid.uuid4()),'cwd':'/'}),
                               ('command-execute',{'id':result['id'],'argv':['/bin/sh']}),
                               ('command-execute',{'id':result['id'],'container':'other'})]:
            with self.assertRaises(broker.Denied):self.b.handle(self.token,operation,data)
        self.assertFalse(self.executor.calls)

    def test_reviewer_cannot_run_commands_manage_workers_or_review_another_request(self):
        first=self.submit();reviewer=self.review_token(first)
        for operation,data in [('command',{'argv':['/bin/echo'],'requestId':str(uuid.uuid4())}),('profiles',{}),
                               ('spawn',{'profile':'worker-a','task':'do this'}),('command-execute',{'id':first['id']})]:
            with self.assertRaises(broker.Denied):self.b.handle(reviewer,operation,data)
        self.decide(first,reviewer,'deny')
        self.b.handle(self.token,'command-status',{'id':first['id']})
        second=self.submit()
        with self.assertRaises(broker.Denied):self.decide(second,reviewer)
        with self.assertRaises((broker.Denied,ValueError)):self.register(str(uuid.uuid4()),'reviewer',review_request_id=second['id'],review_nonce='forged')

    def test_decision_cannot_change_fingerprint_or_reuse_approvals(self):
        result=self.submit();reviewer=self.review_token(result)
        with self.assertRaises(broker.Denied):self.decide(result,reviewer,fingerprint='wrong')
        self.decide(result,reviewer)
        with self.assertRaises(broker.Denied):self.decide(result,reviewer,'deny')
        self.assertFalse(self.executor.calls)

    def test_expiry_and_source_revocation_block_approval_and_execution(self):
        result=self.submit();reviewer=self.review_token(result)
        with self.b.transaction() as db:db.execute('UPDATE command_requests SET expires=0 WHERE id=?',(result['id'],))
        with self.assertRaises(broker.Denied):self.decide(result,reviewer)
        self.assertEqual(self.b.handle(self.token,'command-execute',{'id':result['id']})['status'],'expired')
        result=self.submit();reviewer=self.review_token(result)
        self.b.revoke(self.token)
        with self.assertRaises(broker.Denied):self.decide(result,reviewer)
        self.assertFalse(self.executor.calls)

    def test_replacing_runtime_does_not_inherit_old_command_approval(self):
        result=self.submit();reviewer=self.review_token(result);self.decide(result,reviewer)
        old=self.token;self.token=self.register(self.worker)
        for token in [old,self.token]:
            with self.assertRaises(broker.Denied):self.b.handle(token,'command-execute',{'id':result['id']})
        self.assertFalse(self.executor.calls)

    def test_pending_limit_and_cross_owner_reads(self):
        result=self.submit()
        with self.assertRaises(broker.Denied):self.submit()
        other=self.register(str(uuid.uuid4()))
        with self.assertRaises(broker.Denied):self.b.handle(other,'command-status',{'id':result['id']})
        self.assertFalse(self.executor.calls)

    def test_ambiguous_execution_is_not_retried_even_after_restart(self):
        self.executor.fail=True;key=str(uuid.uuid4());argv=['/usr/bin/git','status','--short']
        result=self.submit(argv,key);self.assertEqual(result['status'],'execution_uncertain')
        self.assertEqual(self.submit(argv,key)['status'],'execution_uncertain')
        self.assertEqual(len(self.executor.calls),1)
        self.b.db.close();self.b=broker.Broker(self.state,[self.projects],self.backend,limit=8,policy=self.policy)
        self.b.commands.executor=self.executor
        self.assertEqual(self.submit(argv,key)['status'],'execution_uncertain')
        self.assertEqual(len(self.executor.calls),1)

    def test_uncertain_execution_blocks_new_request_ids_in_the_same_runtime(self):
        self.executor.fail=True
        result=self.submit(['/usr/bin/git','status','--short'])
        self.assertEqual(result['status'],'execution_uncertain')
        with self.assertRaises(broker.Denied):self.submit(['/usr/bin/git','status','--short'])
        self.assertEqual(len(self.executor.calls),1)

    def test_terminal_review_recovery_requires_exact_native_identity(self):
        self.backend.timeout_once=True
        self.backend.find_review=lambda request,owner:[ident for ident,row in self.backend.records.items() if row['Labels'].get('asp.now.command-review')==request]
        result=self.submit();self.assertEqual(result['status'],'review_launch_uncertain')
        reviewer=next(iter(self.backend.records))
        original=self.backend.records[reviewer]['Provider'];self.backend.records[reviewer]['Provider']='claude'
        self.b.commands.reconcile_reviews(self.b.authenticate(self.token))
        self.assertFalse(self.backend.records[reviewer]['Archived'])
        self.backend.records[reviewer]['Provider']=original
        self.b.commands.reconcile_reviews(self.b.authenticate(self.token))
        self.assertTrue(self.backend.records[reviewer]['Archived'])
        row=self.b.db.execute('SELECT * FROM command_requests WHERE id=?',(result['id'],)).fetchone()
        self.assertTrue(row['reviewer_archived']);self.assertEqual(row['state'],'review_launch_uncertain')
        self.assertFalse(self.executor.calls)

    def test_broker_restart_during_execution_retains_uncertainty(self):
        result=self.submit();reviewer=self.review_token(result);self.decide(result,reviewer)
        with self.b.transaction() as db:db.execute("UPDATE command_requests SET state='executing' WHERE id=?",(result['id'],))
        self.b.db.close();self.b=broker.Broker(self.state,[self.projects],self.backend,limit=8,policy=self.policy)
        self.b.commands.executor=self.executor
        self.assertEqual(self.b.handle(self.token,'command-execute',{'id':result['id']})['status'],'execution_uncertain')
        self.assertFalse(self.executor.calls)

    def test_ambiguous_reviewer_launch_does_not_spawn_another(self):
        self.backend.timeout_once=True;key=str(uuid.uuid4())
        result=self.submit(key=key);self.assertEqual(result['status'],'review_launch_uncertain')
        self.assertEqual(self.submit(key=key)['status'],'review_launch_uncertain')
        self.assertEqual(self.backend.creations,1)

    def test_fast_decision_waits_for_native_reviewer_identity_verification(self):
        observations=[]
        def fast_review():
            row=dict(self.b.db.execute('SELECT * FROM command_requests ORDER BY created DESC LIMIT 1').fetchone())
            reviewer=next(reversed(self.backend.records))
            result=dict(id=row['id'],reviewerId=reviewer,fingerprint=row['fingerprint'])
            token=self.review_token(result)
            observations.append(self.decide(result,token)['status'])
            observations.append(self.b.handle(self.token,'command-execute',{'id':row['id']})['status'])
        self.backend.after_create=fast_review
        result=self.submit()
        self.assertEqual(observations,['review_approved','review_approved'])
        self.assertEqual(result['status'],'executed');self.assertEqual(len(self.executor.calls),1)

    def test_failed_native_reviewer_identity_cannot_promote_fast_approval(self):
        def fast_review():
            row=dict(self.b.db.execute('SELECT * FROM command_requests ORDER BY created DESC LIMIT 1').fetchone())
            reviewer=next(reversed(self.backend.records))
            result=dict(id=row['id'],reviewerId=reviewer,fingerprint=row['fingerprint'])
            self.decide(result,self.review_token(result))
            self.backend.records[reviewer]['Provider']='claude'
        self.backend.after_create=fast_review
        result=self.submit()
        self.assertEqual(result['status'],'review_launch_uncertain');self.assertFalse(self.executor.calls)

    def test_revocation_during_preflight_prevents_actual_execution(self):
        calls=[]
        outer=self
        class RevokingExecutor:
            def execute(self,binding,owner,argv,timeout,start_guard=None):
                outer.b.revoke(outer.token)
                with start_guard():calls.append(argv)
                return {'status':'executed'}
        self.b.commands.executor=RevokingExecutor()
        with self.assertRaises(broker.Denied):self.submit(['/usr/bin/git','status','--short'])
        self.assertEqual(calls,[])
        self.assertEqual(self.b.db.execute('SELECT state FROM command_requests').fetchone()[0],'execution_uncertain')

    def test_concurrent_execution_consumes_approval_once(self):
        result=self.submit();reviewer=self.review_token(result);self.decide(result,reviewer)
        outputs=[]
        def execute():outputs.append(self.b.handle(self.token,'command-execute',{'id':result['id']}))
        workers=[threading.Thread(target=execute) for _ in range(4)]
        for worker in workers:worker.start()
        for worker in workers:worker.join()
        self.assertEqual(len(self.executor.calls),1);self.assertEqual(len(outputs),4)


class HarnessMediationTests(unittest.TestCase):
    def role(self,engine='codex',mode='mediated'):
        return {'agent':engine,'harness_version':'0.171.0' if engine=='codex' else '2.1.329',
                'cli':{'mode':mode},'workspace_access':'readWrite'}

    def test_claude_native_shell_and_external_configuration_are_removed(self):
        result=mediation.prepare_args(self.role('claude'),['--print','--tools','Bash',
            '--permission-mode','bypassPermissions','--mcp-config','{"mcpServers":{"other":{}}}',
            '--settings','{"hooks":{"bad":true}}','--setting-sources','user,project,local'], '/repo')
        self.assertIn('--restricted',result);self.assertNotIn('Bash',result)
        self.assertNotIn('bypassPermissions',result)
        self.assertEqual(result[result.index('--tools')+1],'Read,Glob,Grep,AskUserQuestion,Edit,Write')
        config=json.loads(result[result.index('--mcp-config')+1]);self.assertEqual(list(config['mcpServers']),['agentbox'])

    def test_disabled_cli_has_no_command_gateway_tools(self):
        role=self.role('claude','disabled')
        result=mediation.prepare_args(role,['--print'],'/repo')
        self.assertEqual(result[result.index('--tools')+1],'')
        self.assertEqual(json.loads(result[result.index('--mcp-config')+1])['mcpServers'],{})
        role['role']='approver'
        self.assertEqual(mediation.tools(role),['review_request','decide_command'])

    def test_codex_thread_overrides_cannot_reenable_native_execution_or_extra_mcp(self):
        for method in ['thread/start','thread/resume','thread/fork','turn/start']:
            value=mediation.guard_message(self.role(),{'method':method,'params':{'config':{
                'features':{'shell_tool':True},'features.shell_tool':True,'mcp_servers':{'unsafe':{}}},
                'approvalPolicy':'never','dynamicTools':[{'name':'exec'}]}})
            config=value['params']['config']
            self.assertFalse(config['features']['shell_tool']);self.assertFalse(config['features']['code_mode_host'])
            self.assertNotIn('features.shell_tool',config)
            self.assertEqual(list(config['mcp_servers']),['agentbox']);self.assertNotIn('dynamicTools',value['params'])
        with self.assertRaises(ValueError):mediation.guard_message(self.role(),{'method':'command/exec'})
        args=mediation.prepare_args(self.role(),['app-server','-c','features.shell_tool=true'],'/repo')
        self.assertNotIn('features.shell_tool=true',args);self.assertIn('features.shell_tool=false',args)

    def test_only_verified_harness_versions_and_protocols_are_accepted(self):
        role=self.role();role['harness_version']='0.172.0'
        with self.assertRaises(ValueError):mediation.prepare_args(role,['app-server'],'/repo')
        with self.assertRaises(ValueError):mediation.prepare_args(self.role(),['exec','do this'],'/repo')

    def test_docker_executor_pins_identity_and_never_runs_a_host_shell(self):
        policy={'uid':1000,'gid':1000,'catalog_revision':'revision-one','roles':{'worker':{'workspace_access':'readWrite'}}}
        owner={'id':'worker-id','definition_id':'worker','cwd':'/repo'}
        labels={'agentbox.restricted':'true','agentbox.agent':'worker-id','agentbox.role':'worker','asp.now.revision':'revision-one'}
        output='\n'.join(json.dumps(v) for v in ['a'*64,labels,'1000:1000',True])
        process=types.SimpleNamespace(poll=lambda:0,returncode=0)
        executor=broker.commands.DockerExecutor(policy)
        with patch.object(broker.commands.subprocess,'run',return_value=types.SimpleNamespace(stdout=output)),\
             patch.object(broker.commands.subprocess,'Popen',return_value=process) as popen:
            executor.execute({'container_name':'registered'},owner,['/bin/echo','; touch malicious'],30)
        args=popen.call_args.args[0]
        self.assertEqual(args,['/usr/bin/docker','exec','--user','1000:1000','--workdir','/repo','a'*64,'/bin/echo','; touch malicious'])
        self.assertNotIn('shell',popen.call_args.kwargs)
        for wrong in [dict(labels,**{'agentbox.agent':'other'}),dict(labels,**{'asp.now.revision':'old'})]:
            bad='\n'.join(json.dumps(v) for v in ['a'*64,wrong,'1000:1000',True])
            with patch.object(broker.commands.subprocess,'run',return_value=types.SimpleNamespace(stdout=bad)),\
                 patch.object(broker.commands.subprocess,'Popen') as popen:
                with self.assertRaises(ValueError):executor.execute({'container_name':'registered'},owner,['/bin/true'],30)
                popen.assert_not_called()


if __name__=='__main__':unittest.main()
