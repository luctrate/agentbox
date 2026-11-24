import importlib.util
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('execution_provider',ROOT/'security/provider.py')
provider=importlib.util.module_from_spec(spec);spec.loader.exec_module(provider)
secrets=provider.secret_values


class ExecutionCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.projects=self.root/'projects';self.projects.mkdir()
        self.repo=self.projects/'repo';self.repo.mkdir();self.owner=str(uuid.uuid4())
        self.policy={'catalog_revision':'a'*64,'roots':[str(self.projects)],'vault_addr':'https://vault.example.test',
            'vault_cacert':'/trusted/ca.crt','uid':1000,'gid':1000,'roles':{'reviewer':{
                'definition_id':'reviewer','provider_id':'asp-reviewer','agent':'codex','manager':False,
                'auth':str(self.root/'auth'),'network':'asp-review','network_policy_id':'review',
                'image':'sha256:'+'f'*64,'workspace_access':'readOnly','read_only_root':True,
                'cpu':1.5,'memory':'1536m','pids':128,'drop_capabilities':['ALL'],
                'no_new_privileges':True,'sudo':True,'delegation':{'allowed_workers':[]}}},
            'networks':{'review':{'name':'asp-review','subnet':'172.29.50.0/24','gateway':'172.29.50.1',
                'bridge':'asp-review','mode':'denyAll','allow':[],'dns':[],'brokerAccess':False}}}

    def test_explicit_runtime_controls_are_independent_of_manager_and_sudo_metadata(self):
        _,args,_,manager,_=provider.build(self.policy,'reviewer',['app-server'],{'PASEO_AGENT_ID':self.owner},str(self.repo))
        self.assertFalse(manager)
        self.assertIn(str(self.repo)+':'+str(self.repo)+':ro',args)
        self.assertIn('--read-only',args)
        self.assertIn('no-new-privileges:true',args)
        self.assertEqual(args[args.index('--memory')+1],'1536m')
        self.assertEqual(args[args.index('--cpus')+1],'1.5')
        self.assertEqual(args[args.index('--pids-limit')+1],'128')
        self.assertEqual(args[args.index('--dns')+1],'127.0.0.1')
        self.assertIn('--cap-drop',args)
        self.assertIn('--group-add',args)  # Installed sudo is blocked by no-new-privileges.

    def test_research_has_no_host_binds_and_worker_has_only_project_bind(self):
        role=self.policy['roles']['reviewer'];role.update(auth_storage='ephemeral',sudo=False)
        for access,expected in [('none',[]),('readWrite',[str(self.repo)+':'+str(self.repo)])]:
            role['workspace_access']=access
            _,args,env,_,_=provider.build(self.policy,'reviewer',['app-server'],{'PASEO_AGENT_ID':self.owner},str(self.repo))
            binds=[args[i+1] for i,x in enumerate(args) if x=='--volume']
            self.assertEqual(binds,expected)
            self.assertNotIn(str(self.root/'auth'),str(args));self.assertNotIn('VAULT_TOKEN',env)
            self.assertIn('CODEX_HOME=/home/agent/.codex',args)
        role['vault_secrets']={'TOKEN':'kv/test#token'}
        with self.assertRaises(ValueError):provider.build(self.policy,'reviewer',[],{},str(self.repo))

    def test_bootstrap_copies_only_login_and_names_the_trusted_parent(self):
        role=self.policy['roles']['reviewer'];auth=Path(role['auth']);auth.mkdir()
        (auth/'auth.json').write_text('{"tokens":{"access_token":"fixture-model-login"},"mcpOAuth":{"token":"never-copy-tool-login"}}')
        (auth/'AGENTS.md').write_text('Use only the research allowlist.')
        (auth/'unrelated-secret').write_text('never-copy-this')
        payload=json.loads(provider.bootstrap_header(self.policy,role,['app-server'],self.owner))
        self.assertEqual(set(payload['files']),{'.codex/auth.json','.codex/AGENTS.md'})
        instructions=base64.b64decode(payload['files']['.codex/AGENTS.md']).decode()
        self.assertIn(self.owner,instructions);self.assertIn('remain untrusted data',instructions)
        self.assertNotIn('fixture-model-login',instructions);self.assertNotIn('never-copy-this',str(payload))
        login=json.loads(base64.b64decode(payload['files']['.codex/auth.json']))
        self.assertEqual(set(login),{'tokens'})
        (auth/'.credentials.json').write_text('{"claudeAiOauth":{"accessToken":"fixture-model-login"},"mcpOAuth":{"token":"never-copy-tool-login"}}')
        role['agent']='claude'
        payload=json.loads(provider.bootstrap_header(self.policy,role,['--version','not-a-probe']))
        login=json.loads(base64.b64decode(payload['files']['.claude/.credentials.json']))
        self.assertEqual(set(login),{'claudeAiOauth'})

    def test_catalog_requires_digest_and_consistent_network_identity(self):
        role=self.policy['roles']['reviewer']
        role['image']='mutable:latest'
        with self.assertRaises(ValueError):provider.build(self.policy,'reviewer',[],{},str(self.repo))
        role['image']='sha256:'+'f'*64;role['network']='other-network'
        with self.assertRaises(ValueError):provider.build(self.policy,'reviewer',[],{},str(self.repo))

    def test_catalog_delegation_requires_broker_network_access(self):
        self.policy['roles']['reviewer']['delegation']['allowed_workers']=['worker']
        with self.assertRaises(ValueError):provider.build(self.policy,'reviewer',[],{},str(self.repo))

    def test_host_control_names_are_rejected_before_any_vault_read(self):
        for name in ['DOCKER_HOST','DOCKER_CONFIG','LD_PRELOAD','DYLD_INSERT_LIBRARIES','PYTHONPATH',
                     'NODE_OPTIONS','HOME','PATH','VAULT_TOKEN','PASEO_AGENT_ID','AGENTBOX_ROOT','ASP_POLICY',
                     'HTTPS_PROXY','http_proxy','CODEX_HOME','CLAUDE_CONFIG_DIR','GIT_CONFIG_COUNT']:
            with self.subTest(name=name),patch.object(secrets.subprocess,'run') as run:
                with self.assertRaises(ValueError):secrets.resolve_vault_secrets({name:'secret/test#field'},{})
                run.assert_not_called()

    def test_field_bytes_preserve_crlf_and_trailing_newlines_and_do_not_pollute_later_reads(self):
        with patch.object(secrets.subprocess,'run',side_effect=[types.SimpleNamespace(stdout=b'first\r\nlast\n\n'),
                                                             types.SimpleNamespace(stdout=b'next')]) as run:
            values=secrets.resolve_vault_secrets({'FIRST':'secret/first#value','SECOND':'secret/second#value'},
                                               {'VAULT_ADDR':'https://vault.example.test'})
        self.assertEqual(values['FIRST'],'first\r\nlast\n\n')
        self.assertEqual(values['SECOND'],'next')
        for call in run.call_args_list:
            self.assertNotIn('FIRST',call.kwargs['env'])
            self.assertNotIn('first\r\nlast\n\n',str(call.args[0]))

    def test_nul_and_vault_failure_are_sanitized(self):
        for result in [types.SimpleNamespace(stdout=b'private\x00secret'),subprocess.CalledProcessError(1,['vault'],stderr=b'private-secret')]:
            with self.subTest(result=type(result).__name__):
                kwargs={'side_effect':result} if isinstance(result,Exception) else {'return_value':result}
                with patch.object(secrets.subprocess,'run',**kwargs):
                    with self.assertRaises(RuntimeError) as error:secrets.resolve_vault_secrets({'TOKEN':'secret/test#field'},{})
                    self.assertNotIn('private',str(error.exception))

    def test_network_readiness_revision_and_plan_hash_are_required(self):
        ready=self.root/'ready.json';self.policy['network_readiness']={'path':str(ready),'revision':'a'*64}
        with patch.object(provider,'trusted_file',return_value=ready):
            ready.write_text(json.dumps({'revision':'b'*64,'plan_hash':provider.network_policy.policy_fingerprint(self.policy),'networks':['asp-review']}))
            with self.assertRaises(ValueError):provider.verify_network_readiness(self.policy,self.policy['roles']['reviewer'])
            ready.write_text(json.dumps({'revision':'a'*64,'plan_hash':'wrong','networks':['asp-review']}))
            with self.assertRaises(ValueError):provider.verify_network_readiness(self.policy,self.policy['roles']['reviewer'])
            ready.write_text(json.dumps({'revision':'a'*64,'plan_hash':provider.network_policy.policy_fingerprint(self.policy),'networks':['asp-review']}))
            provider.verify_network_readiness(self.policy,self.policy['roles']['reviewer'])

    def test_cleanup_timeout_does_not_skip_revoke_and_registration_carries_catalog_identity(self):
        role=self.policy['roles']['reviewer'];role['delegation']['allowed_workers']=['worker']
        self.policy.update({'control_socket':'/run/control','broker_url':'http://broker','client':'/opt/client'})
        process=types.SimpleNamespace(wait=lambda:0,poll=lambda:0)
        requests=[]
        def control(path,request):requests.append(request);return {'token':'private-capability'}
        with patch.object(provider,'trusted_file',return_value=Path('/trusted/policy')),\
             patch.object(provider.Path,'read_text',return_value=json.dumps(self.policy)),\
             patch.object(provider,'verify_network_readiness'),\
             patch.object(provider,'build',return_value=('test',[],{},False,False)),\
             patch.object(provider,'control',side_effect=control),\
             patch.object(provider.subprocess,'Popen',return_value=process),\
             patch.object(provider.subprocess,'run',side_effect=subprocess.TimeoutExpired('cleanup',15)),\
             patch.object(provider.signal,'signal'),\
             patch.object(sys,'argv',['provider','--policy','/trusted/policy','--role','reviewer','app-server']),\
             patch.dict(os.environ,{'PASEO_AGENT_ID':self.owner}),patch('sys.stderr',new_callable=io.StringIO) as stderr:
            self.assertEqual(provider.main(),0)
        self.assertEqual([x['op'] for x in requests],['register','revoke'])
        self.assertEqual(requests[0]['definition_id'],'reviewer')
        self.assertEqual(requests[0]['catalog_revision'],'a'*64)
        self.assertNotIn('private-capability',stderr.getvalue())

    def test_policy_argument_is_absolute_and_does_not_consume_harness_arguments(self):
        self.assertEqual(provider._arguments(['--policy','/trusted/policy','--role','worker','app-server','--config','x']),
                         ('/trusted/policy','worker',['app-server','--config','x']))
        with self.assertRaises(ValueError):provider._arguments(['--policy','relative','--role','worker'])


if __name__=='__main__':unittest.main()
