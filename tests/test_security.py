import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'security'/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
broker=load('broker');provider=load('provider')


class Backend:
    def __init__(self):self.calls=[]
    def call(self,args,owner):
        self.calls.append((args,dict(owner)))
        if args[0]=='run':return {'agentId':str(uuid.uuid4()),'status':'running'}
        return {'ok':True}


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.projects=self.root/'projects';self.projects.mkdir()
        self.repo=self.projects/'repo';self.repo.mkdir()
        self.backend=Backend()
        self.b=broker.Broker(self.root/'state.json',[self.projects],self.backend,limit=2)
        self.owner=str(uuid.uuid4())
        self.token=self.b.register({'id':self.owner,'cwd':str(self.repo),'workspace':'wks_test'})['token']

    def test_no_caller_supplied_environment_provider_or_docker_fields(self):
        for extra in ['env','mounts','provider','command','vault_path','cwd','mode']:
            with self.assertRaises(broker.Denied):
                self.b.handle(self.token,'spawn',{'profile':'codex','task':'test',extra:'untrusted'})
        with self.assertRaises(broker.Denied):
            self.b.handle(self.token,'spawn',{'profile':'claude-manager','task':'test'})
        self.assertEqual(self.backend.calls,[])

    def test_owner_context_and_fixed_provider_and_task_are_separate_arguments(self):
        result=self.b.handle(self.token,'spawn',{'profile':'codex','task':'--env X=bad; echo no'})
        args,owner=self.backend.calls[-1]
        self.assertEqual(args[args.index('--provider')+1],'codex-box')
        self.assertEqual(args[-2:],['--','--env X=bad; echo no'])
        self.assertEqual(owner['id'],self.owner)
        self.b.handle(self.token,'status',{'id':result['agentId']})

    def test_cannot_read_stop_or_archive_other_managers_workers(self):
        child=self.b.handle(self.token,'spawn',{'profile':'claude','task':'test'})['agentId']
        other=self.b.register({'id':str(uuid.uuid4()),'cwd':str(self.repo)})['token']
        for operation in ['status','logs','stop','archive']:
            with self.assertRaises(broker.Denied):self.b.handle(other,operation,{'id':child})

    def test_revocation_and_resume_invalidate_old_capabilities(self):
        new=self.b.register({'id':self.owner,'cwd':str(self.repo)})['token']
        with self.assertRaises(broker.Denied):self.b.handle(self.token,'profiles',{})
        self.b.revoke(new)
        with self.assertRaises(broker.Denied):self.b.handle(new,'profiles',{})

    def test_limit_released_only_on_archive_and_state_persists(self):
        child=self.b.handle(self.token,'spawn',{'profile':'codex','task':'one'})['agentId']
        self.b.handle(self.token,'spawn',{'profile':'codex','task':'two'})
        with self.assertRaises(broker.Denied):self.b.handle(self.token,'spawn',{'profile':'codex','task':'three'})
        self.b.handle(self.token,'archive',{'id':child})
        self.b.handle(self.token,'spawn',{'profile':'codex','task':'three'})
        restored=broker.Broker(self.root/'state.json',[self.projects],self.backend)
        self.assertEqual(restored.authenticate(self.token)['id'],self.owner)
        self.assertNotIn(self.token,(self.root/'state.json').read_text())

    def test_reject_root_or_symlink_escape_workspaces(self):
        (self.projects/'escape').symlink_to(self.root)
        for path in [self.root,self.projects,self.projects/'escape']:
            with self.assertRaises((broker.Denied,ValueError)):
                self.b.register({'id':str(uuid.uuid4()),'cwd':str(path)})
            with self.assertRaises(ValueError):provider.workspace_mounts(path,[str(self.projects)])

    def test_launcher_ignores_host_environment_overrides_and_manager_has_read_only_repo(self):
        policy={'roots':[str(self.projects)],'vault_addr':'https://vault.example.com',
                'vault_cacert':'/public/ca.crt','roles':{'manager-codex':{
                    'agent':'codex','manager':True,'auth':str(self.root/'auth'),
                    'network':'fixed-manager-net','image':'sha256:fixed'}}}
        with patch.object(provider.subprocess,'run',side_effect=AssertionError('No Vault read permitted')):
            _,args,env,manager,_=provider.build(policy,'manager-codex',['app-server'],{
                'PASEO_AGENT_ID':self.owner,'PATH':'/attacker','DOCKER_HOST':'tcp://attacker','VAULT_TOKEN':'secret',
                'AGENTBOX_ROOT':'/attacker','OPENAI_API_KEY':'unrelated'},str(self.repo))
        self.assertTrue(manager)
        self.assertIn(str(self.repo)+':'+str(self.repo)+':ro',args)
        self.assertIn('--read-only',args)
        self.assertIn('no-new-privileges:true',args)
        self.assertNotIn('VAULT_TOKEN',env)
        self.assertNotIn('OPENAI_API_KEY',env)
        self.assertNotIn('DOCKER_HOST',env)
        self.assertNotIn('/attacker',str(args)+str(env))
        self.assertFalse(any('docker.sock' in value for value in args))

    def test_unscoped_provider_probe_gets_no_workspace_or_worker_secrets(self):
        policy={'roots':[str(self.projects)],'vault_addr':'https://vault.example.com',
                'vault_cacert':'/public/ca.crt','roles':{'gitlab':{
                    'agent':'claude','manager':False,'auth':str(self.root/'auth'),
                    'network':'fixed-worker-net','image':'sha256:fixed',
                    'vault_secrets':{'GITLAB_TOKEN':'secret/gitlab#token'}}}}
        with patch.object(provider.subprocess,'run',side_effect=AssertionError('No probe Vault read')):
            _,args,env,_,probe=provider.build(policy,'gitlab',['app-server'],{},str(self.projects))
        self.assertTrue(probe)
        self.assertNotIn(str(self.projects)+':'+str(self.projects),args)
        self.assertNotIn('GITLAB_TOKEN',env)
        self.assertNotIn('AGENTBOX_BROKER_TOKEN',env)

    def test_worktree_pointer_cannot_mount_host_secrets(self):
        outside=self.root/'outside';outside.mkdir()
        (self.repo/'.git').write_text('gitdir: '+str(outside))
        with self.assertRaises(ValueError):provider.workspace_mounts(self.repo,[str(self.projects)])


if __name__=='__main__':unittest.main()
