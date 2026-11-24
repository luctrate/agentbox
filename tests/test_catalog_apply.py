import copy
import fcntl
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from subprocess import CompletedProcess
from unittest.mock import patch

from agentbox_config.apply import ApplyError,atomic_json,deploy,digest,reconcile_providers,validate_live_bindings,inspect_images


class ProviderMergeTests(unittest.TestCase):
    def setUp(self):
        self.old={'extends':'codex','command':['/opt/agentbox/security/provider.py','--role','worker'],
                  'env':{'CODEX_HOME':'/private/auth/worker'},'label':'Worker'}
        self.new=copy.deepcopy(self.old)
        self.new['command']=['/opt/agentbox/security/provider.py','--policy','/etc/agentbox/gen/abc/policy.json','--role','worker']
        self.config={'daemon':{'mcp':{'injectIntoAgents':False},'auth':{'password':'fixture-hash'}},
                     'plugins':{'keep':{'enabled':True}},'agents':{'providers':{
                         'claude':{'enabled':True},'codex':{'enabled':True},'worker-box':self.old}}}

    def test_first_adoption_is_explicit_and_preserves_native_auth_plugins_and_mcp(self):
        with self.assertRaises(ApplyError):reconcile_providers(self.config,{'worker-box':self.new})
        updated,changes,hashes=reconcile_providers(self.config,{'worker-box':self.new},adopt_existing=True)
        self.assertEqual(updated['daemon'],self.config['daemon'])
        self.assertEqual(updated['plugins'],self.config['plugins'])
        for native in ['claude','codex']:
            self.assertEqual(updated['agents']['providers'][native],self.config['agents']['providers'][native])
        self.assertEqual(changes['update'],['worker-box'])
        self.assertEqual(hashes['worker-box'],digest(self.new))

    def test_three_way_merge_refuses_unreviewed_changes_even_if_command_matches(self):
        previous={'provider_hashes':{'worker-box':digest(self.old)}}
        modified=copy.deepcopy(self.config)
        modified['agents']['providers']['worker-box']['env']['UNREVIEWED']='value'
        with self.assertRaises(ApplyError):reconcile_providers(modified,{'worker-box':self.new},previous)

    def test_removed_definitions_are_disabled_without_deleting_provider_history_binding(self):
        previous={'provider_hashes':{'worker-box':digest(self.old)}}
        updated,changes,hashes=reconcile_providers(self.config,{},previous)
        item=updated['agents']['providers']['worker-box']
        self.assertFalse(item['enabled'])
        self.assertEqual(item['command'],self.old['command'])
        self.assertEqual(changes['disable'],['worker-box'])
        self.assertIn('worker-box',hashes)

    def test_catalog_cannot_take_over_native_host_providers(self):
        with self.assertRaises(ApplyError):reconcile_providers(self.config,{'claude':self.new})

    def test_previous_manifest_cannot_disable_native_providers(self):
        previous={'provider_hashes':{'claude':digest({'enabled':True})}}
        with self.assertRaises(ApplyError):reconcile_providers(self.config,{},previous)



class FakeCommands:
    def __init__(self):self.calls=[];self.fail_start_once=False;self.active=[]
    def run(self,args,timeout=45,check=True):
        from subprocess import CompletedProcess
        self.calls.append(list(args))
        if args[:2]==['/usr/bin/systemctl','start'] and self.fail_start_once:
            self.fail_start_once=False;raise ApplyError('fixture service activation failed')
        out='\n'.join(self.active) if args[:3]==['/usr/bin/docker','ps','--filter'] else ''
        return CompletedProcess(args,0,out,'')
    def paseo(self,args,timeout=45,check=True):
        from subprocess import CompletedProcess
        self.calls.append(['paseo',*args])
        return CompletedProcess(args,0,'[]' if args[0]=='ls' else '[{"provider":"worker-box","status":"available"}]' if args[:2]==['provider','ls'] else '{}','')


class ImageAuthPreflightTests(unittest.TestCase):
    def test_auth_access_is_checked_as_runtime_user_without_reading_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            image='sha256:'+'a'*64
            policy={'uid':1000,'roles':{'manager':{'image':image,'agent':'claude',
                    'harness_version':'2.1.329','auth':directory}}}
            calls=[]
            class Images:
                def run(self,args,**kwargs):
                    calls.append(args)
                    if args[1:3]==['image','inspect']:output=json.dumps([{'Id':image}])
                    elif args[:2]==['/usr/bin/docker','run']:output=json.dumps({'sudo':False,'versions':{'claude':'2.1.329'}})
                    else:output=''
                    return CompletedProcess(args,0,output,'')
            with patch('agentbox_config.apply.os.geteuid',return_value=0),patch('agentbox_config.apply.pwd.getpwuid',return_value=SimpleNamespace(pw_name='runner')):
                inspect_images(policy,Images())
            probes=[args for args in calls if args[0]=='/usr/sbin/runuser']
            self.assertEqual([args[-2] for args in probes],['-r','-w','-x'])
            self.assertTrue(all(args[-1]==directory for args in probes))

    def test_inaccessible_auth_parent_fails_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            image='sha256:'+'a'*64
            policy={'uid':1000,'roles':{'manager':{'image':image,'agent':'claude',
                    'harness_version':'2.1.329','auth':directory}}}
            class Images:
                def run(self,args,**kwargs):
                    if args[0]=='/usr/sbin/runuser':raise ApplyError('Auth directory cannot be accessed')
                    output=json.dumps([{'Id':image}]) if args[1:3]==['image','inspect'] else json.dumps({'sudo':False,'versions':{'claude':'2.1.329'}})
                    return CompletedProcess(args,0,output,'')
            with patch('agentbox_config.apply.os.geteuid',return_value=0),patch('agentbox_config.apply.pwd.getpwuid',return_value=SimpleNamespace(pw_name='runner')):
                with self.assertRaises(ApplyError):inspect_images(policy,Images())


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.config=self.root/'paseo.json';self.link=self.root/'security.json'
        self.manifest=self.root/'managed.json';self.generations=self.root/'generations'
        self.before={'daemon':{'mcp':{'injectIntoAgents':False}},'agents':{'providers':{'claude':{'enabled':True}}}}
        atomic_json(self.config,self.before);atomic_json(self.link,{'roles':{},'networks':{}})
        self.platform={'host_home':'/home/paseo','uid':1000,'gid':1000,
                       'network_command':['python3','/trusted/network.py']}
        self.compiled={'revision':'abc','runtime_policy':{'roles':{},'networks':{}},
          'providers':{'worker-box':{'extends':'codex','command':['/trusted/provider.py','--policy',
                 str(self.generations/'abc/policy.json'),'--role','worker']}},'normalized_catalog':{}}
        self.commands=FakeCommands()

    def apply(self,**kwargs):
        with patch('agentbox_config.apply.inspect_images',return_value={}):
            return deploy(self.compiled,self.platform,self.config,self.generations,self.link,
                          self.manifest,commands=self.commands,require_root=False,**kwargs)

    def test_success_activates_immutable_generation_and_is_idempotent(self):
        result=self.apply();self.assertTrue(result['changed'])
        self.assertTrue(self.link.is_symlink())
        self.assertEqual(json.loads(self.link.read_text()),self.compiled['runtime_policy'])
        self.assertEqual(json.loads(self.config.read_text())['daemon'],self.before['daemon'])
        calls=len(self.commands.calls)
        self.assertFalse(self.apply()['changed'])
        self.assertEqual(len(self.commands.calls),calls)

    def test_service_failure_restores_previous_regular_policy_and_configuration(self):
        self.commands.fail_start_once=True
        with self.assertRaisesRegex(ApplyError,'previous state restored'):self.apply()
        self.assertFalse(self.link.is_symlink())
        self.assertEqual(json.loads(self.link.read_text()),{'roles':{},'networks':{}})
        self.assertEqual(self.link.stat().st_mode&0o777,0o644)
        self.assertEqual(json.loads(self.config.read_text()),self.before)
        self.assertFalse(self.manifest.exists())
        self.assertTrue(any('--config' in args and 'before-activation/policy.json' in args[-1]
                            for args in self.commands.calls))

    def test_active_managed_session_requires_explicit_drain_before_mutation(self):
        self.commands.active=['11111111-1111-1111-1111-111111111111']
        original=self.config.read_bytes()
        with self.assertRaisesRegex(ApplyError,'explicit --drain'):self.apply()
        self.assertEqual(self.config.read_bytes(),original)
        self.assertFalse(self.generations.exists())

    def test_wrong_generation_path_is_rejected_before_services_stop(self):
        self.compiled['providers']['worker-box']['command'][2]='/wrong/policy.json'
        with self.assertRaises(ApplyError):self.apply()
        self.assertFalse(any(args[0]=='/usr/bin/systemctl' for args in self.commands.calls))

    def test_concurrent_apply_is_rejected_without_service_mutation(self):
        descriptor=(self.root/'.apply.lock').open('w')
        try:
            fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(ApplyError,'already running'):self.apply()
            self.assertFalse(self.commands.calls)
        finally:descriptor.close()

    def test_bad_generation_is_rejected_before_explicit_drain(self):
        self.commands.active=['11111111-1111-1111-1111-111111111111']
        self.compiled['providers']['worker-box']['command'][2]='/wrong/policy.json'
        with self.assertRaises(ApplyError):self.apply(drain=True)
        self.assertFalse(any(args[:2]==['paseo','archive'] for args in self.commands.calls))

    def test_live_auth_symlink_aliases_are_rejected(self):
        projects=self.root/'projects';projects.mkdir()
        auth=self.root/'auth';auth.mkdir()
        alias=self.root/'alias';alias.symlink_to(auth,target_is_directory=True)
        policy={'roots':[str(projects)],'roles':{'first':{'auth':str(auth)},'second':{'auth':str(alias)}}}
        with self.assertRaisesRegex(ApplyError,'Auth directories overlap'):validate_live_bindings(policy)

    def test_live_auth_symlink_cannot_overlay_read_only_workspace(self):
        projects=self.root/'projects';projects.mkdir()
        repo=projects/'repo';repo.mkdir()
        alias=self.root/'alias';alias.symlink_to(repo,target_is_directory=True)
        policy={'roots':[str(projects)],'roles':{'worker':{'auth':str(alias)}}}
        with self.assertRaisesRegex(ApplyError,'overlaps a workspace'):validate_live_bindings(policy)



if __name__=='__main__':unittest.main()
