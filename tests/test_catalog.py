import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentbox_config.compiler import compile_catalog
from agentbox_config.loader import CatalogError, load_catalog, loads_catalog
from agentbox_config.model import validate_catalog

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'sha256:' + 'a' * 64


def definition(ident='worker-a', role='worker', engine='claude'):
    return {'id': ident, 'name': ident.title(), 'role': role,
            'image': {'ref': IMAGE},
            'harness': {'name': engine, 'version': '2.1.329' if engine == 'claude' else '0.171.0',
                        'authRef': ident}, 'networkPolicyRef': 'worker-net'}


def catalog():
    manager = definition('manager-a', 'manager', 'codex')
    manager.update({'networkPolicyRef': 'manager-net', 'tools': {'launchAgent': {'allowedWorkers': ['worker-a']}}})
    return {'apiVersion': 'asp.now/v1alpha1', 'kind': 'AgentCatalog',
            'agents': [manager, definition()],
            'networkPolicies': {'manager-net': {'mode': 'publicExceptPrivate', 'brokerAccess': True},
                                'worker-net': {'mode': 'publicExceptPrivate'}}}


def platform():
    return {'host_home': '/home/paseo', 'uid': 1000, 'gid': 1000,
            'roots': ['/srv/projects', '/srv/worktrees'],
            'provider_command': '/opt/asp/security/provider.py',
            'policy_path': '/etc/asp/generations/placeholder/policy.json',
            'authRefs': {'manager-a': '/srv/auth/manager-a', 'worker-a': '/srv/auth/worker-a'},
            'networkBindings': {
                'manager-net': {'name': 'asp-manager', 'subnet': '172.30.10.0/24',
                                'gateway': '172.30.10.1', 'bridge': 'asp-manager'},
                'worker-net': {'name': 'asp-worker', 'subnet': '172.30.11.0/24',
                               'gateway': '172.30.11.1', 'bridge': 'asp-worker'}},
            'network_readiness': {'path': '/run/asp/ready.json'}}


class CatalogTests(unittest.TestCase):
    def test_example_loads_and_compiles_without_docker_network_or_secret_reads(self):
        document = load_catalog(ROOT/'examples/catalog.yaml')
        bindings = json.loads((ROOT/'examples/platform.json').read_text())
        with patch('subprocess.run', side_effect=AssertionError('No subprocess in compiler')):
            with patch('socket.getaddrinfo', side_effect=AssertionError('No DNS in compiler')):
                compiled = compile_catalog(document, bindings)
        self.assertEqual(len(compiled['providers']), 5)
        self.assertNotIn('claude', compiled['managed_provider_ids'])
        self.assertNotIn('codex', compiled['managed_provider_ids'])
        self.assertEqual(compiled['runtime_policy']['roles']['gitlab']['vault_secrets'],
                         {'GITLAB_TOKEN': 'kv/agents/gitlab#token'})
        self.assertEqual(compiled['providers']['manager-codex']['label'], 'Managers Codex')
        self.assertEqual(compiled['providers']['codex-box']['extends'], 'codex')

    def test_yaml_rejects_duplicate_keys_aliases_tags_and_multiple_documents(self):
        for text in ['kind: AgentCatalog\nkind: Other\n',
                     'a: &anchor [one]\nb: *anchor\n',
                     'a: !!python/object/apply:os.system [echo bad]\n',
                     'a: !!str safe\n', '---\na: 1\n---\nb: 2\n',
                     'a: {<<: {x: 1}}\n']:
            with self.subTest(text=text):
                with self.assertRaises(CatalogError):loads_catalog(text)

    def test_yaml_is_bounded_and_errors_do_not_echo_secret_values(self):
        secret = 'do-not-echo-this-value'
        with self.assertRaises(CatalogError) as error:
            loads_catalog('a: [' + secret)
        self.assertNotIn(secret, str(error.exception))
        with self.assertRaises(CatalogError):loads_catalog('x: '+ 'a' * (1024*1024))
        with self.assertRaises(CatalogError):loads_catalog('x: '+ '[' * 40 + '1' + ']' * 40)

    def test_unknown_keys_and_wrong_version_or_types_are_rejected(self):
        for mutation in [lambda c: c.update({'apiVersion': 'asp.now/v9'}),
                         lambda c: c.update({'unexpected': True}),
                         lambda c: c['agents'][0].update({'dockerExtra': ['--privileged']}),
                         lambda c: c['agents'][0].update({'enabled': 'false'})]:
            value = catalog();mutation(value)
            with self.assertRaises(CatalogError):validate_catalog(value)

    def test_duplicate_ids_missing_references_and_disabled_targets_are_rejected(self):
        values=[]
        value=catalog();value['agents'].append(copy.deepcopy(value['agents'][1]));values.append(value)
        value=catalog();value['agents'][0]['networkPolicyRef']='missing';values.append(value)
        value=catalog();value['agents'][0]['tools']['launchAgent']['allowedWorkers']=['missing'];values.append(value)
        value=catalog();value['agents'][1]['enabled']=False;values.append(value)
        for value in values:
            with self.assertRaises(CatalogError):validate_catalog(value)

    def test_defaults_replace_permission_lists_instead_of_unioning_them(self):
        value=catalog();second=definition('worker-b')
        second['tools']={'launchAgent': {'allowedWorkers': []}}
        value['agents'][1]['tools']={'launchAgent': {'allowedWorkers': []}}
        value['agents'].append(second)
        value['defaults']={'tools': {'launchAgent': {'allowedWorkers': ['worker-a','worker-b']}}}
        normalized=validate_catalog(value)
        self.assertEqual(normalized['agents'][0]['tools']['launchAgent']['allowedWorkers'],['worker-a'])
        self.assertEqual(normalized['agents'][1]['tools']['launchAgent']['allowedWorkers'],[])
        self.assertEqual(value['defaults']['tools']['launchAgent']['allowedWorkers'],['worker-a','worker-b'])

    def test_unimplemented_security_modes_are_rejected(self):
        mutations=[lambda c:c['agents'][0].update({'tools': {'cli': {'mode': 'mediated'}}}),
                   lambda c:c['agents'][0].update({'tools': {'cli': {'mode': 'disabled'}}}),
                   lambda c:c['agents'][0].update({'tools': {'mcp': [{'serverRef': 'docs'}]}}),
                   lambda c:c['agents'][0]['tools']['launchAgent'].update({'interfaces':['cli','mcp']}),
                   lambda c:c['agents'][0].update({'workspace':{'source':'ephemeral'}}),
                   lambda c:c['agents'][0].update({'role':'approver'})]
        for mutate in mutations:
            value=catalog();mutate(value)
            with self.assertRaises(CatalogError):validate_catalog(value)

    def test_bounded_worker_delegation_and_unshared_ephemeral_auth(self):
        value=catalog();research=definition('research');research.update({'workspace':{'source':'none','access':'none'}})
        research['harness']['authStorage']='ephemeral'
        value['agents'].append(research)
        value['agents'][1].update({'networkPolicyRef':'manager-net','tools':{'launchAgent':{'allowedWorkers':['research']}}})
        value['agents'][0]['tools']['launchAgent']['maxDepth']=2
        normalized=validate_catalog(value)
        self.assertEqual(normalized['agents'][2]['workspace']['access'],'none')
        value['agents'][0]['tools']['launchAgent']['maxDepth']=1
        with self.assertRaises(CatalogError):validate_catalog(value)
        value['agents'][0]['tools']['launchAgent']['maxDepth']=2
        value['agents'][2]['networkPolicyRef']='manager-net'
        value['agents'][2]['tools']={'launchAgent':{'allowedWorkers':['worker-a']}}
        with self.assertRaises(CatalogError):validate_catalog(value)

    def test_unshared_agents_cannot_keep_auth_mounts_or_receive_tool_secrets(self):
        value=catalog();agent=value['agents'][1]
        agent['workspace']={'source':'none','access':'none'}
        with self.assertRaises(CatalogError):validate_catalog(value)
        agent['harness']['authStorage']='ephemeral'
        agent['vaultPathToEnv']=[{'vaultPath':'kv/test','field':'token','env':'GITLAB_TOKEN'}]
        with self.assertRaises(CatalogError):validate_catalog(value)

    def test_immutable_images_and_resource_privilege_consistency(self):
        mutations=[lambda c:c['agents'][0].update({'image':{'ref':'example/base:latest'}}),
                   lambda c:c['agents'][0].update({'execution':{'resources':{'memory':'1m'}}}),
                   lambda c:c['agents'][0].update({'execution':{'resources':{'cpu':True}}}),
                   lambda c:c['agents'][0].update({'execution':{'allowPrivilegeEscalation':True}})]
        for mutate in mutations:
            value=catalog();mutate(value)
            with self.assertRaises(CatalogError):validate_catalog(value)
        value=catalog();value['agents'][1].update({'execution':{
            'allowPrivilegeEscalation':True,'capabilities':{'drop':[]}},
            'image':{'ref':IMAGE,'expectedCapabilities':{'sudo':'available'}}})
        role=compile_catalog(value,platform())['runtime_policy']['roles']['worker-a']
        self.assertTrue(role['sudo']);self.assertFalse(role['no_new_privileges'])

    def test_vault_and_static_env_reject_host_control_variables_and_collisions(self):
        names=['LD_PRELOAD','LD_LIBRARY_PATH','DOCKER_HOST','DOCKER_CONTEXT','PATH','HOME',
               'PYTHONPATH','AGENTBOX_ROOT','PASEO_PASSWORD','ASP_TOKEN','VAULT_TOKEN',
               'HTTP_PROXY','NODE_EXTRA_CA_CERTS','CLAUDE_CONFIG_DIR','CODEX_HOME','GIT_CONFIG_COUNT']
        for key in names:
            for field in ['vaultPathToEnv','staticEnv']:
                value=catalog()
                value['agents'][1][field]=([{'vaultPath':'kv/tools/gitlab','field':'token','env':key}]
                                          if field=='vaultPathToEnv' else {key:'untrusted'})
                with self.subTest(key=key,field=field):
                    with self.assertRaises(CatalogError):validate_catalog(value)
        value=catalog();value['agents'][1]['staticEnv']={'GITLAB_TOKEN':'not-a-real-token'}
        value['agents'][1]['vaultPathToEnv']=[{'vaultPath':'kv/gitlab','field':'token','env':'GITLAB_TOKEN'}]
        with self.assertRaises(CatalogError):validate_catalog(value)

    def test_network_rules_are_ipv4_and_ports_only_no_unsupported_domains(self):
        mutations=[lambda n:n.update({'dns':['::1']}),
                   lambda n:n.update({'allow':[{'cidr':'fd00::/8','protocol':'tcp','ports':[443]}]}),
                   lambda n:n.update({'allow':[{'cidr':'10.0.0.0/8','protocol':'tcp','ports':[]}]}),
                   lambda n:n.update({'allow':[{'cidr':'10.0.0.0/8','protocol':'tcp','ports':[70000]}]}),
                   lambda n:n.update({'allowDomains':['api.example.com']})]
        for mutate in mutations:
            value=catalog();mutate(value['networkPolicies']['worker-net'])
            with self.assertRaises(CatalogError):validate_catalog(value)

    def test_native_provider_ids_are_never_managed_or_delegated(self):
        value=catalog();value['agents'][1]['id']='claude';value['agents'][1]['harness']['authRef']='worker-a'
        value['agents'][0]['tools']['launchAgent']['allowedWorkers']=['claude']
        with self.assertRaises(CatalogError):compile_catalog(value,platform())
        bindings=platform();bindings['providerBindings']={'claude':'claude-box'}
        compiled=compile_catalog(value,bindings)
        self.assertEqual(compiled['runtime_policy']['roles']['claude']['provider_id'],'claude-box')
        self.assertNotIn('claude',compiled['providers'])

    def test_provider_model_and_whitespace_cannot_bypass_native_target_rejection(self):
        for target in ['claude/model', 'codex/model', 'codex other', 'claude\n', 'copilot', 'omp']:
            bindings=platform();bindings['providerBindings']={'worker-a':target}
            with self.subTest(target=target):
                with self.assertRaises(CatalogError):compile_catalog(catalog(),bindings)

    def test_revision_is_deterministic_and_not_circular_with_generation_paths(self):
        value=catalog();bindings=platform();before=copy.deepcopy(bindings)
        first=compile_catalog(value,bindings)
        bindings['policy_path']='/etc/asp/generations/'+first['revision']+'/policy.json'
        bindings['network_readiness']['path']='/run/asp/other-ready.json'
        second=compile_catalog(value,bindings)
        self.assertEqual(first['revision'],second['revision'])
        self.assertNotEqual(first['providers']['manager-a']['command'],second['providers']['manager-a']['command'])
        self.assertNotIn('policy_path',second['runtime_policy'])
        self.assertEqual(first['runtime_policy']['network_readiness']['revision'],first['revision'])
        self.assertEqual(before,platform())
        value['agents'][0]['tools']['launchAgent']['allowedWorkers']=[]
        self.assertNotEqual(first['revision'],compile_catalog(value,bindings)['revision'])

    def test_validation_bounds_match_runtime_and_network_enforcement(self):
        value=catalog();value['agents'][0]['execution']={'resources':{'cpu':64,'pids':32768}}
        self.assertEqual(compile_catalog(value,platform())['runtime_policy']['roles']['manager-a']['pids'],32768)
        for key,amount in [('cpu',65),('pids',32769)]:
            value=catalog();value['agents'][0]['execution']={'resources':{key:amount}}
            with self.assertRaises(CatalogError):compile_catalog(value,platform())
        bindings=platform();bindings['networkBindings']['worker-net'].update({'subnet':'10.0.0.0/15','gateway':'10.0.0.1'})
        with self.assertRaises(CatalogError):compile_catalog(catalog(),bindings)
        value=catalog();value['networkPolicies']['worker-net']['dns']=['127.0.0.1']
        with self.assertRaises(CatalogError):compile_catalog(value,platform())
        value=catalog();value['networkPolicies']['worker-net']['allow']=[{'cidr':'172.30.10.0/24','protocol':'tcp','ports':[443]}]
        with self.assertRaises(CatalogError):compile_catalog(value,platform())
        bindings=platform();bindings.pop('network_readiness')
        with self.assertRaises(CatalogError):compile_catalog(catalog(),bindings)

    def test_definitions_cannot_share_or_nest_writable_auth_history_mounts(self):
        for value in ['/srv/auth/manager-a','/srv/auth/manager-a/worker','/srv/auth']:
            bindings=platform();bindings['authRefs']['worker-a']=value
            with self.assertRaises(CatalogError):compile_catalog(catalog(),bindings)

    def test_platform_paths_cannot_overlay_workspace_mounts_or_expose_trusted_code(self):
        mutations=[lambda p:p.update({'roots':['/']}),
                   lambda p:p.update({'uid':0}), lambda p:p.update({'uid':True}),
                   lambda p:p.update({'gid':'1000'}),
                   lambda p:p['authRefs'].update({'worker-a':'/srv/projects/auth'}),
                   lambda p:p['authRefs'].update({'worker-a':'/srv'}),
                   lambda p:p.update({'provider_command':'/srv/projects/launcher.py'}),
                   lambda p:p.update({'provider_command':['/usr/bin/python3','/srv/projects/launcher.py']}),
                   lambda p:p.update({'policy_path':'/srv/projects/policy.json'}),
                   lambda p:p.update({'control_socket':'/srv/projects/control.sock'}),
                   lambda p:p.update({'state':'/srv/projects/state.json'}),
                   lambda p:p.update({'client':'/srv/projects/client.py'}),
                   lambda p:p.update({'network_readiness':{'path':'/srv/projects/ready.json'}})]
        for mutate in mutations:
            bindings=platform();mutate(bindings)
            with self.assertRaises(CatalogError):compile_catalog(catalog(),bindings)

    def test_missing_or_overlapping_platform_bindings_fail_before_apply(self):
        mutations=[lambda p:p['authRefs'].pop('worker-a'),
                   lambda p:p['authRefs'].update({'worker-a':'relative/path'}),
                   lambda p:p['networkBindings']['worker-net'].update({'subnet':'172.30.10.0/24','gateway':'172.30.10.2'}),
                   lambda p:p['networkBindings']['worker-net'].update({'bridge':'asp-manager'}),
                   lambda p:p.update({'providerBindings':{'worker-a':'manager-a'}})]
        for mutate in mutations:
            bindings=platform();mutate(bindings)
            with self.assertRaises(CatalogError):compile_catalog(catalog(),bindings)


if __name__=='__main__':unittest.main()
