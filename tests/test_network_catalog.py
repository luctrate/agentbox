import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('network_catalog',ROOT/'security/network.py')
network=importlib.util.module_from_spec(spec);spec.loader.exec_module(network)
SNAPSHOT='''*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:DOCKER-USER - [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A FORWARD -j DOCKER-USER
-A DOCKER-USER -s 198.51.100.1 -j RETURN
COMMIT
'''


def policy():
    return {'catalog_revision':'revision-one','listen':'172.29.50.1','port':6768,'deny_public_ips':['203.0.113.1/32'],
        'networks':{'review':{'name':'asp-review','subnet':'172.29.50.0/24','gateway':'172.29.50.1','bridge':'asp-review',
            'mode':'denyAll','allow':[{'cidr':'10.77.0.10/32','protocol':'tcp','ports':[443]}],
            'dns':['1.1.1.1'],'brokerAccess':True}}}


class NetworkCatalogTests(unittest.TestCase):
    def test_internal_model_network_only_opens_gateway_proxy_and_broker(self):
        p=policy();n=p['networks']['review'];n.update(internal=True,dns=[],allow=[],
            httpsProxy={'host':n['gateway'],'port':3128,'caFile':'/etc/agentbox/model-ca.pem','allowedHosts':['api.anthropic.com','chatgpt.com']})
        plan=network.normalized_plan(p);rules=network.render_rules(plan,SNAPSHOT)
        self.assertIn('-d 172.29.50.1 -p tcp --dport 3128 -j ACCEPT',rules)
        self.assertIn('-d 172.29.50.1 -p tcp --dport 6768 -j ACCEPT',rules)
        self.assertNotIn('--dport 53 -j ACCEPT',rules)
        for change in [{'dns':['1.1.1.1']},{'internal':False},{'mode':'publicExceptPrivate'}]:
            wrong=copy.deepcopy(p);wrong['networks']['review'].update(change)
            with self.assertRaises(ValueError):network.normalized_plan(wrong)
    def test_deny_all_has_explicit_services_dns_broker_and_no_unconditional_forward_accept(self):
        plan=network.normalized_plan(policy());rules=network.render_rules(plan,SNAPSHOT)
        self.assertIn('-d 10.77.0.10/32 -p tcp --dport 443 -j ACCEPT',rules)
        self.assertIn('-d 1.1.1.1 -p udp --dport 53 -j ACCEPT',rules)
        self.assertIn('-d 172.29.50.1 -p tcp --dport 6768 -j ACCEPT',rules)
        self.assertIn('-d 172.29.50.0/24 -j REJECT',rules)
        self.assertFalse(any(line.startswith('-A ABX-CF-') and line.endswith(' -j ACCEPT') and '--' not in line for line in rules.splitlines()))
        self.assertNotIn('-F INPUT',rules)
        self.assertNotIn('-F FORWARD',rules)
        self.assertNotIn('-F DOCKER-USER',rules)
        self.assertTrue(rules.startswith('*filter\n'));self.assertTrue(rules.endswith('COMMIT\n'))

    def test_legacy_private_deny_and_public_egress_are_preserved(self):
        p=policy();p['networks']['manager']=p['networks'].pop('review')
        for key in ['mode','allow','dns','brokerAccess']:p['networks']['manager'].pop(key)
        plan=network.normalized_plan(p)
        self.assertEqual(plan['networks']['manager']['mode'],'publicExceptPrivate')
        rules=network.render_rules(plan,SNAPSHOT)
        self.assertIn('-d 169.254.0.0/16 -j REJECT',rules)
        self.assertIn('-d 203.0.113.1/32 -j REJECT',rules)
        self.assertIn('--dport 6768 -j ACCEPT',rules)

    def test_ipv6_overlap_invalid_ports_and_domain_fields_fail_before_external_actions(self):
        bad=[]
        p=policy();p['deny_public_ips']=['2001:db8::/32'];bad.append(p)
        p=policy();p['networks']['review']['allow'][0]['ports']=[True];bad.append(p)
        p=policy();p['networks']['review']['allow'][0]['ports']=[65536];bad.append(p)
        p=policy();p['networks']['review']['allowDomains']=['example.com'];bad.append(p)
        p=policy();p['networks']['review']['dns']=['172.29.50.1'];bad.append(p)
        p=policy();p['networks']['other']=dict(p['networks']['review'],name='other',bridge='other');bad.append(p)
        p=policy();p['networks']['review']['allow'][0]['cidr']='172.29.50.0/24';bad.append(p)
        for value in bad:
            with self.subTest(value=value),patch.object(network,'run') as run:
                with self.assertRaises(ValueError):network.apply(value)
                run.assert_not_called()

    def test_all_existing_networks_are_validated_before_creating_anything(self):
        p=policy();p['networks']['other']=dict(p['networks']['review'],name='other',bridge='other',
            subnet='172.29.51.0/24',gateway='172.29.51.1')
        calls=[]
        def run(args,check=True,**kwargs):
            calls.append(args)
            if args[0]==network._SAVE:return types.SimpleNamespace(stdout=SNAPSHOT,returncode=0)
            if args[:3]==['/usr/bin/docker','network','inspect']:
                if args[-1]=='asp-review':return types.SimpleNamespace(stdout='',returncode=1)
                return types.SimpleNamespace(stdout=json.dumps([{'Driver':'host','IPAM':{'Config':[]}}]),returncode=0)
            return types.SimpleNamespace(stdout='',returncode=0)
        with patch.object(network,'run',side_effect=run):
            with self.assertRaises(ValueError):network.apply(p)
        self.assertFalse(any(args[:3]==['/usr/bin/docker','network','create'] for args in calls))
        self.assertFalse(any(args[0]==network._RESTORE and '--test' not in args for args in calls))

    def test_atomic_restore_failure_keeps_old_readiness_and_rolls_back_new_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready=Path(temporary)/'ready.json';ready.write_text('old revision')
            p=policy();p['network_readiness']={'path':str(ready),'revision':'revision-one'}
            calls=[]
            def run(args,check=True,**kwargs):
                calls.append((args,kwargs))
                if args[0]==network._SAVE:return types.SimpleNamespace(stdout=SNAPSHOT,returncode=0)
                if args[:3]==['/usr/bin/docker','network','inspect']:return types.SimpleNamespace(stdout='',returncode=1)
                if args[0]==network._RESTORE and '--test' not in args:raise subprocess.CalledProcessError(1,args)
                return types.SimpleNamespace(stdout='',returncode=0)
            with patch.object(network,'run',side_effect=run):
                with self.assertRaises(subprocess.CalledProcessError):network.apply(p)
            self.assertEqual(ready.read_text(),'old revision')
            self.assertTrue(any(args[:3]==['/usr/bin/docker','network','rm'] for args,_ in calls))
            self.assertFalse(any(args[0].endswith('/iptables') for args,_ in calls))
            self.assertTrue(all('COMMIT\n' in kwargs['input'] for args,kwargs in calls if args[0]==network._RESTORE))

    def test_success_writes_revision_and_fingerprint_after_atomic_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            p=policy();ready=Path(temporary)/'ready.json';p['network_readiness']={'path':str(ready),'revision':'revision-one'}
            calls=[]
            def run(args,check=True,**kwargs):
                calls.append(args)
                if args[0]==network._SAVE:return types.SimpleNamespace(stdout=SNAPSHOT,returncode=0)
                if args[:3]==['/usr/bin/docker','network','inspect']:return types.SimpleNamespace(stdout='',returncode=1)
                if args[0]==network._RESTORE and '--test' not in args:self.assertFalse(ready.exists())
                return types.SimpleNamespace(stdout='',returncode=0)
            with patch.object(network,'run',side_effect=run):network.apply(p)
            manifest=json.loads(ready.read_text())
            self.assertEqual(manifest['revision'],'revision-one')
            self.assertEqual(manifest['plan_hash'],network.policy_fingerprint(p))
            self.assertEqual(manifest['networks'],['asp-review'])
            creation=next(args for args in calls if args[:3]==['/usr/bin/docker','network','create'])
            self.assertIn('com.docker.network.bridge.enable_icc=false',creation)
            self.assertEqual(len(list(ready.parent.glob('ready.json.*'))),0)


if __name__=='__main__':unittest.main()
