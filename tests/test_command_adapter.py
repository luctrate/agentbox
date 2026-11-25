"""Transport loss handling and image/runtime admission for command profiles."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

from agentbox_config.apply import ApplyError,inspect_images
from agentbox_config.compiler import compile_catalog
from security import mediation
from test_commands import command_catalog,command_platform

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('command_adapter_fixture',ROOT/'security/mcp.py')
adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)


class CommandAdapterTests(unittest.TestCase):
    def test_lost_submission_returns_its_exact_generated_idempotency_key(self):
        calls=[]
        def call(operation,data):
            calls.append((operation,dict(data)))
            if operation=='command-tools':return {'tools':['run_command']}
            raise TimeoutError('fixture network drop')
        with patch.object(adapter,'call',side_effect=call):
            value=adapter.perform({'method':'tools/call','params':{'name':'run_command','arguments':{'argv':['/usr/bin/printf','fixture']}}})
        receipt=json.loads(value['content'][0]['text'])
        self.assertTrue(value['isError']);self.assertEqual(receipt['status'],'delivery_unconfirmed')
        self.assertEqual(str(uuid.UUID(receipt['requestId'])),receipt['requestId'])
        self.assertEqual(calls[-1][1]['requestId'],receipt['requestId'])
        self.assertEqual(sum(operation=='command' for operation,data in calls),1)

    def test_review_adapter_lists_only_assigned_review_tools_and_rejects_exec(self):
        with patch.object(adapter,'call',return_value={'tools':['review_request','decide_command']}) as call:
            tools=adapter.perform({'method':'tools/list'})['tools']
            self.assertEqual([tool['name'] for tool in tools],['review_request','decide_command'])
            self.assertFalse(tools[1]['inputSchema']['additionalProperties'])
            with self.assertRaises(ValueError):adapter.perform({'method':'tools/call','params':{'name':'run_command','arguments':{'argv':['/bin/sh']}}})
            self.assertTrue(all(c.args[0]=='command-tools' for c in call.call_args_list))

    def test_lost_decision_instructs_authoritative_status_check(self):
        def call(operation,data):
            if operation=='command-tools':return {'tools':['decide_command']}
            raise TimeoutError()
        with patch.object(adapter,'call',side_effect=call):
            result=adapter.perform({'method':'tools/call','params':{'name':'decide_command','arguments':{
                'id':'00000000-0000-4000-8000-000000000001','fingerprint':'fixture','decision':'allow','reason':'fixture'}}})
        receipt=json.loads(result['content'][0]['text'])
        self.assertIn('review_request',receipt['instruction']);self.assertEqual(receipt['id'],'00000000-0000-4000-8000-000000000001')

    def test_runtime_admission_rejects_mutable_or_privileged_controlled_roles(self):
        role=compile_catalog(command_catalog(),command_platform())['runtime_policy']['roles']['worker-a']
        mediation.validate_role(role)
        for field,value in [('auth_storage','persistent'),('read_only_root',False),('sudo',True),
                            ('no_new_privileges',False),('drop_capabilities',[]),('harness_version','0.0.0')]:
            changed=dict(role,**{field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):mediation.validate_role(changed)

    def test_operator_rejects_an_image_without_the_gateway(self):
        with tempfile.TemporaryDirectory() as temporary:
            policy=compile_catalog(command_catalog(),command_platform())['runtime_policy']
            role=policy['roles']['worker-a'];role['auth']=temporary;policy['roles']={'worker-a':role}
            class Commands:
                def run(self,args,**kwargs):
                    if args[:3]==['/usr/bin/docker','image','inspect']:
                        return types.SimpleNamespace(stdout=json.dumps([{'Id':role['image']}]))
                    return types.SimpleNamespace(stdout=json.dumps({'sudo':False,'bootstrap':True,'broker_client':True,
                        'command_gateway':False,'versions':{'claude':'2.1.329','codex':'0.171.0'}}))
            with patch('agentbox_config.apply.os.geteuid',return_value=1000):
                with self.assertRaisesRegex(ApplyError,'image-baked command adapter'):inspect_images(policy,Commands())


if __name__=='__main__':unittest.main()
