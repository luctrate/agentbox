import importlib.util
import json
from pathlib import Path
import subprocess
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('catalog_broker',ROOT/'security/broker.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class Backend:
    def __init__(self):
        self.records={};self.calls=[];self.creations=0
        self.timeout_once=False;self.find_enabled=True;self.offline=False
        self.after_create=None;self.lock=threading.Lock()
    def call(self,args,owner):
        self.calls.append((args,dict(owner)))
        if self.offline:raise OSError('fixture backend unavailable')
        if args[0]=='run':
            with self.lock:
                ident=str(uuid.uuid4());self.creations+=1
                self.records[ident]={'Id':ident,'ParentAgentId':owner['id'],
                    'Provider':args[args.index('--provider')+1],
                    'Name':args[args.index('--title')+1],
                    'Labels':dict([args[index+1].split('=',1) for index,value in enumerate(args) if value=='--label']),
                    'Cwd':owner['cwd'],'Archived':False,'Status':'idle'}
            if self.after_create:self.after_create()
            if self.timeout_once:
                self.timeout_once=False;raise subprocess.TimeoutExpired('fixture Paseo',45)
            return {'agentId':ident,'status':'running'}
        if args[0]=='archive':
            self.records[args[1]]['Archived']=True
            return {'agentId':args[1],'status':'archived'}
        if args[0]=='stop':return {'agentId':args[1],'status':'idle'}
        if args[0]=='logs':return {'agentId':args[1],'items':[]}
        raise AssertionError(args)
    def inspect(self,child,owner):
        if self.offline:raise OSError('fixture backend unavailable')
        record=self.records.get(child)
        return dict(record) if record else None
    def find_launch(self,launch_id,owner):
        if self.offline:raise OSError('fixture backend unavailable')
        if not self.find_enabled:return []
        return [ident for ident,row in self.records.items() if row.get('Labels',{}).get('asp.now.launch')==launch_id]
    def messaging(self,operation,data,owner,launch):
        self.calls.append(([operation,dict(data)],dict(owner)))
        return {'agentId':data['id'],'status':'answered' if operation=='answer' else 'sent'}


class CatalogBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.projects=self.root/'projects'
        self.cwd=self.projects/'demo';self.cwd.mkdir(parents=True)
        self.policy={'catalog_revision':'revision-one','roles':{
            'manager':{'definition_id':'manager','provider_id':'manager-codex','revision':'revision-one',
                       'delegation':{'allowed_workers':['codex'],'max_concurrent':2,'max_depth':1}},
            'other-manager':{'definition_id':'other-manager','provider_id':'manager-claude','revision':'revision-one',
                       'delegation':{'allowed_workers':['claude'],'max_concurrent':1,'max_depth':1}},
            'codex':{'definition_id':'codex','provider_id':'codex-box','revision':'revision-one','delegation':{'allowed_workers':[]}},
            'claude':{'definition_id':'claude','provider_id':'claude-box','revision':'revision-one','delegation':{'allowed_workers':[]}},
        }}
        self.backend=Backend();self.state=self.root/'state.sqlite3'
        self.b=module.Broker(self.state,[self.projects],self.backend,limit=2,policy=self.policy)
        self.owner=str(uuid.uuid4());self.token=self.register(self.owner)
    def register(self,owner,definition='manager',**changes):
        request={'id':owner,'cwd':str(self.cwd),'workspace':'wks_fixture',
                 'definition_id':definition,'catalog_revision':self.policy['catalog_revision']}
        request.update(changes)
        return self.b.register(request)['token']
    def spawn(self,token=None,profile='codex',task='fixture task',request_id=None):
        data={'profile':profile,'task':task}
        if request_id:data['requestId']=request_id
        return self.b.handle(token or self.token,'spawn',data)

    def test_allowlist_is_definition_specific_and_native_definition_names_are_safe(self):
        self.assertEqual(self.b.handle(self.token,'profiles',{})['profiles'],['codex'])
        with self.assertRaises(module.Denied):self.spawn(profile='claude')
        other=self.register(str(uuid.uuid4()),'other-manager')
        child=self.spawn(other,'claude')['agentId']
        self.assertEqual(self.backend.records[child]['Provider'],'claude-box')
        with self.assertRaises(module.Denied):self.spawn(profile='manager')

    def test_owned_followup_is_idempotent_and_does_not_change_worker_configuration(self):
        child=self.spawn()['agentId'];request=str(uuid.uuid4())
        data={'id':child,'message':'--provider claude; $(curl example.invalid)','requestId':request}
        first=self.b.handle(self.token,'send',data)
        self.assertEqual(first,self.b.handle(self.token,'send',data))
        sent=[entry for entry in self.backend.calls if entry[0][0]=='send']
        self.assertEqual(len(sent),1);self.assertEqual(sent[0][0][1],data)
        self.assertEqual(sent[0][1]['id'],self.owner)
        with self.assertRaises(module.Denied):self.b.handle(self.token,'send',dict(data,message='different'))

    def test_messaging_ownership_and_revocation_checked_before_backend(self):
        child=self.spawn()['agentId'];other=self.register(str(uuid.uuid4()),'other-manager')
        for operation,extra in [('send',{'message':'hello'}),('questions',{}),
                                 ('answer',{'questionId':'question-1','answers':{'Color':'blue'}})]:
            with self.subTest(operation=operation):
                before=len(self.backend.calls)
                with patch.object(self.backend,'inspect',side_effect=AssertionError('Must authorize first')):
                    with self.assertRaises(module.Denied):self.b.handle(other,operation,dict(id=child,**extra))
                self.assertEqual(len(self.backend.calls),before)
        self.b.revoke(self.token)
        with self.assertRaises(module.Denied):self.b.handle(self.token,'send',{'id':child,'message':'hello'})

    def test_messaging_rejects_identity_changes_and_archived_or_missing_workers(self):
        child=self.spawn()['agentId'];original=dict(self.backend.records[child])
        for field,value in [('Provider','codex'),('ParentAgentId',str(uuid.uuid4())),('Cwd',str(self.root)),('Archived',True)]:
            self.backend.records[child]=dict(original,**{field:value})
            with self.subTest(field=field),self.assertRaises((module.Denied,module.BackendFailure)):
                self.b.handle(self.token,'send',{'id':child,'message':'hello'})
        del self.backend.records[child]
        with self.assertRaises(module.BackendFailure):self.b.handle(self.token,'send',{'id':child,'message':'hello'})
        self.assertFalse(any(entry[0][0]=='send' for entry in self.backend.calls))

    def test_messaging_cannot_supply_permission_behavior_or_arbitrary_inputs(self):
        child=self.spawn()['agentId']
        for extra in ['provider','env','cwd','behavior','input','all','command']:
            with self.subTest(extra=extra),self.assertRaises(module.Denied):
                self.b.handle(self.token,'answer',{'id':child,'questionId':'q1','answers':{'Color':'blue'},extra:'bad'})
        for message in ['', ' ',None,[], 'x'*50001, 'hello\0world']:
            with self.assertRaises(module.Denied):self.b.handle(self.token,'send',{'id':child,'message':message})
        for answers in [{},[],{'Color':[]},{'Color':' '},{'Color':'x\0y'}]:
            with self.assertRaises(module.Denied):self.b.handle(self.token,'answer',{'id':child,'questionId':'q1','answers':answers})

    def test_delivery_timeout_and_restart_never_blindly_resend(self):
        child=self.spawn()['agentId'];data={'id':child,'message':'hello','requestId':str(uuid.uuid4())}
        with patch.object(self.backend,'messaging',side_effect=subprocess.TimeoutExpired('fixture',30)) as sender:
            first=self.b.handle(self.token,'send',data)
            self.assertEqual(first['status'],'delivery_unconfirmed')
            self.assertEqual(first,self.b.handle(self.token,'send',data));sender.assert_called_once()
        restored=module.Broker(self.state,[self.projects],self.backend,policy=self.policy)
        with patch.object(self.backend,'messaging',side_effect=AssertionError('Must not resend')):
            self.assertEqual(first,restored.handle(self.token,'send',data))

    def test_rejected_question_answer_is_not_reexecuted(self):
        child=self.spawn()['agentId'];data={'id':child,'questionId':'q1','answers':{'Color':'blue'},'requestId':str(uuid.uuid4())}
        with patch.object(self.backend,'messaging',side_effect=module.Denied('Not a question')) as sender:
            for _ in range(2):
                with self.assertRaises(module.Denied):self.b.handle(self.token,'answer',data)
            sender.assert_called_once()

    def test_registration_requires_definition_revision_and_no_permission_fields(self):
        for changes in [{'catalog_revision':'old'}, {'definition_id':'codex'}, {'allowed_workers':['claude']}, {'definition_id':'missing'}]:
            with self.assertRaises(module.Denied):self.register(str(uuid.uuid4()),**changes)
        with self.assertRaises(module.Denied):self.b.register({'id':str(uuid.uuid4()),'cwd':str(self.cwd)})

    def test_native_provider_and_nested_delegation_rejected(self):
        policy=json.loads(json.dumps(self.policy));policy['roles']['codex']['provider_id']='codex'
        with self.assertRaises(ValueError):module.Broker(self.root/'bad.sqlite',[self.projects],self.backend,policy=policy)
        policy=json.loads(json.dumps(self.policy));policy['roles']['codex']['delegation']={'allowed_workers':['claude'],'max_depth':1,'max_concurrent':1}
        with self.assertRaises(ValueError):module.Broker(self.root/'nested.sqlite',[self.projects],self.backend,policy=policy)

    def nested(self):
        self.policy['roles']['manager']['delegation']['max_depth']=2
        self.policy['roles']['codex']['delegation']={'allowed_workers':['research'],'max_concurrent':2,'max_depth':1}
        self.policy['roles']['research']={'definition_id':'research','provider_id':'research-box','delegation':{'allowed_workers':[]}}
        self.b=module.Broker(self.root/'nested-valid.sqlite',[self.projects],self.backend,limit=8,policy=self.policy)
        self.token=self.register(self.owner);registered={}
        def early_registration():
            ident=list(self.backend.records)[-1];record=self.backend.records[ident]
            with patch.object(self.backend,'inspect',side_effect=AssertionError('Paseo has not published this child yet')):
                registered['token']=self.b.register({'id':ident,'cwd':str(self.cwd),'workspace':'wks_fixture',
                    'definition_id':'codex','catalog_revision':self.policy['catalog_revision'],
                    'launch_id':record['Labels']['asp.now.launch']})['token']
        self.backend.after_create=early_registration
        child=self.spawn()['agentId'];self.backend.after_create=None
        return child,registered['token']

    def test_nested_worker_can_launch_only_its_research_allowlist(self):
        child,token=self.nested();claims=self.b.authenticate(token)
        self.assertEqual(claims['max_depth'],1);self.assertEqual(claims['allowed_workers'],['research'])
        research=self.spawn(token,profile='research')['agentId']
        self.assertEqual(self.backend.records[research]['ParentAgentId'],child)
        with self.assertRaises(module.Denied):self.spawn(token,profile='codex')
        with self.assertRaises(module.Denied):self.b.handle(self.token,'logs',{'id':research})
        with self.assertRaises(module.Denied):self.register(child,definition='codex')
        self.b.revoke(self.token)
        with self.assertRaises(module.Denied):self.b.authenticate(token)

    def test_parent_runtime_replacement_invalidates_descendant_capability(self):
        _,token=self.nested();self.register(self.owner)
        with self.assertRaises(module.Denied):self.b.handle(token,'profiles',{})

    def test_provider_model_shortcuts_whitespace_and_native_aliases_are_rejected(self):
        for index,value in enumerate(['codex/model','claude/model',' claude','codex ','copilot','omp']):
            policy=json.loads(json.dumps(self.policy));policy['roles']['codex']['provider_id']=value
            with self.subTest(provider=value),self.assertRaises(ValueError):
                module.Broker(self.root/('unsafe-'+str(index)+'.sqlite'),[self.projects],self.backend,policy=policy)

    def test_runtime_generation_replaces_token_and_claims_are_snapshots(self):
        claims=self.b.authenticate(self.token)
        replacement=self.register(self.owner)
        with self.assertRaises(module.Denied):self.b.authenticate(self.token)
        self.assertEqual(claims['generation'],1)
        self.assertEqual(self.b.authenticate(replacement)['generation'],2)
        self.assertEqual(claims['allowed_workers'],['codex'])

    def test_cross_manager_ownership_and_session_definition_are_stable(self):
        child=self.spawn()['agentId'];other=self.register(str(uuid.uuid4()),'other-manager')
        for operation in ['status','logs','stop','archive']:
            with self.assertRaises(module.Denied):self.b.handle(other,operation,{'id':child})
        with self.assertRaises(module.Denied):self.register(self.owner,'other-manager')
        with self.assertRaises(module.Denied):self.register(child)

    def test_idempotent_retry_does_not_create_second_worker(self):
        request=str(uuid.uuid4())
        first=self.spawn(request_id=request);second=self.spawn(request_id=request)
        self.assertEqual(first,second);self.assertEqual(self.backend.creations,1)
        with self.assertRaises(module.Denied):self.spawn(task='different task',request_id=request)

    def test_timeout_after_creation_remains_reserved_then_reconciles_without_duplicate(self):
        self.backend.timeout_once=True;self.backend.find_enabled=False
        request=str(uuid.uuid4());first=self.spawn(request_id=request)
        self.assertEqual(first['status'],'pending_reconciliation')
        second=self.spawn(request_id=request)
        self.assertEqual(second['status'],'pending_reconciliation');self.assertEqual(self.backend.creations,1)
        self.b.limit=1
        with self.assertRaises(module.Denied):self.spawn(task='another task')
        restored=module.Broker(self.state,[self.projects],self.backend,limit=1,policy=self.policy)
        self.backend.find_enabled=True
        result=restored.handle(self.token,'spawn',{'profile':'codex','task':'fixture task','requestId':request})
        self.assertEqual(self.backend.creations,1);self.assertIn('agentId',result)
        self.assertEqual(restored.handle(self.token,'status',{'id':result['agentId']})['ParentAgentId'],self.owner)

    def test_failure_recording_created_worker_is_recovered_by_request_identity(self):
        request=str(uuid.uuid4())
        with patch.object(self.b,'_adopt',side_effect=OSError('fixture storage interruption')):
            first=self.spawn(request_id=request)
        self.assertEqual(first['status'],'pending_reconciliation')
        result=self.spawn(request_id=request)
        self.assertIn('agentId',result);self.assertEqual(self.backend.creations,1)

    def test_crash_with_reserved_intent_is_reconciled_on_restart(self):
        request=str(uuid.uuid4())
        self.backend.timeout_once=True;self.backend.find_enabled=False
        self.spawn(request_id=request)
        self.b.db.execute("UPDATE launches SET state='reserved'")
        self.backend.find_enabled=True
        restored=module.Broker(self.state,[self.projects],self.backend,policy=self.policy)
        result=restored.handle(self.token,'spawn',{'profile':'codex','task':'fixture task','requestId':request})
        self.assertIn('agentId',result);self.assertEqual(self.backend.creations,1)

    def test_confirmed_missing_known_ambiguous_child_releases_reservation_without_relaunch(self):
        request=str(uuid.uuid4())
        with patch.object(self.b,'_adopt',side_effect=OSError('fixture interruption')):
            pending=self.spawn(request_id=request)
        self.backend.records.clear()
        result=self.spawn(request_id=request)
        self.assertEqual(result['status'],'failed')
        self.assertEqual(self.backend.creations,1)
        self.b.limit=1
        self.assertIn('agentId',self.spawn(task='new authorized request'))

    def test_external_archive_and_confirmed_delete_release_quota_but_outage_does_not(self):
        self.b.limit=1
        child=self.spawn()['agentId']
        self.backend.offline=True
        with self.assertRaises(module.Denied):self.spawn(task='blocked')
        self.backend.offline=False;self.backend.records[child]['Archived']=True
        second=self.spawn(task='second')['agentId']
        del self.backend.records[second]
        self.assertIn('agentId',self.spawn(task='third'))

    def test_revocation_during_launch_tracks_and_archives_created_worker(self):
        self.backend.after_create=lambda:self.b.revoke(self.token)
        with self.assertRaises(module.Denied):self.spawn()
        self.assertEqual(len(self.backend.records),1)
        self.assertTrue(next(iter(self.backend.records.values()))['Archived'])
        self.assertTrue(all(self.b.data['owners'][self.owner]['children'].values()))

    def test_archive_is_idempotent_when_another_actor_already_archived_worker(self):
        self.b.limit=1;child=self.spawn()['agentId']
        self.backend.records[child]['Archived']=True
        with patch.object(self.backend,'call',side_effect=AssertionError('Duplicate archive must not invoke Paseo')):
            result=self.b.handle(self.token,'archive',{'id':child})
        self.assertEqual(result,{'agentId':child,'status':'archived','alreadyArchived':True})
        self.assertIn('agentId',self.spawn(task='quota was released'))

    def test_archive_of_confirmed_deleted_owned_worker_is_scoped_success(self):
        self.b.limit=1;child=self.spawn()['agentId'];del self.backend.records[child]
        with patch.object(self.backend,'call',side_effect=AssertionError('Missing child must not invoke archive')):
            result=self.b.handle(self.token,'archive',{'id':child})
        self.assertEqual(result,{'agentId':child,'status':'archived','missing':True})
        self.assertIn('agentId',self.spawn(task='new worker'))

    def test_already_archived_cli_error_requires_positive_final_inspection(self):
        child=self.spawn()['agentId']
        error=subprocess.CalledProcessError(1,['fixture-paseo','archive'],
            output=json.dumps({'error':{'code':'AGENT_ALREADY_ARCHIVED'}}))
        def concurrent_archive(args,owner):
            self.backend.records[child]['Archived']=True
            raise error
        with patch.object(self.backend,'call',side_effect=concurrent_archive):
            result=self.b.handle(self.token,'archive',{'id':child})
        self.assertTrue(result['alreadyArchived'])
        self.assertTrue(self.b.data['owners'][self.owner]['children'][child])
        second=self.spawn(task='second worker')['agentId']
        # The exact same error without a confirmed archived/missing record is not success.
        with patch.object(self.backend,'call',side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError):self.b.handle(self.token,'archive',{'id':second})
        self.assertFalse(self.b.data['owners'][self.owner]['children'][second])

    def test_archive_outage_or_failed_postcheck_never_releases_quota(self):
        self.b.limit=1;child=self.spawn()['agentId'];self.backend.offline=True
        with self.assertRaises(OSError):self.b.handle(self.token,'archive',{'id':child})
        self.assertFalse(self.b.data['owners'][self.owner]['children'][child])
        self.backend.offline=False
        def lose_contact(args,owner):
            self.backend.offline=True
            raise subprocess.TimeoutExpired('fixture archive',10)
        with patch.object(self.backend,'call',side_effect=lose_contact):
            with self.assertRaises(OSError):self.b.handle(self.token,'archive',{'id':child})
        self.assertFalse(self.b.data['owners'][self.owner]['children'][child])
        with self.assertRaises(module.Denied):self.spawn(task='must remain blocked')

    def test_unconfirmed_archive_does_not_release_quota(self):
        self.b.limit=1;child=self.spawn()['agentId']
        original=self.backend.call
        def broken(args,owner):
            return {'status':'failed'} if args[0]=='archive' else original(args,owner)
        with patch.object(self.backend,'call',side_effect=broken):
            with self.assertRaises(module.BackendFailure):self.b.handle(self.token,'archive',{'id':child})
        with self.assertRaises(module.Denied):self.spawn(task='must remain blocked')

    def test_catalog_revision_change_revokes_old_caps(self):
        policy=json.loads(json.dumps(self.policy));policy['catalog_revision']='revision-two'
        restored=module.Broker(self.state,[self.projects],self.backend,policy=policy)
        with self.assertRaises(module.Denied):restored.handle(self.token,'profiles',{})

    def test_parallel_spawns_respect_durable_global_limit(self):
        errors=[];results=[];gate=threading.Barrier(6)
        def run():
            try:gate.wait();results.append(self.spawn(task=str(uuid.uuid4())))
            except module.Denied:pass
            except Exception as error:errors.append(error)
        threads=[threading.Thread(target=run) for _ in range(6)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(timeout=10)
        self.assertEqual(errors,[]);self.assertEqual(len(results),2);self.assertEqual(self.backend.creations,2)

    def test_legacy_json_migrates_children_without_authorizing_old_tokens_in_catalog_mode(self):
        legacy=self.root/'legacy.json';owner=str(uuid.uuid4());child=str(uuid.uuid4())
        token='fixture-old-token';digest=module.hashlib.sha256(token.encode()).hexdigest()
        contents={'owners':{owner:{'cwd':str(self.cwd),'workspace':None,'children':{child:False},'tokens':{digest:time.time()+3600}}}}
        legacy.write_text(json.dumps(contents));original=legacy.read_bytes()
        restored=module.Broker(legacy,[self.projects],self.backend,policy=self.policy)
        self.assertEqual(legacy.read_bytes(),original)
        self.assertIn(child,restored.data['owners'][owner]['children'])
        self.assertTrue(legacy.with_suffix('.sqlite3').exists())
        with self.assertRaises(module.Denied):restored.authenticate(token)

    def test_invalid_backend_json_fails_closed(self):
        backend=module.Backend(self.root)
        for stdout in ['not json','null','{"error":{"code":"FAILED"}}']:
            with patch.object(module.subprocess,'run',return_value=type('Result',(),{'stdout':stdout})()):
                with self.assertRaises(module.BackendFailure):backend.call(['archive',str(uuid.uuid4()),'--json'],{'id':self.owner})

    def test_recovery_uses_server_label_filter_and_rejects_malformed_metadata(self):
        backend=module.Backend(self.root);launch=str(uuid.uuid4());child=str(uuid.uuid4())
        with patch.object(backend,'call',return_value=[{'id':child,'labels':{'asp.now.launch':launch}}]) as call:
            self.assertEqual(backend.find_launch(launch,{'id':self.owner}),[child])
            self.assertIn('asp.now.launch='+launch,call.call_args.args[0])
        # Older CLI versions may omit label output, but still enforce their server filter.
        with patch.object(backend,'call',return_value=[{'id':child}]):
            self.assertEqual(backend.find_launch(launch,{'id':self.owner}),[child])
        with patch.object(backend,'call',return_value=[{'id':child,'labels':{'asp.now.launch':'wrong'}}]):
            self.assertEqual(backend.find_launch(launch,{'id':self.owner}),[])
        with patch.object(backend,'call',return_value=[{'id':child,'labels':'malformed'}]):
            with self.assertRaises(module.BackendFailure):backend.find_launch(launch,{'id':self.owner})

    def test_http_transport_uses_same_definition_policy_and_has_no_registration_route(self):
        def request(path,payload,token=None):
            client,server=socket.socketpair()
            try:
                body=json.dumps(payload).encode()
                headers='POST '+path+' HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\n'
                if token:headers+='Authorization: Bearer '+token+'\r\n'
                client.sendall(headers.encode()+b'\r\n'+body)
                module.make_http_handler(self.b)(server,('fixture',0),object())
                response=client.recv(65536)
                return int(response.split(b' ',2)[1])
            finally:client.close();server.close()
        self.assertEqual(request('/v1/profiles',{},self.token),200)
        self.assertEqual(request('/v1/profiles',{}),403)
        self.assertEqual(request('/v1/spawn',{'profile':'claude','task':'forbidden'},self.token),403)
        self.assertEqual(request('/v1/register',{'id':self.owner},self.token),403)
        self.assertEqual(self.backend.creations,0)

    def test_unknown_spawn_fields_and_mcp_endpoint_cannot_bypass_authorization(self):
        with self.assertRaises(module.Denied):self.b.handle(self.token,'spawn',{'profile':'codex','task':'x','provider':'claude'})
        with self.assertRaises(module.Denied):self.b.handle(self.token,'register',{'id':self.owner})
        self.assertEqual(self.backend.creations,0)


if __name__=='__main__':unittest.main()
