#!/usr/bin/python3
"""External worker authorization, durable launch tracking, and bounded HTTP API."""
import argparse
from contextlib import contextmanager
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import sqlite3
import subprocess
import threading
import time
import uuid

PROFILES={'claude':'claude-box','codex':'codex-box','node':'agentbox-node',
          'node-codex':'agentbox-node-codex','gitlab':'agentbox-gitlab',
          'gitlab-codex':'agentbox-gitlab-codex'}
FIELDS={'profiles':set(),'spawn':{'profile','task'},'status':{'id'},'logs':{'id'},
        'stop':{'id'},'archive':{'id'},'send':{'id','message'},
        'questions':{'id'},'answer':{'id','questionId','answers'}}
PENDING=('reserved','uncertain')
NATIVE_PROVIDERS={'claude','codex','copilot','opencode','pi','omp','antigravity','muse'}


def worker_provider(value):
    # Paseo accepts provider/model syntax and trims provider strings. Delegation
    # must name one compiled container provider, never a parsed native shortcut.
    return (isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',value)
            and value.lower() not in NATIVE_PROVIDERS)


class Denied(Exception):
    pass


class BackendFailure(Exception):
    def __init__(self,message,code=None):
        super().__init__(message);self.code=code


def identifier(value):
    if not isinstance(value,str):raise Denied('Invalid agent ID')
    try:valid=str(uuid.UUID(value))==value
    except ValueError:valid=False
    if not valid:raise Denied('Invalid agent ID')
    return value


class Backend:
    """Only the trusted adapter invokes Paseo; transport clients never supply args."""
    def __init__(self,home=None,binary='/usr/bin/paseo'):
        self.home=str(home or Path.home());self.binary=binary

    def call(self,args,owner):
        env={'HOME':self.home,'PATH':'/usr/local/bin:/usr/bin:/bin',
             'PASEO_AGENT_ID':owner['id']}
        if owner.get('workspace'):env['PASEO_WORKSPACE_ID']=owner['workspace']
        timeout=45 if args[0]=='run' else (10 if args[0] in ('archive','stop') else 5)
        result=subprocess.run([self.binary,*args],env=env,cwd=self.home,
                              capture_output=True,text=True,timeout=timeout,check=True)
        if len(result.stdout)>8*1024*1024:raise BackendFailure('Backend response too large')
        try:value=json.loads(result.stdout)
        except ValueError:raise BackendFailure('Backend returned invalid JSON') from None
        if not isinstance(value,(dict,list)):
            raise BackendFailure('Backend returned an error')
        if isinstance(value,dict) and 'error' in value:
            detail=value['error'];code=detail.get('code') if isinstance(detail,dict) else None
            raise BackendFailure('Backend returned an error',code)
        return value

    def inspect(self,child,owner):
        try:return self.call(['inspect',child,'--json'],owner)
        except BackendFailure as error:
            if error.code in ('AGENT_NOT_FOUND','NOT_FOUND'):return None
            raise
        except subprocess.CalledProcessError as error:
            for stream in [error.stdout,error.stderr]:
                try:record=json.loads(stream or '')
                except ValueError:continue
                if isinstance(record,dict) and isinstance(record.get('error'),dict):
                    if record['error'].get('code') in ('AGENT_NOT_FOUND','NOT_FOUND'):return None
            # An offline daemon, invalid JSON, or other CLI failure is not proof of deletion.
            raise

    def find_launch(self,launch_id,owner):
        rows=self.call(['ls','--all','--label','asp.now.launch='+launch_id,'--json'],owner)
        if not isinstance(rows,list):raise BackendFailure('Invalid backend list response')
        result=[]
        for row in rows:
            if not isinstance(row,dict):raise BackendFailure('Invalid filtered worker record')
            # Paseo's filter is authoritative; older CLI JSON omitted labels.
            # When metadata is included, reject mismatches or malformed values.
            if 'labels' in row or 'Labels' in row:
                labels=row.get('labels',row.get('Labels'))
                if not isinstance(labels,dict):raise BackendFailure('Invalid worker labels')
                if labels.get('asp.now.launch')!=launch_id:continue
            child=row.get('id',row.get('Id',row.get('agentId')))
            result.append(identifier(child))
        return result

    def messaging(self,operation,data,owner,launch):
        payload=dict(data,operation=operation,owner=owner['id'],provider=launch['provider'],
                     cwd=launch['cwd'])
        env={'HOME':self.home,'PATH':'/usr/local/bin:/usr/bin:/bin'}
        result=subprocess.run(['/usr/bin/env','node',str(Path(__file__).with_name('paseo-messaging.mjs')),self.binary],
                              input=json.dumps(payload),env=env,cwd=self.home,
                              capture_output=True,text=True,timeout=30)
        if len(result.stdout)>1024*1024:raise BackendFailure('Messaging response too large')
        try:value=json.loads(result.stdout)
        except ValueError:raise BackendFailure('Unconfirmed worker response') from None
        if isinstance(value,dict) and value.get('error')=='denied':raise Denied('Worker message or question was rejected')
        if result.returncode or not isinstance(value,dict) or 'error' in value:
            raise BackendFailure('Unconfirmed worker response')
        return value


class Broker:
    def __init__(self,state,roots,backend=None,limit=8,policy=None):
        self.path=Path(state)
        self.db_path=self.path.with_suffix('.sqlite3') if self.path.suffix=='.json' else self.path
        self.roots=[Path(x).resolve() for x in roots]
        self.policy=json.loads(json.dumps(policy)) if policy else {}
        self.revision=self.policy.get('catalog_revision')
        self.catalog=self.revision is not None
        self.roles=self.policy.get('roles',{})
        self.backend=backend or Backend(self.policy.get('host_home'),self.policy.get('paseo_binary','/usr/bin/paseo'))
        self.limit=limit
        self.lock=threading.RLock()
        self._reconcile_lock=threading.Lock()
        self.inflight=0  # compatibility diagnostic; durable reservations enforce quota
        self.db_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.db=sqlite3.connect(str(self.db_path),timeout=10,check_same_thread=False,isolation_level=None)
        self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS owners(id TEXT PRIMARY KEY,cwd TEXT NOT NULL,workspace TEXT,
 definition_id TEXT NOT NULL,revision TEXT,generation INTEGER NOT NULL,claims TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS capabilities(digest TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES owners(id),
 generation INTEGER NOT NULL,expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS launches(launch_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES owners(id),
 request_key TEXT NOT NULL,fingerprint TEXT NOT NULL,profile TEXT NOT NULL,provider TEXT NOT NULL,
 revision TEXT,state TEXT NOT NULL,child_id TEXT,result TEXT,created REAL NOT NULL,
 UNIQUE(owner_id,request_key));
CREATE TABLE IF NOT EXISTS children(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES owners(id),
 launch_id TEXT,active INTEGER NOT NULL,profile TEXT,provider TEXT);
CREATE TABLE IF NOT EXISTS deliveries(owner_id TEXT NOT NULL REFERENCES owners(id),request_key TEXT NOT NULL,
 fingerprint TEXT NOT NULL,state TEXT NOT NULL,result TEXT,created REAL NOT NULL,
 PRIMARY KEY(owner_id,request_key));
''')
        if 'context' not in {row[1] for row in self.db.execute('PRAGMA table_info(launches)')}:
            self.db.execute('ALTER TABLE launches ADD COLUMN context TEXT')
        self.db_path.chmod(0o600)
        self._validate_policy()
        self._migrate_legacy()
        with self.transaction() as db:
            # A previous broker may have exited between reservation and launch confirmation.
            db.execute("UPDATE launches SET state='uncertain' WHERE state='reserved'")
            db.execute("UPDATE deliveries SET state='uncertain' WHERE state='reserved'")
            if self.catalog:
                db.execute('DELETE FROM capabilities WHERE owner_id IN (SELECT id FROM owners WHERE revision IS NULL OR revision!=?)',(self.revision,))
            if self.path!=self.db_path and not self.path.exists():
                self.path.write_text(json.dumps({'format':'agentbox-sqlite','database':self.db_path.name})+'\n')
                self.path.chmod(0o600)

    @contextmanager
    def transaction(self):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield self.db
                self.db.commit()
            except BaseException:
                self.db.rollback();raise

    def _validate_policy(self):
        if not self.catalog:return
        if not isinstance(self.revision,str) or not self.revision:raise ValueError('Invalid catalog revision')
        for name,role in self.roles.items():
            delegation=role.get('delegation',{})
            allowed=delegation.get('allowed_workers',[])
            if not isinstance(allowed,list) or any(not isinstance(x,str) for x in allowed):
                raise ValueError('Invalid delegation allowlist')
            if not allowed:continue
            if type(delegation.get('max_depth')) is not int or not 1<=delegation['max_depth']<=16:raise ValueError('Invalid delegation depth')
            if type(delegation.get('max_concurrent')) is not int or delegation['max_concurrent']<1:
                raise ValueError('Invalid delegation quota')
            for target in allowed:
                child=self.roles.get(target)
                if not child or not child.get('enabled',True):raise ValueError('Unknown or disabled delegated definition')
                if not worker_provider(child.get('provider_id')):raise ValueError('Native providers cannot be delegated')
                if child.get('manager'):raise ValueError('Managers cannot be delegated')
        depths={}
        def depth(name,path):
            if name in path:raise ValueError('Delegation cycles are not allowed')
            if name in depths:return depths[name]
            children=self.roles[name].get('delegation',{}).get('allowed_workers',[])
            value=max([1+depth(child,path+[name]) for child in children] or [0]);depths[name]=value
            return value
        for name,role in self.roles.items():
            if depth(name,[])>role.get('delegation',{}).get('max_depth',1):raise ValueError('Delegation graph exceeds max depth')

    def _migrate_legacy(self):
        with self.transaction() as db:
            if db.execute("SELECT value FROM meta WHERE key='legacy_imported'").fetchone():return
            legacy=json.loads(self.path.read_text()) if self.path!=self.db_path and self.path.exists() else {}
            for owner_id,record in legacy.get('owners',{}).items():
                identifier(owner_id)
                cwd=str(record['cwd']);workspace=record.get('workspace')
                claims={'allowed_workers':list(PROFILES),'max_concurrent':self.limit,'max_depth':1}
                db.execute('INSERT OR IGNORE INTO owners VALUES(?,?,?,?,?,?,?)',
                           (owner_id,cwd,workspace,'__legacy__',None,1,json.dumps(claims)))
                if not self.catalog:
                    for digest,expiry in record.get('tokens',{}).items():
                        if re.fullmatch('[0-9a-f]{64}',digest) and isinstance(expiry,(int,float)):
                            db.execute('INSERT OR IGNORE INTO capabilities VALUES(?,?,?,?)',(digest,owner_id,1,expiry))
                for child,archived in record.get('children',{}).items():
                    identifier(child)
                    db.execute('INSERT OR IGNORE INTO children VALUES(?,?,?,?,?,?)',
                               (child,owner_id,None,int(not archived),None,None))
            db.execute("INSERT INTO meta VALUES('legacy_imported','1')")

    @property
    def data(self):
        """Read-only compatibility snapshot. SQLite is authoritative after migration."""
        with self.lock:
            owners={}
            for row in self.db.execute('SELECT * FROM owners'):
                record=dict(row);record['id']=row['id'];record['tokens']={};record['children']={}
                owners[row['id']]=record
            for row in self.db.execute('SELECT * FROM capabilities'):
                owners[row['owner_id']]['tokens'][row['digest']]=row['expires']
            for row in self.db.execute('SELECT * FROM children'):
                owners[row['owner_id']]['children'][row['id']]=not bool(row['active'])
            return {'owners':owners}

    def register(self,request):
        allowed={'op','id','cwd','workspace','definition_id','catalog_revision','launch_id'}
        if not isinstance(request,dict) or set(request)-allowed:raise Denied('Invalid registration')
        owner_id=identifier(request['id'])
        cwd=Path(request['cwd']).resolve(strict=True)
        if not cwd.is_dir() or not any(cwd!=root and root in cwd.parents for root in self.roots):
            raise Denied('Workspace is outside allowed project roots')
        workspace=request.get('workspace')
        if workspace is not None and (not isinstance(workspace,str) or len(workspace)>200):raise Denied('Invalid workspace')
        definition='__legacy__'
        claims={'allowed_workers':list(PROFILES),'max_concurrent':self.limit,'max_depth':1}
        if self.catalog:
            definition=request.get('definition_id')
            if request.get('catalog_revision')!=self.revision:raise Denied('Catalog revision mismatch')
            role=self.roles.get(definition) if isinstance(definition,str) else None
            if not role or not role.get('enabled',True):raise Denied('Unknown definition')
            delegation=role.get('delegation',{})
            if not delegation.get('allowed_workers'):raise Denied('Definition cannot delegate')
            claims={k:delegation[k] for k in ('allowed_workers','max_concurrent','max_depth')}
            if request.get('launch_id'):
                launch_id=identifier(request['launch_id'])
                with self.transaction() as db:
                    row=db.execute('SELECT * FROM launches WHERE launch_id=?',(launch_id,)).fetchone()
                    if not row:raise Denied('Unknown parent launch')
                    launch=dict(row);context=self._launch_context(launch)
                    digest=context.get('parent_capability')
                    parent=self._authenticate(db,digest)
                    if (launch['profile']!=definition or launch['owner_id']!=parent['id'] or
                            launch['revision']!=self.revision or str(cwd)!=context['cwd'] or
                            workspace!=context['workspace'] or launch['state'] not in ('reserved','uncertain','created') or
                            parent['max_depth']<2):raise Denied('Invalid nested launch scope')
                claims['max_depth']=min(claims['max_depth'],parent['max_depth']-1)
                claims['parent_capability']=digest
                claims['launch_id']=launch_id
        token=secrets.token_urlsafe(40);digest=hashlib.sha256(token.encode()).hexdigest()
        with self.transaction() as db:
            child=db.execute('SELECT * FROM children WHERE id=?',(owner_id,)).fetchone()
            if self.catalog and child and (not request.get('launch_id') or child['launch_id']!=request['launch_id']):
                raise Denied('Delegated runtimes must retain their parent launch identity')
            if claims.get('parent_capability'):self._authenticate(db,claims['parent_capability'])
            old=db.execute('SELECT * FROM owners WHERE id=?',(owner_id,)).fetchone()
            if old and json.loads(old['claims']).get('launch_id') not in (None,request.get('launch_id')):
                raise Denied('Delegated runtime cannot discard its launch identity')
            if old and old['definition_id'] not in ('__legacy__',definition):raise Denied('Session definition cannot change')
            if claims.get('launch_id'):
                # Paseo initializes the provider before publishing the agent.
                # This socket is private to trusted launchers, and the server's
                # launch UUID is passed only through its trusted process env.
                # Bind one expected child now; _adopt verifies its actual native
                # parent/provider/workspace after Paseo completes initialization.
                launch=db.execute('SELECT * FROM launches WHERE launch_id=?',(claims['launch_id'],)).fetchone()
                if launch['child_id'] not in (None,owner_id):raise Denied('Launch already bound to another runtime')
                db.execute('UPDATE launches SET child_id=? WHERE launch_id=?',(owner_id,claims['launch_id']))
            generation=old['generation']+1 if old else 1
            db.execute('INSERT INTO owners VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET cwd=excluded.cwd,workspace=excluded.workspace,definition_id=excluded.definition_id,revision=excluded.revision,generation=excluded.generation,claims=excluded.claims',
                       (owner_id,str(cwd),workspace,definition,self.revision,generation,json.dumps(claims)))
            db.execute('DELETE FROM capabilities WHERE owner_id=?',(owner_id,))
            db.execute('INSERT INTO capabilities VALUES(?,?,?,?)',(digest,owner_id,generation,time.time()+24*3600))
        return {'token':token}

    def revoke(self,token):
        digest=hashlib.sha256(token.encode()).hexdigest()
        with self.transaction() as db:db.execute('DELETE FROM capabilities WHERE digest=?',(digest,))

    def _authenticate(self,db,digest):
        row=db.execute('''SELECT o.*,c.expires,c.generation AS cap_generation FROM owners o
 JOIN capabilities c ON c.owner_id=o.id WHERE c.digest=?''',(digest,)).fetchone()
        if not row or row['expires']<=time.time() or row['generation']!=row['cap_generation']:
            raise Denied('Invalid or expired manager capability')
        if self.catalog and row['revision']!=self.revision:raise Denied('Stale catalog capability')
        claims=json.loads(row['claims']);ancestor=claims.get('parent_capability');seen={digest}
        while ancestor:
            if ancestor in seen or len(seen)>16:raise Denied('Invalid capability lineage')
            seen.add(ancestor)
            parent=db.execute('''SELECT o.*,c.expires,c.generation AS cap_generation FROM owners o
 JOIN capabilities c ON c.owner_id=o.id WHERE c.digest=?''',(ancestor,)).fetchone()
            if (not parent or parent['expires']<=time.time() or parent['generation']!=parent['cap_generation'] or
                    self.catalog and parent['revision']!=self.revision):raise Denied('Parent capability is no longer active')
            ancestor=json.loads(parent['claims']).get('parent_capability')
        result={k:row[k] for k in ('id','cwd','workspace','definition_id','revision','generation')}
        result.update(json.loads(row['claims']));result['_digest']=digest
        return result

    def authenticate(self,token):
        if not isinstance(token,str):raise Denied('Manager capability required')
        digest=hashlib.sha256(token.encode()).hexdigest()
        with self.transaction() as db:return self._authenticate(db,digest)

    def _current(self,db,owner):
        current=self._authenticate(db,owner['_digest'])
        if current['generation']!=owner['generation']:raise Denied('Runtime capability was replaced')

    def _provider(self,owner,profile):
        if profile not in owner['allowed_workers']:raise Denied('Profile is not allowed')
        if not self.catalog:return PROFILES[profile]
        role=self.roles.get(profile,{})
        provider=role.get('provider_id')
        if not role.get('enabled',True) or not worker_provider(provider):
            raise Denied('Delegated provider is not a container worker')
        if owner['max_depth']<1:raise Denied('Delegation depth exhausted')
        if role.get('manager'):raise Denied('Managers cannot be delegated')
        if role.get('delegation',{}).get('allowed_workers') and owner['max_depth']<2:
            raise Denied('Delegation depth exhausted')
        return provider

    def _owner(self,db,owner_id):
        row=db.execute('SELECT * FROM owners WHERE id=?',(owner_id,)).fetchone()
        return dict(row) if row else None

    def _inspect(self,child,owner):
        method=getattr(self.backend,'inspect',None)
        return method(child,owner) if method else self.backend.call(['inspect',child,'--json'],owner)

    def _valid_child(self,record,launch):
        if not isinstance(record,dict):raise BackendFailure('Invalid worker record')
        if not self.catalog:return
        if record.get('Id')!=launch['child_id'] or record.get('ParentAgentId')!=launch['owner_id']:
            raise BackendFailure('Worker identity does not match launch')
        if record.get('Provider')!=launch['provider']:raise BackendFailure('Worker provider does not match launch')
        expected=self._launch_context(launch)['cwd']
        if not isinstance(record.get('Cwd'),str) or str(Path(record['Cwd']).resolve())!=expected:
            raise BackendFailure('Worker workspace does not match launch')

    def _adopt(self,launch,child,result,record=None,principal=None):
        launch=dict(launch);launch['child_id']=child
        if record is None:
            record=self._inspect(child,self._launch_context(launch)) if self.catalog else {}
        self._valid_child(record,launch)
        active=not bool(record.get('Archived'))
        public={k:result[k] for k in ('agentId','status','provider','cwd','title') if k in result}
        public.update({'agentId':child,'requestId':launch['request_key'],'launchId':launch['launch_id']})
        revoked=False
        with self.transaction() as db:
            current_launch=db.execute('SELECT child_id FROM launches WHERE launch_id=?',(launch['launch_id'],)).fetchone()
            if current_launch and current_launch['child_id'] not in (None,child):
                raise BackendFailure('Worker differs from trusted runtime registration')
            existing=db.execute('SELECT owner_id FROM children WHERE id=?',(child,)).fetchone()
            if existing and existing['owner_id']!=launch['owner_id']:raise BackendFailure('Worker already has another owner')
            db.execute('INSERT OR REPLACE INTO children VALUES(?,?,?,?,?,?)',
                       (child,launch['owner_id'],launch['launch_id'],int(active),launch['profile'],launch['provider']))
            db.execute("UPDATE launches SET state='created',child_id=?,result=? WHERE launch_id=?",
                       (child,json.dumps(public),launch['launch_id']))
            if principal:
                try:self._current(db,principal)
                except Denied:revoked=True
        if revoked:
            # Creation may already have happened. Preserve ownership/quota even if cleanup fails.
            try:
                self._archive_backend(child,self._launch_context(launch))
                with self.transaction() as db:db.execute('UPDATE children SET active=0 WHERE id=?',(child,))
            except Exception:pass
            raise Denied('Runtime capability expired during launch')
        return public

    def _launch_context(self,launch):
        return json.loads(launch['context']) if launch.get('context') else self._owner_snapshot(launch['owner_id'])

    def _owner_snapshot(self,owner_id):
        with self.lock:return self._owner(self.db,owner_id)

    def reconcile(self):
        """Unknown/offline states retain reservations. Only positive evidence releases them."""
        if not self._reconcile_lock.acquire(blocking=False):return
        try:
            deadline=time.monotonic()+10
            with self.lock:
                pending=[dict(x) for x in self.db.execute("SELECT * FROM launches WHERE state='uncertain' ORDER BY created")]
                children=[dict(x) for x in self.db.execute('SELECT * FROM children WHERE active=1')]
            for launch in pending:
                if time.monotonic()>deadline:break
                try:
                    owner=self._launch_context(launch)
                    candidates=[launch['child_id']] if launch['child_id'] else getattr(self.backend,'find_launch',lambda *_:[])(launch['launch_id'],owner)
                    if len(candidates)!=1:continue
                    child=identifier(candidates[0]);record=self._inspect(child,owner)
                    if record is None:
                        if launch['child_id']:
                            with self.transaction() as db:
                                failed={'requestId':launch['request_key'],'launchId':launch['launch_id'],'status':'failed','error':'Worker no longer exists'}
                                db.execute("UPDATE launches SET state='failed',result=? WHERE launch_id=?",(json.dumps(failed),launch['launch_id']))
                        continue
                    self._adopt(launch,child,{'agentId':child,'status':record.get('Status','unknown')},record)
                except Exception:continue
            for child in children:
                if time.monotonic()>deadline:break
                try:
                    record=self._inspect(child['id'],self._owner_snapshot(child['owner_id']))
                    if record is None or isinstance(record,dict) and record.get('Archived') is True:
                        with self.transaction() as db:db.execute('UPDATE children SET active=0 WHERE id=?',(child['id'],))
                except Exception:continue
        finally:self._reconcile_lock.release()

    def _slots(self,db,owner_id=None):
        clause=' WHERE active=1'+(' AND owner_id=?' if owner_id else '')
        args=(owner_id,) if owner_id else ()
        children=db.execute('SELECT count(*) FROM children'+clause,args).fetchone()[0]
        clause=" WHERE state IN ('reserved','uncertain')"+(' AND owner_id=?' if owner_id else '')
        return children+db.execute('SELECT count(*) FROM launches'+clause,args).fetchone()[0]

    def _spawn(self,owner,data):
        profile,task=data['profile'],data['task']
        if not isinstance(profile,str):raise Denied('Invalid profile')
        provider=self._provider(owner,profile)
        if not isinstance(task,str) or not task.strip() or len(task)>50000:raise Denied('Invalid task')
        request_key=identifier(data.get('requestId',str(uuid.uuid4())))
        fingerprint=hashlib.sha256(json.dumps([profile,task],separators=(',',':')).encode()).hexdigest()
        self.reconcile()
        with self.transaction() as db:
            self._current(db,owner)
            previous=db.execute('SELECT * FROM launches WHERE owner_id=? AND request_key=?',(owner['id'],request_key)).fetchone()
            if previous:
                if previous['fingerprint']!=fingerprint:raise Denied('Request ID is already bound to another task')
                if previous['state'] in ('created','failed'):return json.loads(previous['result'])
                return {'requestId':request_key,'launchId':previous['launch_id'],'status':'pending_reconciliation'}
            if self._slots(db)>=self.limit or self._slots(db,owner['id'])>=owner['max_concurrent']:
                raise Denied('Worker limit reached; archive a finished worker')
            launch_id=str(uuid.uuid4())
            context=json.dumps({k:owner[k] for k in ('id','cwd','workspace','definition_id','revision','generation')})
            context=json.dumps(dict(json.loads(context),parent_capability=owner['_digest']))
            db.execute('INSERT INTO launches VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                       (launch_id,owner['id'],request_key,fingerprint,profile,provider,self.revision,'reserved',None,None,time.time(),context))
            launch=dict(db.execute('SELECT * FROM launches WHERE launch_id=?',(launch_id,)).fetchone())
        args=['run','--provider',provider,'--title','[box:'+profile+'] '+task[:60],
              '--label','asp.now.launch='+launch_id,'--no-wait','--json']
        if self.catalog:args+=['--env','AGENTBOX_PARENT_AGENT_ID='+owner['id']]
        if self.catalog and self.roles[profile].get('delegation',{}).get('allowed_workers'):
            args+=['--env','AGENTBOX_PARENT_LAUNCH='+launch_id]
        if owner.get('workspace'):args+=['--workspace',owner['workspace']]
        else:args+=['--cwd',owner['cwd']]
        child=None
        try:
            result=self.backend.call([*args,'--',task],owner)
            if not isinstance(result,dict) or 'error' in result:raise BackendFailure('Invalid launch response')
            child=identifier(result['agentId'])
            return self._adopt(launch,child,result,principal=owner)
        except Exception as error:
            with self.transaction() as db:
                state=db.execute('SELECT state FROM launches WHERE launch_id=?',(launch_id,)).fetchone()['state']
                db.execute("UPDATE launches SET state='uncertain',child_id=COALESCE(?,child_id) WHERE launch_id=? AND state!='created'",(child,launch_id))
            if isinstance(error,Denied) and state=='created':raise
            # Do not retry execution or free its reservation on an ambiguous outcome.
            return {'requestId':request_key,'launchId':launch_id,'status':'pending_reconciliation'}

    def _archive_confirmed(self,result):
        if self.catalog and not (isinstance(result,dict) and
                (result.get('status')=='archived' or result.get('Archived') is True)):
            raise BackendFailure('Archive was not confirmed')

    def _terminal_archive(self,child,record):
        # None is only emitted by the adapter for a positively identified NOT_FOUND.
        if record is None:return {'agentId':child,'status':'archived','missing':True}
        if not isinstance(record,dict) or record.get('Id')!=child or type(record.get('Archived')) is not bool:
            raise BackendFailure('Invalid worker archive state')
        if record['Archived']:
            return {'agentId':child,'status':'archived','alreadyArchived':True}
        return None

    def _archive_backend(self,child,owner):
        if self.catalog:
            completed=self._terminal_archive(child,self._inspect(child,owner))
            if completed is not None:return completed
        try:
            result=self.backend.call(['archive',child,'--json'],owner)
            self._archive_confirmed(result)
            return result
        except Exception:
            # Another actor may archive/delete between our precheck and mutation.
            # An error code alone is not confirmation; verify the final state.
            if self.catalog:
                completed=self._terminal_archive(child,self._inspect(child,owner))
                if completed is not None:return completed
            raise

    def _messaging_context(self,owner,child):
        with self.transaction() as db:
            self._current(db,owner)
            row=db.execute('SELECT * FROM children WHERE id=? AND owner_id=?',(child,owner['id'])).fetchone()
            if not row:raise Denied('Worker does not belong to this manager')
            if not row['active']:raise Denied('Worker is archived')
            stored=db.execute('SELECT * FROM launches WHERE launch_id=?',(row['launch_id'],)).fetchone()
            if not stored:raise Denied('Worker has no verified launch context')
            launch=dict(stored)
        record=self._inspect(child,owner)
        self._valid_child(record,launch)
        if record.get('Archived') is not False:raise Denied('Worker is missing or archived')
        return {'provider':launch['provider'],'cwd':self._launch_context(launch)['cwd']}

    def _message(self,owner,operation,data):
        child=identifier(data['id'])
        if operation=='send':
            text=data['message']
            if not isinstance(text,str) or not text.strip() or len(text)>50000 or '\0' in text:
                raise Denied('Invalid message')
        if operation=='answer':
            question=data['questionId'];answers=data['answers']
            if not isinstance(question,str) or not question.strip() or len(question)>512 or '\0' in question:
                raise Denied('Invalid question ID')
            if (not isinstance(answers,dict) or not 1<=len(answers)<=20 or len(json.dumps(answers))>100000 or
                    any(not isinstance(k,str) or not isinstance(v,str) or not v.strip() or len(v)>50000 or '\0' in v for k,v in answers.items())):
                raise Denied('Invalid answers')
        if operation=='questions':
            context=self._messaging_context(owner,child)
            return self.backend.messaging(operation,data,owner,context)
        request=identifier(data.get('requestId',str(uuid.uuid4())))
        fingerprint=hashlib.sha256(json.dumps([operation,{k:v for k,v in data.items() if k!='requestId'}],
                                              sort_keys=True,separators=(',',':')).encode()).hexdigest()
        # Check ownership before even consulting a delivery receipt.
        with self.transaction() as db:
            self._current(db,owner)
            if not db.execute('SELECT 1 FROM children WHERE id=? AND owner_id=?',(child,owner['id'])).fetchone():
                raise Denied('Worker does not belong to this manager')
            previous=db.execute('SELECT * FROM deliveries WHERE owner_id=? AND request_key=?',(owner['id'],request)).fetchone()
            if previous:
                if previous['fingerprint']!=fingerprint:raise Denied('Request ID already belongs to another message')
                if previous['state']=='completed':return json.loads(previous['result'])
                if previous['state']=='denied':raise Denied('Worker message or question was rejected')
                return {'agentId':child,'requestId':request,'status':'delivery_unconfirmed'}
        context=self._messaging_context(owner,child)
        with self.transaction() as db:
            self._current(db,owner)
            # A concurrent retry may have reserved the same request during inspection.
            if db.execute('SELECT 1 FROM deliveries WHERE owner_id=? AND request_key=?',(owner['id'],request)).fetchone():
                raise Denied('Request is already in progress; retry using the same request ID')
            db.execute('INSERT INTO deliveries VALUES(?,?,?,?,?,?)',
                       (owner['id'],request,fingerprint,'reserved',None,time.time()))
        try:
            result=self.backend.messaging(operation,data,owner,context)
            result=dict(result,requestId=request)
        except Denied:
            with self.transaction() as db:
                db.execute("UPDATE deliveries SET state='denied' WHERE owner_id=? AND request_key=?",(owner['id'],request))
            raise
        except Exception:
            with self.transaction() as db:
                db.execute("UPDATE deliveries SET state='uncertain' WHERE owner_id=? AND request_key=?",(owner['id'],request))
            return {'agentId':child,'requestId':request,'status':'delivery_unconfirmed'}
        with self.transaction() as db:
            db.execute("UPDATE deliveries SET state='completed',result=? WHERE owner_id=? AND request_key=?",
                       (json.dumps(result),owner['id'],request))
            self._current(db,owner)
        return result

    def handle(self,token,operation,data):
        owner=self.authenticate(token)
        if operation not in FIELDS or not isinstance(data,dict):raise Denied('Unsupported operation or fields')
        valid=set(data)==FIELDS[operation] or operation in ('spawn','send','answer') and set(data)==FIELDS[operation]|{'requestId'}
        if not valid:raise Denied('Unsupported operation or fields')
        if operation=='profiles':return {'profiles':list(owner['allowed_workers']),'max_unarchived_workers':owner['max_concurrent'],'global_max_unarchived_workers':self.limit}
        if operation=='spawn':return self._spawn(owner,data)
        if operation in ('send','questions','answer'):return self._message(owner,operation,data)
        child=identifier(data['id'])
        with self.transaction() as db:
            self._current(db,owner)
            if not db.execute('SELECT 1 FROM children WHERE id=? AND owner_id=?',(child,owner['id'])).fetchone():
                raise Denied('Worker does not belong to this manager')
        if operation=='status':
            record=self._inspect(child,owner)
            return record if record is not None else {'Id':child,'Status':'missing','Archived':True,'PendingPermissions':[]}
        if operation=='logs':return self.backend.call(['logs',child,'--json'],owner)
        if operation=='archive':
            result=self._archive_backend(child,owner)
            with self.transaction() as db:
                self._current(db,owner)
                db.execute('UPDATE children SET active=0 WHERE id=?',(child,))
            return result
        return self.backend.call([operation,child,'--json'],owner)


def make_http_handler(broker):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            self.close_connection=True
            try:
                length=int(self.headers.get('Content-Length','0'))
                if length<2 or length>262144:raise Denied('Invalid request length')
                if self.headers.get('Content-Type','').split(';',1)[0]!='application/json':raise Denied('JSON required')
                auth=self.headers.get('Authorization','')
                if not auth.startswith('Bearer '):raise Denied('Manager capability required')
                if not self.path.startswith('/v1/'):raise Denied('Unknown endpoint')
                result=broker.handle(auth[7:],self.path[4:],json.loads(self.rfile.read(length)))
                status=202 if isinstance(result,dict) and result.get('status') in ('pending_reconciliation','delivery_unconfirmed') else 200
            except (Denied,ValueError,KeyError,RecursionError):result={'error':'Request denied'};status=403
            except Exception:result={'error':'Worker operation failed'};status=502
            payload=json.dumps(result).encode()
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(payload)));self.send_header('Connection','close')
            self.end_headers();self.wfile.write(payload)
    return Handler


class BoundedThreads:
    daemon_threads=True
    max_handlers=16
    def server_activate(self):
        self._handlers=threading.BoundedSemaphore(self.max_handlers)
        super().server_activate()
    def get_request(self):
        request,address=super().get_request();request.settimeout(10);return request,address
    def process_request(self,request,address):
        if not self._handlers.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:self._handlers.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self._handlers.release()


class HTTPServer(BoundedThreads,http.server.ThreadingHTTPServer):
    request_queue_size=32


class ControlServer(BoundedThreads,socketserver.ThreadingUnixStreamServer):
    pass


def serve(config):
    os.umask(0o077)
    if config.get('mcp',{}).get('enabled'):raise ValueError('MCP transport is not implemented in this release')
    broker=Broker(config['state'],config['roots'],limit=config.get('max_workers',8),policy=config)
    class Control(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                raw=self.rfile.readline(65537)
                if len(raw)>65536:raise Denied('Too long')
                request=json.loads(raw)
                if request.get('op')=='register':result=broker.register(request)
                elif request.get('op')=='revoke' and set(request)=={'op','token'}:broker.revoke(request['token']);result={'ok':True}
                else:raise Denied('Unknown control operation')
            except Exception:result={'error':'Control request denied'}
            self.wfile.write(json.dumps(result).encode()+b'\n')
    path=Path(config['control_socket']);path.parent.mkdir(parents=True,exist_ok=True)
    path.unlink(missing_ok=True)
    control=ControlServer(str(path),Control);path.chmod(0o600)
    threading.Thread(target=control.serve_forever,daemon=True).start()
    addresses=config.get('listen_addresses',[config['listen']])
    if not isinstance(addresses,list) or not addresses:raise ValueError('Explicit broker listeners required')
    servers=[HTTPServer((address,config['port']),make_http_handler(broker)) for address in addresses]
    for server in servers[1:]:threading.Thread(target=server.serve_forever,daemon=True).start()
    servers[0].serve_forever()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True)
    serve(json.loads(Path(parser.parse_args().config).read_text()))
