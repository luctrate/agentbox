"""Operator-only catalog deployment. Compile/plan never read Vault values."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time


class ApplyError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def read_json(path,default=None):
    path=Path(path)
    return json.loads(path.read_text()) if path.exists() else default


def atomic_json(path,value,mode=0o600):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'-',dir=str(path.parent))
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.chmod(name,mode);os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)


def reconcile_providers(existing,desired,previous=None,adopt_existing=False):
    """Three-way managed merge. Native providers and daemon settings stay untouched."""
    config=copy.deepcopy(existing)
    current=config.setdefault('agents',{}).setdefault('providers',{})
    previous=previous or {}
    old_hashes=previous.get('provider_hashes',{})
    reserved={'claude','codex','copilot','opencode','pi','omp','antigravity','muse'}
    if not isinstance(old_hashes,dict) or reserved.intersection(old_hashes):
        raise ApplyError('Managed manifest cannot contain native host providers')
    changes={'add':[],'update':[],'disable':[],'unchanged':[]}
    for name,new in desired.items():
        if name in reserved:raise ApplyError('Catalog cannot manage native host providers')
        old=current.get(name)
        if old is not None and old!=new:
            if name in old_hashes:
                if digest(old)!=old_hashes[name]:raise ApplyError('Managed provider changed outside catalog: '+name)
            elif not adopt_existing or not _adoptable(old,new):
                raise ApplyError('Existing provider is unmanaged; review/adopt explicitly: '+name)
        changes['add' if old is None else 'unchanged' if old==new else 'update'].append(name)
        current[name]=copy.deepcopy(new)
    for name,old_hash in old_hashes.items():
        if name in desired:continue
        old=current.get(name)
        if old is None:continue
        if digest(old)!=old_hash:raise ApplyError('Removed provider changed outside catalog: '+name)
        replacement=copy.deepcopy(old);replacement['enabled']=False
        current[name]=replacement;changes['disable'].append(name)
    # Retain disabled providers in the manifest so later apply still detects edits.
    managed=set(desired)|set(old_hashes)
    hashes={name:digest(current[name]) for name in managed if name in current}
    return config,changes,hashes


def _adoptable(old,new):
    command=old.get('command',[]);wanted=new.get('command',[])
    if not command or not wanted or command[0]!=wanted[0]:return False
    try:
        old_role=command[command.index('--role')+1]
        new_role=wanted[wanted.index('--role')+1]
    except (ValueError,IndexError):return False
    return (old_role==new_role and old.get('extends')==new.get('extends') and
            old.get('env',{})==new.get('env',{}))


class Commands:
    def __init__(self,platform):self.platform=platform
    def run(self,args,timeout=45,check=True):
        result=subprocess.run(args,capture_output=True,text=True,timeout=timeout,
            env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                 'HOME':pwd.getpwuid(os.getuid()).pw_dir})
        if check and result.returncode:raise ApplyError('Command failed: '+str(args[0])+': '+result.stderr[-1200:])
        return result
    def paseo(self,args,timeout=45,check=True):
        command=self.platform.get('paseo_binary','/usr/bin/paseo')
        home=self.platform['host_home']
        invocation=[command,*args]
        if os.geteuid()==0:
            account=pwd.getpwuid(self.platform.get('uid',1000)).pw_name
            invocation=['/usr/sbin/runuser','-u',account,'--','/usr/bin/env',
                        'HOME='+home,'PATH=/usr/local/bin:/usr/bin:/bin',*invocation]
        return self.run(invocation,timeout=timeout,check=check)


def inspect_images(policy,commands):
    """Probe trusted, digest-pinned images without host mounts, credentials or network."""
    observations={}
    script="""import json,shutil,subprocess
out={'sudo':bool(shutil.which('sudo')),'bootstrap':bool(shutil.which('agentbox-bootstrap')),'broker_client':bool(shutil.which('agentbox')),'command_gateway':bool(shutil.which('agentbox-mcp')),'versions':{}}
for name in ['claude','codex']:
 try:out['versions'][name]=subprocess.check_output([name,'--version'],text=True,stderr=subprocess.DEVNULL).strip()
 except Exception:out['versions'][name]=None
print(json.dumps(out))
"""
    for name,role in policy['roles'].items():
        image=role['image']
        if not re.fullmatch(r'(?:[^\s]+@)?sha256:[0-9a-f]{64}',image):
            raise ApplyError('Image must be pinned by digest/ID: '+name)
        if image not in observations:
            raw=commands.run(['/usr/bin/docker','image','inspect',image],timeout=30)
            metadata=json.loads(raw.stdout)[0]
            probe=commands.run(['/usr/bin/docker','run','--rm','--network','none','--read-only',
                '--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','512m',
                '--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,mode=1777,size=64m',
                '--entrypoint','python3',image,'-c',script],timeout=45)
            observed=json.loads(probe.stdout)
            observed['image_id']=metadata['Id'];observations[image]=observed
        observed=observations[image]
        found=re.search(r'(?<!\d)(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)(?!\d)',
                        observed.get('versions',{}).get(role['agent']) or '')
        if not found or found.group(1)!=role['harness_version']:
            raise ApplyError('Harness version does not match pinned expectation: '+name)
        expected=role.get('expected_capabilities',{}).get('sudo','unknown')
        if expected not in ('available','unavailable','unknown'):raise ApplyError('Invalid sudo metadata')
        if expected!='unknown' and observed['sudo']!=(expected=='available'):
            raise ApplyError('Image sudo capability does not match expectation: '+name)
        if role.get('sudo') and not observed['sudo']:raise ApplyError('Sudo role requires a sudo image: '+name)
        if role.get('auth_storage')=='ephemeral' and not observed.get('bootstrap'):
            raise ApplyError('Ephemeral model auth requires the bootstrap image: '+name)
        if role.get('cli',{}).get('mode') in ('mediated','disabled') and not observed.get('command_gateway'):
            raise ApplyError('Controlled CLI requires an image-baked command adapter: '+name)
        if role.get('auth_storage')=='ephemeral' and role.get('delegation',{}).get('allowed_workers') and not observed.get('broker_client'):
            raise ApplyError('Unshared delegation requires an image-baked broker client: '+name)
        if not Path(role['auth']).is_dir():raise ApplyError('Role auth directory is missing: '+name)
        if os.geteuid()==0:
            account=pwd.getpwuid(policy.get('uid',1000)).pw_name
            for access in ['-r','-w','-x']:
                commands.run(['/usr/sbin/runuser','-u',account,'--','/usr/bin/test',access,role['auth']],timeout=10)

    return observations


def validate_live_bindings(policy,extra_paths=()):
    roots=[Path(value).resolve(strict=True) for value in policy['roots']]
    if any(str(root)=='/' for root in roots):raise ApplyError('Root filesystem cannot be a workspace scope')
    for index,left in enumerate(roots):
        for right in roots[index+1:]:
            if left==right or left in right.parents or right in left.parents:
                raise ApplyError('Workspace roots overlap after resolving symlinks')
    auth=[Path(role['auth']).resolve(strict=True) for role in policy['roles'].values()]
    for index,left in enumerate(auth):
        for right in auth[index+1:]:
            if left==right or left in right.parents or right in left.parents:
                raise ApplyError('Auth directories overlap after resolving symlinks')
    protected=[str(path) for path in auth]+list(extra_paths)
    protected += [policy[key] for key in ['client','state','control_socket'] if key in policy]
    if policy.get('network_readiness'):protected.append(policy['network_readiness']['path'])
    protected += [n['httpsProxy']['caFile'] for n in policy.get('networks',{}).values() if n.get('httpsProxy')]
    for value in protected:
        resolved=Path(value).resolve(strict=False)
        if any(resolved==root or resolved in root.parents or root in resolved.parents for root in roots):
            raise ApplyError('Trusted/auth path overlaps a workspace after resolving symlinks')


def _protected_parent(path):
    """Runtime policy must never be installed under an agent-writable ancestor."""
    path=Path(path).absolute()
    for current in [path,*path.parents]:
        if current.exists():
            st=current.stat()
            if st.st_uid!=0 or st.st_mode&0o022:
                raise ApplyError('Deployment path is not administrator-owned: '+str(current))


def _switch_link(link,target):
    link=Path(link);link.parent.mkdir(parents=True,exist_ok=True)
    candidate=link.with_name('.'+link.name+'.next-'+str(os.getpid()))
    candidate.unlink(missing_ok=True)
    candidate.symlink_to(target)
    os.replace(candidate,link)


def _restore_file(path,original,link_target=None,mode=0o600):
    path=Path(path)
    if link_target is not None:_switch_link(path,link_target)
    elif original is None:path.unlink(missing_ok=True)
    else:
        temp=path.with_name('.'+path.name+'.restore')
        temp.write_bytes(original);temp.chmod(mode);os.replace(temp,path)


def _active_managed(commands):
    r=commands.run(['/usr/bin/docker','ps','--filter','label=agentbox.restricted=true',
                    '--format','{{.Label "agentbox.agent"}}'])
    return sorted({line for line in r.stdout.splitlines() if re.fullmatch(r'[0-9a-f-]{36}',line)})


def _wait_ready(commands,managed_ids=None,policy=None):
    if policy and policy.get('network_readiness'):
        from security.network import policy_fingerprint
        readiness=policy['network_readiness']
        artifact=Path(readiness['path'])
        _protected_parent(artifact)
        current=read_json(artifact,{})
        if (current.get('revision')!=readiness['revision'] or
            current.get('plan_hash')!=policy_fingerprint(policy)):
            raise ApplyError('Activated network readiness does not match the compiled policy')
    for _ in range(30):
        r=commands.paseo(['status','--json'],timeout=10,check=False)
        if r.returncode==0:
            if not managed_ids:return
            rows=commands.paseo(['provider','ls','--json'],timeout=15,check=False)
            if rows.returncode==0:
                try:index={row['provider']:row for row in json.loads(rows.stdout)}
                except (ValueError,TypeError,KeyError):index={}
                if all(index.get(name,{}).get('status')=='available' for name in managed_ids):return
        time.sleep(1)
    raise ApplyError('Paseo or managed providers did not become ready after activation')


def _deploy_locked(compiled,platform,paseo_config,generations,policy_link,manifest_path,
           adopt_existing=False,drain=False,commands=None,require_root=True):
    """Apply an already reviewed compilation. All failures attempt the previous revision."""
    if require_root and os.geteuid()!=0:raise ApplyError('Apply requires an administrator; validate/plan do not')
    commands=commands or Commands(platform)
    policy_link=Path(policy_link);generations=Path(generations);manifest_path=Path(manifest_path)
    paseo_config=Path(paseo_config)
    if require_root:
        for path in [generations,policy_link.parent,manifest_path.parent]:_protected_parent(path)
    existing=read_json(paseo_config)
    if existing is None:raise ApplyError('Existing Paseo configuration is required')
    previous=read_json(manifest_path,{})
    config,changes,hashes=reconcile_providers(existing,compiled['providers'],previous,adopt_existing)
    deployment_revision=compiled.get('deployment_revision',compiled['revision'])
    if previous.get('deployment_revision',previous.get('revision'))==deployment_revision and config==existing:
        return {'revision':compiled['revision'],'changed':False,'changes':changes}
    revision=compiled['revision'];generation=generations/deployment_revision
    policy_path=generation/'policy.json'
    if require_root:_protected_parent(generation)
    for name,item in compiled['providers'].items():
        argv=item['command']
        if '--policy' not in argv or Path(argv[argv.index('--policy')+1])!=policy_path:
            raise ApplyError('Provider policy path does not match immutable generation: '+name)
    if policy_path.exists() and read_json(policy_path)!=compiled['runtime_policy']:
        raise ApplyError('An existing immutable generation has different content')
    # Complete all fail-fast checks before any runtime or policy mutation.
    if require_root:
        executable=platform['provider_command']
        code_paths=([executable] if isinstance(executable,str) else executable)
        validate_live_bindings(compiled['runtime_policy'],[str(policy_path),str(policy_link),
            *[value for value in code_paths if str(value).startswith('/')],
            *[value for value in platform.get('network_command',[]) if str(value).startswith('/')]])
        for value in ([executable] if isinstance(executable,str) else executable):
            if str(value).startswith('/') and Path(value).exists():_protected_parent(value)
        for value in [compiled['runtime_policy'].get('client'),*platform.get('network_command',[])]:
            if value and str(value).startswith('/') and Path(value).exists():_protected_parent(value)
        for network in compiled['runtime_policy'].get('networks',{}).values():
            if network.get('httpsProxy'):_protected_parent(network['httpsProxy']['caFile'])
    images=inspect_images(compiled['runtime_policy'],commands)
    sessions=json.loads(commands.paseo(['ls','--json']).stdout)
    for session in sessions:
        native=session.get('provider','').split('/')[0] in ('claude','codex')
        if native and session.get('status') in ('running','starting','initializing'):
            raise ApplyError('A normal host agent has an active turn; apply after it finishes')
    active=_active_managed(commands)
    if active and not drain:raise ApplyError('Managed runtimes exist; use explicit --drain or close them first')
    for ident in active:commands.paseo(['archive',ident,'--json'])
    generation.mkdir(parents=True,exist_ok=True,mode=0o755)
    for directory in [generations.parent,generations,generation]:directory.chmod(0o755)
    atomic_json(policy_path,compiled['runtime_policy'],0o644)
    atomic_json(generation/'providers.json',compiled['providers'])
    atomic_json(generation/'catalog.normalized.json',compiled.get('normalized_catalog',{}))
    atomic_json(generation/'verified-images.json',images)
    original_config=paseo_config.read_bytes()
    original_policy=policy_link.read_bytes() if policy_link.exists() else None
    original_target=os.readlink(policy_link) if policy_link.is_symlink() else None
    original_manifest=manifest_path.read_bytes() if manifest_path.exists() else None
    backup=generation/'before-activation'
    backup.mkdir(exist_ok=True,mode=0o700)
    (backup/'paseo-config.json').write_bytes(original_config)
    (backup/'paseo-config.json').chmod(0o600)
    if original_policy is not None:
        (backup/'policy.json').write_bytes(original_policy);(backup/'policy.json').chmod(0o600)
    broker_service=platform.get('broker_service','agentbox-broker')
    paseo_service=platform.get('paseo_service','paseo')
    network_command=platform.get('network_command',['/usr/bin/python3','/opt/agentbox-restricted/security/network.py'])
    egress_service=platform.get('egress_service')
    needs_proxy=any(n.get('httpsProxy') for n in compiled['runtime_policy'].get('networks',{}).values())
    if needs_proxy and not egress_service:raise ApplyError('HTTPS proxy requires a trusted egress service binding')
    def activate_egress(policy):
        if not egress_service:return
        enabled=any(n.get('httpsProxy') for n in policy.get('networks',{}).values())
        commands.run(['/usr/bin/systemctl','restart' if enabled else 'stop',egress_service],timeout=60)
        if enabled:commands.run(['/usr/bin/systemctl','is-active',egress_service],timeout=10)
    try:
        print('Stopping the controller for a coherent policy activation...',file=sys.stderr,flush=True)
        commands.run(['/usr/bin/systemctl','stop',paseo_service,broker_service],timeout=90)
        # Preserve both legacy registry and durable SQLite state for operator recovery.
        state=Path(compiled['runtime_policy'].get('state','/nonexistent'))
        database=state.with_suffix('.sqlite3') if state.suffix=='.json' else state
        for source in dict.fromkeys([state,database,Path(str(database)+'-wal'),Path(str(database)+'-shm')]):
            if source.is_file():
                destination=backup/('registry-'+source.name)
                shutil.copy2(source,destination);destination.chmod(0o600)
        print('Activating the complete network revision...',file=sys.stderr,flush=True)
        commands.run([*network_command,'--config',str(policy_path)],timeout=90)
        _switch_link(policy_link,policy_path)
        activate_egress(compiled['runtime_policy'])
        atomic_json(paseo_config,config)
        # Keep the daemon user's ownership, including on configs replaced atomically.
        if require_root:os.chown(paseo_config,platform.get('uid',1000),platform.get('gid',1000))
        commands.run(['/usr/bin/systemctl','start',broker_service,paseo_service],timeout=90)
        commands.run(['/usr/bin/systemctl','is-active',broker_service],timeout=10)
        _wait_ready(commands,[name for name,item in compiled['providers'].items() if item.get('enabled',True)],compiled['runtime_policy'])
        manifest={'revision':revision,'deployment_revision':deployment_revision,'provider_hashes':hashes,'managed_provider_ids':sorted(hashes),
                  'generation':str(generation),'runtime_code_hash':compiled.get('runtime_code_hash'),'activated_at':time.time()}
        atomic_json(manifest_path,manifest,0o644)
        return {'revision':revision,'changed':True,'changes':changes,'generation':str(generation),'deployment_revision':deployment_revision}
    except Exception as error:
        print('Activation failed; restoring the previous configuration and policy...',file=sys.stderr,flush=True)
        rollback_errors=[]
        for action in [
            lambda:commands.run(['/usr/bin/systemctl','stop',paseo_service,broker_service],timeout=90),
            lambda:_restore_file(paseo_config,original_config),
            lambda:_restore_file(policy_link,original_policy,original_target,0o644),
            lambda:_restore_file(manifest_path,original_manifest),
        ]:
            try:action()
            except Exception as failure:rollback_errors.append(type(failure).__name__)
        if require_root:
            try:os.chown(paseo_config,platform.get('uid',1000),platform.get('gid',1000))
            except OSError as failure:rollback_errors.append(type(failure).__name__)
        if original_policy is not None:
            try:commands.run([*network_command,'--config',str(backup/'policy.json')],timeout=90)
            except Exception as failure:rollback_errors.append('network:'+type(failure).__name__)
            try:activate_egress(json.loads(original_policy))
            except Exception as failure:rollback_errors.append('egress:'+type(failure).__name__)
        if not rollback_errors:
            try:
                commands.run(['/usr/bin/systemctl','start',broker_service,paseo_service],timeout=90)
                _wait_ready(commands)
            except Exception as failure:rollback_errors.append('services:'+type(failure).__name__)
        message='Catalog activation failed; previous state restored' if not rollback_errors else 'Catalog activation failed; services left stopped because rollback could not be verified: '+','.join(rollback_errors)
        raise ApplyError(message) from error


def deploy(compiled,platform,paseo_config,generations,policy_link,manifest_path,
           adopt_existing=False,drain=False,commands=None,require_root=True):
    """Serialize policy transactions before reading the current revision/config."""
    if require_root and os.geteuid()!=0:raise ApplyError('Apply requires an administrator')
    parent=Path(manifest_path).parent
    if require_root:_protected_parent(parent)
    parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    lock=parent/'.apply.lock'
    flags=os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)
    descriptor=os.open(lock,flags,0o600)
    try:
        if require_root:
            metadata=os.fstat(descriptor)
            if metadata.st_uid!=0 or metadata.st_mode&0o022:raise ApplyError('Unsafe apply lock')
        try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ApplyError('Another catalog apply is already running') from None
        return _deploy_locked(compiled,platform,paseo_config,generations,policy_link,manifest_path,
                              adopt_existing,drain,commands,require_root)
    finally:os.close(descriptor)
