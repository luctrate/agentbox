#!/usr/bin/env python3
"""Generate fixed container profiles and optionally merge them into native Paseo."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shlex


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mount', action='append', required=True, type=Path,
                        help='absolute checkout/worktree parent to mount read-write; repeat as needed')
    parser.add_argument('--output', type=Path, default=Path.home()/'.config/agentbox')
    parser.add_argument('--paseo-config', type=Path, default=Path.home()/'.paseo/config.json')
    parser.add_argument('--claude-config', type=Path, default=Path.home()/'.claude')
    parser.add_argument('--codex-home', type=Path, default=Path.home()/'.codex')
    parser.add_argument('--mcp-host', default='host.docker.internal', help='host[:port] reachable from Docker')
    parser.add_argument('--with-node', action='store_true', help='also generate nvm + container-local sudo profiles')
    parser.add_argument('--gitlab-host', help='GitLab hostname, without scheme')
    parser.add_argument('--gitlab-vault-ref', help='Vault reference, e.g. secret/agentbox/gitlab#token')
    parser.add_argument('--apply', action='store_true', help='merge providers and enable MCP injection; back up existing config')
    args = parser.parse_args()
    if bool(args.gitlab_host) != bool(args.gitlab_vault_ref):
        parser.error('--gitlab-host and --gitlab-vault-ref must be supplied together')
    if args.gitlab_host and any(c in args.gitlab_host for c in '/\\\n\r'):
        parser.error('--gitlab-host must be a hostname, optionally with a port')
    if args.gitlab_vault_ref and ('#' not in args.gitlab_vault_ref or '\n' in args.gitlab_vault_ref):
        parser.error('--gitlab-vault-ref must be path#field')
    mounts = [p.expanduser().resolve() for p in args.mount]
    for path in mounts:
        if not path.is_dir():
            parser.error('mount must be an existing directory: '+str(path))
    output = args.output.expanduser().resolve()
    root = Path(__file__).resolve().parents[1]
    claude = args.claude_config.expanduser().resolve()
    codex = args.codex_home.expanduser().resolve()
    for path in [claude, codex]:
        if not path.is_dir():
            parser.error('authenticate the native CLI first; config directory missing: '+str(path))
    definitions = [('claude','claude','base','none'), ('codex','codex','base','none')]
    if args.with_node:
        definitions += [('node','claude','nvm-sudo','sudo'), ('node-codex','codex','nvm-sudo','sudo')]
    if args.gitlab_host:
        definitions += [('gitlab','claude','base','none'), ('gitlab-codex','codex','base','none')]
    planned = {}
    providers = {}
    for name, agent, image, privilege in definitions:
        provider = {'claude':'claude-box','codex':'codex-box'}.get(name,'agentbox-'+name)
        profile = [
            '# Managed by agentbox deploy/configure.py',
            'DESC='+shlex.quote(agent+' container; '+name),
            'IMAGE=agentbox/'+image+':latest', 'AGENT='+agent,
            'PRIVILEGE='+privilege, 'NETWORK=bridge', 'PASEO_PROVIDER='+provider,
            'AUTH_VOLUME='+shlex.quote(str(claude if agent=='claude' else codex)),
            'MOUNTS=('+' '.join(shlex.quote(str(p)) for p in mounts)+')',
        ]
        if name.startswith('gitlab'):
            profile += ['STATIC_ENV=('+shlex.quote('GITLAB_HOST='+args.gitlab_host)+')',
                        'VAULT_SECRETS=('+shlex.quote('GITLAB_TOKEN='+args.gitlab_vault_ref)+')']
        planned[output/'profiles'/(name+'.sh')] = '\n'.join(profile)+'\n'
        definition = {
            'extends':agent, 'label':agent.title()+' (container: '+name+')',
            'command':[str(root/'bin/agentbox-provider'),'--profile',name],
            'env':{'AGENTBOX_PROFILE_DIR':str(output/'profiles'),
                   'AGENTBOX_DAEMON_HOST':args.mcp_host,
                   'CLAUDE_CONFIG_DIR':str(claude), 'CODEX_HOME':str(codex)},
        }
        if agent=='codex':
            definition['options']={'sandbox_mode':'danger-full-access','approval_policy':'on-request'}
        providers[provider] = definition
    planned[output/'providers.json'] = json.dumps(providers,indent=2)+'\n'
    # Validate every conflict before changing any file.
    for path in planned:
        if path.exists() and path.suffix=='.sh' and not path.read_text().startswith('# Managed by agentbox'):
            parser.error('refusing to overwrite custom profile: '+str(path))
    config_path = args.paseo_config.expanduser().resolve()
    config = None
    if args.apply:
        if not config_path.is_file():
            parser.error('--apply requires an existing native Paseo config: '+str(config_path))
        config = json.loads(config_path.read_text())
        # This legacy helper enables broad profiles and native MCP injection.
        # Never use it to overwrite a restricted/catalog-managed deployment.
        for provider in config.get('agents', {}).get('providers', {}).values():
            command = provider.get('command', [])
            if '--role' in command and (
                '--policy' in command or any('/security/provider' in str(part) for part in command)
            ):
                parser.error('Restricted/catalog providers detected; use agentbox catalog plan/apply instead')
        current = config.setdefault('agents',{}).setdefault('providers',{})
        for name, value in providers.items():
            if name in current and current[name].get('command')!=value['command']:
                parser.error('refusing to overwrite custom provider: '+name)
        current.update(providers)
        config.setdefault('daemon',{}).setdefault('mcp',{})['injectIntoAgents']=True
    os.umask(0o077)
    for path, content in planned.items():
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(content)
        path.chmod(0o600)
    if config is not None:
        stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        backup=config_path.with_name(config_path.name+'.before-agentbox-'+stamp)
        backup.write_bytes(config_path.read_bytes())
        backup.chmod(0o600)
        temporary=config_path.with_name(config_path.name+'.agentbox-new')
        temporary.write_text(json.dumps(config,indent=2)+'\n')
        temporary.chmod(0o600)
        temporary.replace(config_path)
        print('Backed up config:',backup)
        print('Merged providers; run `paseo reload` to activate them.')
    print('Generated',len(providers),'providers in',output/'providers.json')
    print('Profiles:',output/'profiles')
    print('Set AGENTBOX_PROFILE_DIR to that profiles directory for agentbox CLI calls.')
    print('Configure the Docker-to-host MCP route before starting workers; see docs/paseo.md.')


if __name__=='__main__':
    main()
