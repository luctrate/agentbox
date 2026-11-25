"""Pinned harness configuration for trusted command-gateway profiles.

This restricts harness tool invocation, not every descendant Linux exec syscall.
Docker remains the operating-system boundary for commands approved by policy.
"""
import json
from pathlib import Path

MCP_PATH = '/usr/local/bin/agentbox-mcp'
BROKER_FILE = '.config/agentbox/broker.json'
FEATURES = {name: False for name in ['shell_tool', 'unified_exec', 'code_mode', 'code_mode_only',
    'code_mode_host', 'computer_use', 'in_app_browser', 'browser_use', 'browser_use_external',
    'plugins', 'hooks', 'apps', 'multi_agent', 'multi_agent_v2']}
WORKER_TOOLS = ['command_policy', 'run_command', 'command_status', 'execute_command']
REVIEW_TOOLS = ['review_request', 'decide_command']


def mode(role):
    return role.get('cli', {}).get('mode', 'unrestrictedWithinContainer')


def enabled(role):
    return mode(role) != 'unrestrictedWithinContainer'


def validate_role(role):
    selected_mode=mode(role)
    if selected_mode not in ('unrestrictedWithinContainer','mediated','disabled'):
        raise ValueError('Unknown CLI execution mode')
    if selected_mode=='unrestrictedWithinContainer':return
    expected={'claude':'2.1.329','codex':'0.171.0'}
    if (role.get('agent') not in expected or role.get('harness_version')!=expected[role['agent']] or
            role.get('auth_storage')!='ephemeral' or not role.get('read_only_root') or
            role.get('sudo') or role.get('no_new_privileges') is not True or
            role.get('drop_capabilities')!=['ALL']):
        raise ValueError('Controlled CLI requires its verified immutable runtime profile')
    if role.get('role')=='approver' and (selected_mode!='disabled' or role.get('workspace_access')!='none' or
            role.get('vault_secrets') or role.get('delegation',{}).get('allowed_workers')):
        raise ValueError('Invalid isolated reviewer profile')


def needs_broker(role):
    return mode(role) == 'mediated' or role.get('role') == 'approver'


def tools(role):
    return REVIEW_TOOLS if role.get('role') == 'approver' else WORKER_TOOLS if mode(role) == 'mediated' else []


def mcp_server(role):
    return {'command': '/usr/bin/python3', 'args': [MCP_PATH], 'enabled_tools': tools(role),
            'default_tools_approval_mode': 'approve', 'tool_timeout_sec': 240,
            'tools': {name: {'approval_mode': 'approve'} for name in tools(role)}}


def codex_config(role):
    return {'features': dict(FEATURES), 'mcp_servers': {'agentbox': mcp_server(role)} if needs_broker(role) else {},
            'web_search': 'disabled', 'approval_policy': 'never', 'sandbox_mode': 'danger-full-access'}


def prepare_args(role, args, cwd, probe=False):
    if not enabled(role) or args == ['--version']:
        return list(args)
    harness = role['agent']
    # Deliberately version-bound. Future versions need compatibility/tool-inventory checks.
    expected = {'claude': '2.1.329', 'codex': '0.171.0'}
    if role.get('harness_version') != expected[harness]:
        raise ValueError('Command mediation requires a verified pinned harness version')
    if harness == 'claude':
        values = {'--tools', '--allowedTools', '--allowed-tools', '--disallowedTools', '--disallowed-tools',
                  '--mcp-config', '--setting-sources', '--settings', '--permission-mode', '--agents', '--agent',
                  '--add-dir', '--plugin-dir', '--plugin-url', '--append-system-prompt-file', '--settings-file'}
        switches = {'--dangerously-skip-permissions', '--allow-dangerously-skip-permissions', '--restricted',
                    '--strict-mcp-config', '--chrome', '--no-chrome', '--safe-mode'}
        output = []
        index = 0
        while index < len(args):
            value = args[index]
            key = value.split('=', 1)[0]
            if key in values:
                if '=' not in value:
                    if index + 1 >= len(args): raise ValueError('Malformed harness arguments')
                    index += 1
                    # SDK list-valued options must be a single serialized value.
                    if index + 1 < len(args) and not args[index + 1].startswith('-'):
                        raise ValueError('Ambiguous tooling arguments')
            elif key not in switches:
                output.append(value)
            index += 1
        native = ['Read', 'Glob', 'Grep', 'AskUserQuestion']
        if role.get('role') == 'approver' or mode(role) == 'disabled':
            native = []
        elif role.get('workspace_access') == 'readWrite':
            native += ['Edit', 'Write']
        servers = {'agentbox': {'command': '/usr/bin/python3', 'args': [MCP_PATH]}} if needs_broker(role) and not probe else {}
        allowed = native + (['mcp__agentbox__*'] if servers else [])
        return output + ['--restricted', '--no-chrome', '--strict-mcp-config', '--mcp-config',
                         json.dumps({'mcpServers': servers}, separators=(',', ':')),
                         '--tools', ','.join(native), '--allowedTools', ','.join(allowed),
                         '--setting-sources', '', '--permission-mode', 'dontAsk']
    if harness != 'codex' or not args or args[0] != 'app-server':
        raise ValueError('Mediated Codex requires the native app-server protocol')
    # Disallow caller config/features; the compiled host policy supplies them.
    result = ['app-server']
    index = 1
    while index < len(args):
        value = args[index]
        if value in ('-c', '--config', '--enable', '--disable'):
            if index + 1 >= len(args): raise ValueError('Malformed Codex config arguments')
            index += 2
            continue
        if value.startswith(('--config=', '--enable=', '--disable=')):
            index += 1
            continue
        if value not in ('--stdio', '--listen', 'stdio://'):
            raise ValueError('Unsupported mediated app-server argument')
        result.append(value);index += 1
    for key, value in FEATURES.items():
        result += ['-c', 'features.' + key + '=false']
    result += ['-c', 'mcp_servers={}', '-c', 'web_search="disabled"', '-c', 'approval_policy="never"',
               '-c', 'sandbox_mode="danger-full-access"', '-c', 'projects.' + json.dumps(cwd) + '.trust_level="untrusted"']
    if needs_broker(role) and not probe:
        server = mcp_server(role)
        result += ['-c', 'mcp_servers.agentbox.command=' + json.dumps(server['command']),
                   '-c', 'mcp_servers.agentbox.args=' + json.dumps(server['args']),
                   '-c', 'mcp_servers.agentbox.enabled_tools=' + json.dumps(server['enabled_tools']),
                   '-c', 'mcp_servers.agentbox.default_tools_approval_mode="approve"',
                   '-c', 'mcp_servers.agentbox.tool_timeout_sec=240']
    return result


def guard_message(role, message):
    """Reapply tool settings when Paseo sends per-thread/per-turn overrides."""
    if not enabled(role) or role['agent'] != 'codex':
        return message
    if message.get('method') in ('command/exec', 'config/value/write', 'config/batchWrite', 'skills/config/write',
                                 'mcpServer/oauth/login', 'config/mcpServer/reload'):
        raise ValueError('Mediated app-server control operation denied')
    if message.get('method') in ('thread/start', 'thread/resume', 'thread/fork', 'turn/start'):
        params = message.setdefault('params', {})
        if not isinstance(params, dict): raise ValueError('Invalid app-server parameters')
        config = params.get('config', {})
        if not isinstance(config, dict): raise ValueError('Invalid app-server config')
        model_keys={'model','model_reasoning_effort','model_reasoning_summary','model_verbosity',
                    'service_tier','model_context_window','model_auto_compact_token_limit','personality'}
        config = {key:value for key,value in config.items() if key in model_keys}
        # Replace whole maps, not just selected values: no extra MCP/tool namespaces.
        config.update(codex_config(role))
        params['config'] = config
        params['approvalPolicy'] = 'never'
        params['approvalsReviewer'] = 'user'
        params['sandbox'] = 'danger-full-access'
        if 'sandboxPolicy' in params:
            params['sandboxPolicy'] = {'type': 'dangerFullAccess'}
        params.pop('dynamicTools', None)
    return message
