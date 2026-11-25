"""Pure compiler from an ASP catalog and trusted platform bindings to runtime IR."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from .loader import CatalogError, _check_data
from .model import validate_catalog
from security.network import normalized_plan

NATIVE_PROVIDER_IDS = {'claude', 'codex', 'copilot', 'opencode', 'pi', 'omp', 'antigravity', 'muse'}
COMPILER_KEYS = {'authRefs', 'providerBindings', 'networkBindings', 'proxyBindings', 'provider_command', 'policy_path'}


def _absolute(value, label):
    if (not isinstance(value, str) or not value or '\x00' in value or not Path(value).is_absolute() or
            value.startswith('//') or '..' in Path(value).parts):
        raise CatalogError(label + ': absolute trusted platform path required')
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _network_binding(value):
    if not isinstance(value, dict) or set(value)-{'name','subnet','gateway','bridge','internal'} or not {'name','subnet','gateway','bridge'}<=set(value):
        raise CatalogError('networkBindings entries require name,subnet,gateway,bridge')
    result = copy.deepcopy(value)
    if 'internal' in result and type(result['internal']) is not bool:raise CatalogError('internal must be boolean')
    if (not isinstance(result['name'], str) or result['name'] in ('host', 'bridge', 'none') or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}', result['name'])):
        raise CatalogError('Invalid Docker network binding name')
    if not isinstance(result['bridge'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', result['bridge']):
        raise CatalogError('Invalid Linux bridge binding name')
    try:
        subnet = ipaddress.ip_network(result['subnet'], strict=True)
        gateway = ipaddress.ip_address(result['gateway'])
    except (ValueError, TypeError):
        raise CatalogError('Invalid network subnet/gateway binding') from None
    private = [ipaddress.ip_network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if (subnet.version != 4 or gateway.version != 4 or not any(subnet.subnet_of(root) for root in private) or
            gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address)):
        raise CatalogError('Docker bindings require a private IPv4 subnet and usable gateway')
    result['subnet'] = str(subnet);result['gateway'] = str(gateway)
    return result


def compile_catalog(catalog, platform):
    """Compile without reading secrets, inspecting Docker, resolving DNS or writing files."""
    normalized = validate_catalog(catalog)
    if not isinstance(platform, dict):
        raise CatalogError('Platform bindings must be an object')
    _check_data(platform)
    roots = platform.get('roots')
    if not isinstance(roots, list) or not roots or len(roots) > 64:
        raise CatalogError('Platform roots must be a nonempty list of workspace roots')
    root_paths = [Path(_absolute(value, 'roots')) for value in roots]
    if any(str(path) == '/' for path in root_paths):
        raise CatalogError('The filesystem root cannot be a workspace root')
    for index, left in enumerate(root_paths):
        for right in root_paths[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise CatalogError('Workspace roots must be distinct and non-overlapping')
    for key in ('uid', 'gid'):
        if type(platform.get(key)) is not int or not 1 <= platform[key] <= 2147483647:
            raise CatalogError('Platform UID/GID must be positive non-root integers')
    if 'max_workers' in platform and (type(platform['max_workers']) is not int or not 1 <= platform['max_workers'] <= 256):
        raise CatalogError('Platform max_workers must be a positive bounded integer')

    def protected_path(value, label):
        path = Path(_absolute(value, label))
        if any(path == root or path in root.parents or root in path.parents for root in root_paths):
            raise CatalogError(label + ': trusted runtime/auth paths must not overlap workspace roots')
        return str(path)

    auth_refs = platform.get('authRefs', {})
    bindings = platform.get('providerBindings', {})
    network_bindings = platform.get('networkBindings', {})
    if not all(isinstance(value, dict) for value in (auth_refs, bindings, network_bindings)):
        raise CatalogError('Platform binding maps must be objects')
    command = platform.get('provider_command')
    if isinstance(command, str):command = [command]
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and x and '\x00' not in x for x in command):
        raise CatalogError('provider_command must be a trusted executable path or argv list')
    _absolute(command[0], 'provider_command')
    for part in command:
        if Path(part).is_absolute():protected_path(part, 'provider_command')
    policy_path = protected_path(platform.get('policy_path', '/etc/agentbox/security.json'), 'policy_path')
    for key in ('client', 'state', 'control_socket'):
        if key in platform:protected_path(platform[key], key)
    readiness = platform.get('network_readiness')
    if readiness is None:
        raise CatalogError('Catalog deployments require network_readiness.path')
    if readiness is not None:
        if not isinstance(readiness, dict) or 'path' not in readiness or set(readiness) - {'path', 'revision'}:
            raise CatalogError('network_readiness requires a trusted path')
        protected_path(readiness['path'], 'network_readiness')
    for value in auth_refs.values():protected_path(value, 'authRefs')
    networks = {}
    used_auth = {};used_bindings = {}
    for agent in normalized['agents']:
        ref = agent['networkPolicyRef']
        if ref not in network_bindings:
            raise CatalogError('Missing trusted network binding for a referenced policy')
        if ref not in networks:
            network = _network_binding(network_bindings[ref])
            network.update(copy.deepcopy(normalized['networkPolicies'][ref]))
            if 'httpsProxy' in network:
                binding=platform.get('proxyBindings',{}).get(ref)
                if not isinstance(binding,dict) or set(binding)!={'port','caFile'}:
                    raise CatalogError('HTTPS proxy needs trusted port/caFile bindings')
                network['httpsProxy'].update({'host':network['gateway'],'port':binding['port'],
                    'caFile':protected_path(binding['caFile'],'proxy CA')})
            networks[ref] = network
        auth_ref = agent['harness']['authRef']
        if auth_ref not in auth_refs:
            raise CatalogError('Missing trusted harness authRef binding')
        used_auth[auth_ref] = protected_path(auth_refs[auth_ref], 'authRefs')
        provider_id = bindings.get(agent['id'], agent['id'])
        if (not isinstance(provider_id, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', provider_id) or
                provider_id in NATIVE_PROVIDER_IDS):
            raise CatalogError('Catalog providers cannot replace native provider IDs; use providerBindings')
        if provider_id in used_bindings.values():
            raise CatalogError('Provider bindings must be unique')
        used_bindings[agent['id']] = provider_id
    # An auth/history directory is a writable bind mount, so even nested auth
    # paths would let one definition read or replace another definition's state.
    used_auth_paths = [(agent['id'], Path(used_auth[agent['harness']['authRef']])) for agent in normalized['agents']]
    for index, (_, left) in enumerate(used_auth_paths):
        for _, right in used_auth_paths[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise CatalogError('Definitions require separate non-overlapping auth/history paths')
    entries = list(networks.values())
    for index, left in enumerate(entries):
        for right in entries[index + 1:]:
            if (left['name'] == right['name'] or left['bridge'] == right['bridge'] or
                    ipaddress.ip_network(left['subnet']).overlaps(ipaddress.ip_network(right['subnet']))):
                raise CatalogError('Managed network bindings must have unique names/bridges and disjoint subnets')
    try:
        network_plan = normalized_plan(dict(platform, networks=networks))
    except ValueError as error:
        raise CatalogError('Network plan rejected: ' + str(error)) from None
    networks = network_plan['networks']
    # Runtime artifact paths never participate in identity: generation paths contain
    # this revision. Stable bindings do affect identity and capability scope.
    identity = {'catalog': normalized, 'authRefs': used_auth, 'providerBindings': used_bindings,
                'networks': networks,
                'platform': {key: copy.deepcopy(platform[key]) for key in (
                    'host_home', 'uid', 'gid', 'roots', 'max_workers', 'ca_mounts', 'ca_env',
                    'deny_public_ips', 'vault_addr', 'vault_cacert') if key in platform}}
    revision = _digest(identity)
    runtime = {key: copy.deepcopy(value) for key, value in platform.items() if key not in COMPILER_KEYS}
    runtime.update({'catalog_revision': revision, 'roles': {}, 'networks': networks,
                    'command_policies': copy.deepcopy(normalized['commandPolicies'])})
    # Internal Docker bridges have no default route; expose the broker only on
    # explicitly managed bridge gateways, never on wildcard/public interfaces.
    runtime['listen_addresses']=sorted(set([runtime.get('listen','127.0.0.1')]+[
        n['gateway'] for n in networks.values() if n.get('internal') and n['brokerAccess']]))
    runtime.pop('worker_private_access', None)
    if 'network_readiness' in runtime:
        if not isinstance(runtime['network_readiness'], dict) or 'path' not in runtime['network_readiness']:
            raise CatalogError('network_readiness requires a trusted path')
        _absolute(runtime['network_readiness']['path'], 'network_readiness')
        runtime['network_readiness']['revision'] = revision
    providers = {}
    for agent in normalized['agents']:
        ident = agent['id'];provider_id = used_bindings[ident];execution = agent['execution']
        launch = agent['tools']['launchAgent'];harness = agent['harness'];ref = agent['networkPolicyRef']
        role = {'definition_id': ident, 'provider_id': provider_id, 'revision': revision,
                'enabled': agent['enabled'], 'agent': harness['name'], 'manager': agent['role'] == 'manager',
                'role': agent['role'], 'cli': copy.deepcopy(agent['tools']['cli']),
                'sudo': execution['allowPrivilegeEscalation'], 'auth': used_auth[harness['authRef']],
                'image': agent['image']['ref'], 'harness_version': harness['version'],
                'expected_capabilities': copy.deepcopy(agent['image']['expectedCapabilities']),
                'network': networks[ref]['name'], 'network_policy_id': ref,
                'workspace_access': agent['workspace']['access'],
                'workspace_source':agent['workspace']['source'],
                'auth_storage':harness['authStorage'],
                'read_only_root': execution['readOnlyRoot'],
                'cpu': execution['resources']['cpu'], 'memory': execution['resources']['memory'],
                'pids': execution['resources']['pids'],
                'drop_capabilities': copy.deepcopy(execution['capabilities']['drop']),
                'no_new_privileges': not execution['allowPrivilegeEscalation'],
                'static_env': copy.deepcopy(agent['staticEnv']), 'hosts': copy.deepcopy(agent['hosts']),
                'vault_secrets': {item['env']: item['vaultPath'] + '#' + item['field'] for item in agent['vaultPathToEnv']},
                'delegation': {'allowed_workers': copy.deepcopy(launch['allowedWorkers']),
                               'max_concurrent': launch['maxConcurrent'], 'max_depth': launch['maxDepth']}}
        runtime['roles'][ident] = role
        config_var = 'CLAUDE_CONFIG_DIR' if harness['name'] == 'claude' else 'CODEX_HOME'
        entry = {'enabled': agent['enabled'], 'extends': harness['name'], 'label': agent['name'],
                 'description': agent.get('description', 'Catalog agent: ' + ident),
                 'command': [*command, '--policy', policy_path, '--role', ident],
                 'env': {config_var: role['auth']}}
        if harness['name'] == 'codex':
            entry['options'] = {'sandbox_mode': 'danger-full-access', 'approval_policy': 'on-request'}
        providers[provider_id] = entry
    return {'revision': revision, 'runtime_policy': runtime, 'providers': providers,
            'managed_provider_ids': list(providers), 'normalized_catalog': normalized}
