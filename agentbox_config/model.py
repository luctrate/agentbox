"""Strict catalog validation and default expansion; no host/network mutation."""
import copy
import ipaddress
import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator

from .loader import CatalogError, _check_data
from security.secret_values import validate_environment_key

SCHEMA_PATH = Path(__file__).resolve().parents[1] / 'schemas/agent-catalog-v1alpha1.schema.json'
IMMUTABLE_IMAGE = re.compile(r'^(?:sha256:[a-f0-9]{64}|[^\s@]+@sha256:[a-f0-9]{64})$')
BASE_DEFAULTS = {
    'enabled': True,
    'execution': {'backend': 'docker', 'user': 'nonRoot', 'allowPrivilegeEscalation': False,
                  'readOnlyRoot': True, 'capabilities': {'drop': ['ALL']},
                  'resources': {'cpu': 2, 'memory': '4g', 'pids': 512}},
    'workspace': {'source': 'callerWorkspace', 'access': 'readOnly'},
    'tools': {'cli': {'mode': 'unrestrictedWithinContainer'}, 'mcp': [],
              'launchAgent': {'interfaces': ['cli'], 'allowedWorkers': [],
                              'maxConcurrent': 4, 'maxDepth': 1}},
    'vaultPathToEnv': [], 'staticEnv': {}, 'hosts': {},
}


def _merge(base, override):
    """Objects merge recursively; arrays/scalars replace, never union grants."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _ipv4(value, location, network=False):
    try:
        parsed = ipaddress.ip_network(value, strict=True) if network else ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise CatalogError(location + ': a valid IPv4 address/CIDR is required') from None
    if parsed.version != 4:
        raise CatalogError(location + ': IPv6 policy is not supported by this runtime')
    return str(parsed)


def _environment_key(key, location):
    try:
        validate_environment_key(key)
    except ValueError:
        raise CatalogError(location + ': invalid or platform-reserved environment variable') from None
    if key.upper().startswith('ASP_'):
        raise CatalogError(location + ': platform-reserved environment variable')


def _validate_schema(catalog):
    _check_data(catalog)
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(catalog), key=lambda error: '/'.join(str(x) for x in error.path))
    if errors:
        error = errors[0]
        location = '.'.join(str(x) for x in error.path) or 'catalog'
        # Never include the instance value or a whole source line in errors.
        raise CatalogError(location + ': invalid field/value (' + error.validator + ')')


def validate_catalog(catalog):
    """Return a new complete normalized catalog, rejecting unenforced settings."""
    _validate_schema(catalog)
    result = {'apiVersion': catalog['apiVersion'], 'kind': catalog['kind'], 'agents': [],
              'networkPolicies': copy.deepcopy(catalog['networkPolicies'])}
    defaults = _merge(BASE_DEFAULTS, catalog.get('defaults', {}))
    ids = set()
    for raw in catalog['agents']:
        agent = _merge(defaults, raw)
        ident = agent['id']
        if ident in ids:
            raise CatalogError('Agent IDs must be unique')
        ids.add(ident)
        if agent['role'] not in ('manager', 'worker'):
            raise CatalogError('Approver agents are not supported until approval routing is installed')
        if not IMMUTABLE_IMAGE.fullmatch(agent['image']['ref']):
            raise CatalogError('agents.' + ident + '.image.ref: immutable sha256 image reference required')
        agent['image'].setdefault('expectedCapabilities', {}).setdefault('sudo', 'unknown')
        source=agent['workspace']['source'];access=agent['workspace']['access']
        agent['harness'].setdefault('authStorage','persistent')
        if (source=='callerWorkspace' and access=='none' or source=='ephemeral' or
                source=='none' and access!='none'):
            raise CatalogError('Use callerWorkspace readOnly/readWrite or none/none')
        if source=='none' and agent['harness']['authStorage']!='ephemeral':
            raise CatalogError('Unshared agents require ephemeral model authentication')
        if agent['harness']['authStorage']=='ephemeral' and agent['vaultPathToEnv']:
            raise CatalogError('Ephemeral-auth profiles do not accept tool secrets')
        tools = agent['tools']
        if tools['cli']['mode'] != 'unrestrictedWithinContainer' or 'policyRef' in tools['cli']:
            raise CatalogError('Mediated/disabled CLI and command policies are not implemented')
        if tools['mcp']:
            raise CatalogError('MCP tool authorization is not implemented by this runtime')
        launch = tools['launchAgent']
        if launch['interfaces'] != ['cli']:
            raise CatalogError('Only the CLI launchAgent interface is currently supported')
        privilege = agent['execution']['allowPrivilegeEscalation']
        if privilege and agent['execution']['capabilities']['drop']:
            raise CatalogError('Privilege escalation conflicts with dropping all capabilities')
        if privilege and agent['image']['expectedCapabilities']['sudo'] == 'unavailable':
            raise CatalogError('Privilege escalation requires a sudo-capable image')
        memory = agent['execution']['resources']['memory'].lower()
        multiplier = {'k': 1024, 'm': 1024**2, 'g': 1024**3}.get(memory[-1], 1)
        count = int(memory[:-1] if memory[-1] in 'kmg' else memory)
        if not 16 * 1024**2 <= count * multiplier <= 1024**4:
            raise CatalogError('Container memory must be between 16 MiB and 1 TiB')
        secret_keys = set()
        for mapping in agent['vaultPathToEnv']:
            _environment_key(mapping['env'], 'vaultPathToEnv')
            if mapping['env'] in secret_keys:
                raise CatalogError('Duplicate vaultPathToEnv destination')
            secret_keys.add(mapping['env'])
            path = mapping['vaultPath']
            if (not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_./-]*', path) or
                    any(part in ('', '.', '..') for part in path.split('/')) or '/' not in path):
                raise CatalogError('vaultPathToEnv: use mount/path without traversal or interpolation')
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', mapping['field']):
                raise CatalogError('vaultPathToEnv: invalid field name')
        for key in agent['staticEnv']:
            _environment_key(key, 'staticEnv')
            if key in secret_keys:
                raise CatalogError('A variable cannot appear in staticEnv and vaultPathToEnv')
        for hostname, address in list(agent['hosts'].items()):
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', hostname):
                raise CatalogError('hosts: invalid hostname')
            agent['hosts'][hostname] = _ipv4(address, 'hosts')
        reference = agent.get('networkPolicyRef')
        if reference not in result['networkPolicies']:
            raise CatalogError('Agent references a missing network policy')
        if launch['allowedWorkers'] and not result['networkPolicies'][reference].get('brokerAccess', False):
            raise CatalogError('Delegating agents need brokerAccess in their network policy')
        result['agents'].append(agent)
    index = {agent['id']: agent for agent in result['agents']}
    for agent in result['agents']:
        allowed = agent['tools']['launchAgent']['allowedWorkers']
        for target in allowed:
            child = index.get(target)
            if child is None or not child['enabled']:
                raise CatalogError('Delegation target is missing or disabled')
            if child['role'] != 'worker':
                raise CatalogError('Only worker definitions may be launched')
    depths={}
    def depth(ident,path):
        if ident in path:raise CatalogError('Delegation cycles are not allowed')
        if ident in depths:return depths[ident]
        children=index[ident]['tools']['launchAgent']['allowedWorkers']
        value=max([1+depth(child,path+[ident]) for child in children] or [0]);depths[ident]=value
        return value
    for agent in result['agents']:
        if depth(agent['id'],[])>agent['tools']['launchAgent']['maxDepth']:
            raise CatalogError('Delegation graph exceeds maxDepth')
    for name, network in result['networkPolicies'].items():
        network.setdefault('dns', ['1.1.1.1', '8.8.8.8'])
        network.setdefault('brokerAccess', False)
        network.setdefault('allow', [])
        network['dns'] = [_ipv4(address, 'networkPolicies.' + name + '.dns') for address in network['dns']]
        for rule in network['allow']:
            rule['cidr'] = _ipv4(rule['cidr'], 'networkPolicies.' + name + '.allow', network=True)
            if not rule['ports']:
                raise CatalogError('Network allow rules require at least one explicit port')
    return result
