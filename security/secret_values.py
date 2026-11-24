"""Vault-to-environment resolution without host-control variable injection."""
import re
import subprocess

_ENVIRONMENT_KEY = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_RESERVED = {
    'HOME', 'PATH', 'PWD', 'OLDPWD', 'USER', 'LOGNAME', 'UID', 'EUID', 'GID',
    'SHELL', 'ENV', 'BASH_ENV', 'IFS', 'SHELLOPTS', 'BASHOPTS',
    'CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'NODE_OPTIONS', 'BUN_OPTIONS',
    'RUBYOPT', 'PERL5OPT', 'PERL5LIB', 'GCONV_PATH', 'GLIBC_TUNABLES',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS', 'REQUESTS_CA_BUNDLE',
    'CURL_CA_BUNDLE', 'GIT_SSL_CAINFO',
}
_RESERVED_PREFIXES = ('DOCKER_', 'LD_', 'DYLD_', 'PYTHON', 'AGENTBOX_', 'PASEO_',
                      'VAULT_', 'ASP_', 'GIT_CONFIG', 'SUDO_')


def validate_environment_key(key):
    if not isinstance(key, str) or not _ENVIRONMENT_KEY.fullmatch(key):
        raise ValueError('Invalid environment variable name')
    upper = key.upper()
    if upper in _RESERVED or upper.startswith(_RESERVED_PREFIXES):
        raise ValueError('Environment variable is reserved by the execution platform')
    return key


def validate_environment_mapping(mapping):
    if not isinstance(mapping, dict):
        raise ValueError('Environment mapping must be an object')
    for key in mapping:
        validate_environment_key(key)
    return mapping


def _reference(reference):
    if isinstance(reference, str):
        if '#' not in reference:
            raise ValueError('Vault reference must be path#field')
        path, field = reference.rsplit('#', 1)
        result = {'path': path, 'field': field}
    elif isinstance(reference, dict) and set(reference) <= {'mount', 'path', 'field', 'version'}:
        result = dict(reference)
    else:
        raise ValueError('Invalid Vault reference')
    for key in ('path', 'field'):
        value = result.get(key)
        if not isinstance(value, str) or not value or value.startswith('-') or any(c in value for c in '\x00\r\n'):
            raise ValueError('Invalid Vault reference field')
    if 'mount' in result:
        value = result['mount']
        if not isinstance(value, str) or not value or value.startswith('-') or any(c in value for c in '\x00\r\n'):
            raise ValueError('Invalid Vault mount')
    if 'version' in result and (type(result['version']) is not int or result['version'] <= 0):
        raise ValueError('Vault version must be a positive integer')
    return result


def validate_vault_mapping(mapping):
    validate_environment_mapping(mapping)
    for reference in mapping.values():
        _reference(reference)
    return mapping


def resolve_vault_secrets(mapping, host_env, vault_binary='/usr/local/bin/vault'):
    """Resolve all values using only trusted host_env; never trim field bytes.

    No fetched value enters another Vault subprocess's environment. The returned
    values may be passed to Docker only after all reads and validations succeed.
    """
    validate_vault_mapping(mapping)
    result = {}
    for key, reference in mapping.items():
        item = _reference(reference)
        command = [vault_binary, 'kv', 'get', '-field=' + item['field']]
        if item.get('mount'):
            command.append('-mount=' + item['mount'])
        if item.get('version'):
            command.append('-version=' + str(item['version']))
        command.append(item['path'])
        try:
            response = subprocess.run(command, env=dict(host_env), capture_output=True,
                                      check=True, timeout=20)
            raw = response.stdout
            value = raw.decode('utf-8') if isinstance(raw, bytes) else raw
            if not isinstance(value, str) or '\x00' in value:
                raise ValueError('Vault value is not a valid environment string')
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
            # Do not include stdout/stderr, reference paths or command arguments.
            raise RuntimeError('Required Vault credential could not be resolved') from None
        result[key] = value
    return result
