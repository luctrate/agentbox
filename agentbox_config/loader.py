"""Bounded, data-only YAML loading for operator-authored agent catalogs."""
import copy
import math
from pathlib import Path
import re

import yaml

MAX_BYTES = 1024 * 1024
MAX_NODES = 20000
MAX_DEPTH = 32


class CatalogError(ValueError):
    """A catalog is invalid or requests an unsupported guarantee."""


class StrictLoader(yaml.SafeLoader):
    pass


# Use JSON-like scalar resolution: avoid YAML 1.1 booleans, dates and octal surprises.
StrictLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for first, resolvers in StrictLoader.yaml_implicit_resolvers.items():
    StrictLoader.yaml_implicit_resolvers[first] = [
        item for item in resolvers if item[0] not in (
            'tag:yaml.org,2002:bool', 'tag:yaml.org,2002:timestamp',
            'tag:yaml.org,2002:int', 'tag:yaml.org,2002:float')]
StrictLoader.add_implicit_resolver('tag:yaml.org,2002:bool', re.compile(r'^(?:true|false)$'), list('tf'))
StrictLoader.add_implicit_resolver('tag:yaml.org,2002:int', re.compile(r'^-?(?:0|[1-9][0-9]*)$'), list('-0123456789'))
StrictLoader.add_implicit_resolver('tag:yaml.org,2002:float', re.compile(
    r'^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+(?:[eE][+-]?[0-9]+)?|[eE][+-]?[0-9]+)$'), list('-0123456789'))


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        if key_node.tag == 'tag:yaml.org,2002:merge':
            raise CatalogError('YAML merge keys are not supported')
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise CatalogError('All mapping keys must be strings')
        if key in result:
            raise CatalogError('Duplicate mapping key at line ' + str(key_node.start_mark.line + 1))
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _check_data(value, depth=0, count=None):
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES or depth > MAX_DEPTH:
        raise CatalogError('Catalog structure exceeds the supported size/depth')
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CatalogError('All mapping keys must be strings')
            _check_data(child, depth + 1, count)
    elif isinstance(value, list):
        for child in value:
            _check_data(child, depth + 1, count)
    elif isinstance(value, float) and not math.isfinite(value):
        raise CatalogError('Non-finite numbers are not supported')
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise CatalogError('Catalog values must be plain JSON-compatible data')
    elif isinstance(value, str) and '\x00' in value:
        raise CatalogError('NUL characters are not supported')


def loads_catalog(text):
    """Parse and validate YAML without fetching references or evaluating strings."""
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_BYTES:
        raise CatalogError('Catalog exceeds the one MiB limit')
    try:
        depth = nodes = 0
        for event in yaml.parse(text, Loader=StrictLoader):
            if isinstance(event, yaml.events.AliasEvent) or getattr(event, 'anchor', None):
                raise CatalogError('YAML anchors and aliases are not supported')
            if getattr(event, 'tag', None):
                raise CatalogError('Explicit YAML tags are not supported')
            if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
                depth += 1
                if depth > MAX_DEPTH:
                    raise CatalogError('Catalog exceeds the supported nesting depth')
            elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
            nodes += 1
            if nodes > MAX_NODES:
                raise CatalogError('Catalog exceeds the supported node count')
        data = yaml.load(text, Loader=StrictLoader)
    except CatalogError:
        raise
    except yaml.YAMLError as error:
        mark = getattr(error, 'problem_mark', None)
        location = '' if mark is None else ' at line ' + str(mark.line + 1)
        raise CatalogError('Invalid YAML' + location) from None
    _check_data(data)
    from .model import validate_catalog
    return validate_catalog(data)


def load_catalog(path):
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise CatalogError('Catalog exceeds the one MiB limit')
    try:
        return loads_catalog(path.read_text(encoding='utf-8'))
    except UnicodeError:
        raise CatalogError('Catalog must be UTF-8 text') from None
