#!/usr/bin/env python3
"""Validate, review and apply asp.now AgentCatalog definitions."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    from agentbox_config.loader import load_catalog
    from agentbox_config.model import validate_catalog
    from agentbox_config.compiler import compile_catalog
    from agentbox_config.apply import ApplyError,Commands,deploy,read_json,reconcile_providers,digest
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    for name in ['validate','plan','apply']:
        command=sub.add_parser(name)
        command.add_argument('catalog',type=Path)
        command.add_argument('--platform',type=Path,required=name!='validate')
        command.add_argument('--paseo-config',type=Path)
        command.add_argument('--generations',type=Path,default=Path('/etc/agentbox/catalog/generations'))
        command.add_argument('--policy-link',type=Path,default=Path('/etc/agentbox/security.json'))
        command.add_argument('--manifest',type=Path,default=Path('/etc/agentbox/catalog/managed.json'))
        command.add_argument('--adopt-existing',action='store_true')
        if name=='apply':
            command.add_argument('--drain',action='store_true')
            command.add_argument('--expect-revision',help='reject a catalog changed since the reviewed plan')
            command.add_argument('--expect-deployment',help='also pin the reviewed platform/deployment bindings')
    status=sub.add_parser('status')
    status.add_argument('--manifest',type=Path,default=Path('/etc/agentbox/catalog/managed.json'))
    args=parser.parse_args()
    if args.operation=='status':
        print(json.dumps(read_json(args.manifest,{'status':'not managed by catalog'}),indent=2));return
    catalog=load_catalog(args.catalog)
    validated=validate_catalog(catalog)
    if args.operation=='validate' and not args.platform:
        print(json.dumps({'valid':True,'apiVersion':catalog['apiVersion'],
                          'agents':[item['id'] for item in catalog['agents']]},indent=2));return
    platform=read_json(args.platform)
    if not isinstance(platform,dict):raise ApplyError('Platform JSON object required')
    compilation=compile_catalog(catalog,platform)
    # Operational bindings get their own deployment identity; generation paths
    # never participate in the catalog hash or create a circular revision.
    runtime_sources={str(path.relative_to(ROOT)):path.read_text() for pattern in
        ['security/*.py','security/*.mjs','agentbox_config/*.py','schemas/*.json','requirements.txt'] for path in sorted(ROOT.glob(pattern)) if not path.name.startswith('.')}
    runtime_code_hash=digest(runtime_sources)
    deployment_revision=digest({'catalog_revision':compilation['revision'],'runtime_code_hash':runtime_code_hash,
        'runtime_policy':compilation['runtime_policy'],'provider_command':platform['provider_command']})
    platform=dict(platform,policy_path=str(args.generations.absolute()/deployment_revision/'policy.json'))
    compilation=compile_catalog(catalog,platform)
    compilation['deployment_revision']=deployment_revision
    compilation['runtime_code_hash']=runtime_code_hash
    if args.operation=='apply':
        if args.expect_revision and args.expect_revision!=compilation['revision']:
            raise ApplyError('Catalog revision differs from reviewed plan')
        if args.expect_deployment and args.expect_deployment!=deployment_revision:
            raise ApplyError('Deployment bindings differ from reviewed plan')
    config_path=args.paseo_config or Path(platform['host_home'])/'.paseo/config.json'
    if args.operation=='validate':
        print(json.dumps({'valid':True,'revision':compilation['revision']},indent=2));return
    existing=read_json(config_path)
    if existing is None:raise ApplyError('Existing Paseo configuration required: '+str(config_path))
    _,changes,_=reconcile_providers(existing,compilation['providers'],read_json(args.manifest,{}),args.adopt_existing)
    if args.operation=='plan':
        result={'revision':compilation['revision'],'deployment_revision':deployment_revision,'changes':changes,
                'providers':compilation['providers'],'runtime_policy':compilation['runtime_policy'],
                'note':'Plan does not fetch Vault secrets, create containers, or change configuration.'}
        print(json.dumps(result,indent=2));return
    result=deploy(compilation,platform,config_path,args.generations,args.policy_link,args.manifest,
                  args.adopt_existing,args.drain)
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    try:main()
    except ImportError:
        print('agentbox: install catalog dependencies: python3 -m pip install -r requirements.txt',file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print('agentbox catalog: '+str(error),file=sys.stderr);sys.exit(1)
