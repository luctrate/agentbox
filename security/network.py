#!/usr/bin/python3
"""Validate Docker network plans and atomically activate owned IPv4 firewall rules."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

PRIVATE=['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
         '172.16.0.0/12','192.168.0.0/16','192.0.0.0/24','198.18.0.0/15','224.0.0.0/4','240.0.0.0/4']
FORWARD_CHAIN='ABX-CATALOG-FWD'
HOST_CHAIN='ABX-CATALOG-HOST'
_RESTORE='/usr/sbin/iptables-restore'
_SAVE='/usr/sbin/iptables-save'


def run(args,check=True,**kwargs):
    return subprocess.run(args,capture_output=True,text=True,check=check,**kwargs)


def _ipv4(value,network=False):
    try:
        item=ipaddress.ip_network(value,strict=False) if network else ipaddress.ip_address(value)
    except (ValueError,TypeError):
        raise ValueError('Invalid network address') from None
    if item.version!=4:
        raise ValueError('IPv6 policies are not supported; containers must disable IPv6')
    return item


def _port(value):
    if type(value) is not int or not 1<=value<=65535:
        raise ValueError('Network ports must be integers from 1 to 65535')
    return value


def normalized_plan(policy):
    """Complete validation before network creation, rule mutation or readiness writes."""
    raw=policy.get('networks')
    if not isinstance(raw,dict) or not raw:
        raise ValueError('At least one network policy is required')
    networks={}
    names=set();bridges=set();subnets=[]
    for key,value in sorted(raw.items()):
        if not isinstance(key,str) or not key or not isinstance(value,dict):
            raise ValueError('Invalid network policy')
        permitted={'name','subnet','gateway','bridge','mode','allow','dns','brokerAccess','internal','httpsProxy'}
        if set(value)-permitted:
            raise ValueError('Unsupported network setting; domain/proxy policies are not implemented')
        for field,pattern in [('name',r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}'),('bridge',r'[A-Za-z0-9_.-]{1,15}')]:
            if not isinstance(value.get(field),str) or not re.fullmatch(pattern,value[field]):
                raise ValueError('Invalid Docker network name or bridge interface')
        if value['name'] in names or value['bridge'] in bridges:
            raise ValueError('Network names and bridge interfaces must be unique')
        names.add(value['name']);bridges.add(value['bridge'])
        subnet=_ipv4(value.get('subnet'),True);gateway=_ipv4(value.get('gateway'))
        private_pools=[ipaddress.ip_network(x) for x in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']]
        if not any(subnet.subnet_of(pool) for pool in private_pools) or not 16<=subnet.prefixlen<=30:
            raise ValueError('Docker subnets must be RFC1918 IPv4 networks with prefix /16 through /30')
        if gateway not in subnet or gateway in (subnet.network_address,subnet.broadcast_address):
            raise ValueError('Docker gateway must be a usable address in its subnet')
        if any(subnet.overlaps(other) for other in subnets):
            raise ValueError('Managed Docker subnets must not overlap')
        subnets.append(subnet)
        legacy='mode' not in value
        mode=value.get('mode','publicExceptPrivate')
        if mode not in ('publicExceptPrivate','denyAll'):
            raise ValueError('Unsupported network mode')
        allow=value.get('allow',[])
        if legacy and key=='worker':
            allow=[{'cidr':item['ip'],'protocol':'tcp','ports':[item['port']]}
                   for item in policy.get('worker_private_access',[])]
        if not isinstance(allow,list):raise ValueError('Network allow must be a list')
        normalized=[]
        for item in allow:
            if not isinstance(item,dict) or set(item)!={'cidr','protocol','ports'}:
                raise ValueError('Service rules require only cidr, protocol and ports')
            cidr=_ipv4(item['cidr'],True)
            protocol=item['protocol']
            if protocol not in ('tcp','udp'):raise ValueError('Only TCP/UDP service rules are supported')
            ports=item['ports']
            if not isinstance(ports,list) or not ports:raise ValueError('Explicit service ports are required')
            normalized.append({'cidr':str(cidr),'protocol':protocol,'ports':sorted(set(_port(p) for p in ports))})
        dns=value.get('dns',['1.1.1.1','8.8.8.8'] if legacy else [])
        if not isinstance(dns,list):raise ValueError('DNS servers must be IPv4 addresses')
        for address in dns:
            ip=_ipv4(address)
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip==ipaddress.ip_address('255.255.255.255'):
                raise ValueError('Invalid upstream DNS server')
        broker=value.get('brokerAccess',legacy and key=='manager')
        if type(broker) is not bool:raise ValueError('brokerAccess must be boolean')
        networks[key]={'name':value['name'],'bridge':value['bridge'],'subnet':str(subnet),
                       'gateway':str(gateway),'mode':mode,'allow':normalized,
                       'dns':sorted(set(dns)),'brokerAccess':broker}
        if 'internal' in value:
            if type(value['internal']) is not bool:raise ValueError('Invalid internal network flag')
            networks[key]['internal']=value['internal']
        if 'httpsProxy' in value:
            proxy=value['httpsProxy']
            if (not isinstance(proxy,dict) or set(proxy)!={'host','port','caFile','allowedHosts'} or
                    mode!='denyAll' or not value.get('internal') or dns or normalized):
                raise ValueError('Model proxy requires an internal denyAll network without DNS/service exceptions')
            if str(_ipv4(proxy['host']))!=str(gateway):raise ValueError('Proxy must bind its own bridge gateway')
            hosts=proxy['allowedHosts']
            if (not isinstance(hosts,list) or not 1<=len(hosts)<=32 or any(not isinstance(h,str) or
                    not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)*',h) or '.' not in h for h in hosts)):
                raise ValueError('Proxy requires exact domain names')
            for host in hosts:
                try:ipaddress.ip_address(host)
                except ValueError:continue
                raise ValueError('Proxy domains cannot be IP literals')
            ca=proxy['caFile']
            if not isinstance(ca,str) or not Path(ca).is_absolute() or '..' in Path(ca).parts:
                raise ValueError('Proxy CA requires a trusted absolute path')
            networks[key]['httpsProxy']=dict(proxy,allowedHosts=sorted(set(hosts)),port=_port(proxy['port']))
    # Network peers remain denied, even if a broad service CIDR would overlap them.
    for value in networks.values():
        for rule in value['allow']:
            if any(_ipv4(rule['cidr'],True).overlaps(other) for other in subnets):
                raise ValueError('Service rules must not grant access to managed container peers')
        if any(_ipv4(server) in subnet for server in value['dns'] for subnet in subnets):
            raise ValueError('DNS servers must not be managed container peers or gateways')
    deny=policy.get('deny_public_ips',[])
    if not isinstance(deny,list):raise ValueError('deny_public_ips must be a list')
    deny=sorted(set(str(_ipv4(item,True)) for item in deny))
    broker_ip=policy.get('listen')
    if broker_ip is None:
        legacy_manager=policy['networks'].get('manager',{})
        broker_ip=legacy_manager.get('gateway','127.0.0.1')
    broker_ip=str(_ipv4(broker_ip))
    if any(item['brokerAccess'] for item in networks.values()) and _ipv4(broker_ip).is_unspecified:
        raise ValueError('Broker must listen on an explicit host address')
    return {'networks':networks,'deny_public_ips':deny,'broker_ip':broker_ip,'broker_port':_port(policy.get('port',6768))}


def policy_fingerprint(policy):
    return hashlib.sha256(json.dumps(normalized_plan(policy),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def render_rules(plan,snapshot):
    """One filter-table transaction, touching only owned chains and exact hooks."""
    existing=set();rules=[]
    for line in snapshot.splitlines():
        if line.startswith(':'):existing.add(line[1:].split()[0])
        if line.startswith('-A '):rules.append(shlex.split(line))
    if not {'INPUT','FORWARD','DOCKER-USER'}<=existing:
        raise ValueError('Docker iptables backend with DOCKER-USER is required')
    chains=[FORWARD_CHAIN,HOST_CHAIN]
    entries=[]
    for key,item in plan['networks'].items():
        suffix=hashlib.sha256(key.encode()).hexdigest()[:12]
        forward='ABX-CF-'+suffix;host='ABX-CH-'+suffix
        chains.extend([forward,host]);entries.append((item,forward,host))
    output=['*filter']+[':'+chain+' - [0:0]' for chain in chains]
    # Flushing is part of the atomic restore transaction, never a live command.
    output+=['-F '+chain for chain in chains]
    for parent,owned in [('DOCKER-USER',FORWARD_CHAIN),('INPUT',HOST_CHAIN)]:
        hook=['-A',parent,'-j',owned]
        for old in rules:
            if old==hook:output.append('-D '+parent+' -j '+owned)
        output.append('-I '+parent+' 1 -j '+owned)
    if ['-A','FORWARD','-j','DOCKER-USER'] not in rules:
        output.append('-I FORWARD 1 -j DOCKER-USER')
    for item,forward,host in entries:
        output+=['-A '+FORWARD_CHAIN+' -i '+item['bridge']+' -j '+forward,
                 '-A '+HOST_CHAIN+' -i '+item['bridge']+' -j '+host]
        output.append('-A '+forward+' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
        for network in plan['networks'].values():
            output.append('-A '+forward+' -d '+network['subnet']+' -j REJECT')
        for destination in plan['deny_public_ips']:
            output.append('-A '+forward+' -d '+destination+' -j REJECT')
        for rule in item['allow']:
            for port in rule['ports']:
                output.append('-A '+forward+' -d '+rule['cidr']+' -p '+rule['protocol']+' --dport '+str(port)+' -j ACCEPT')
        for address in item['dns']:
            for protocol in ['tcp','udp']:
                output.append('-A '+forward+' -d '+address+' -p '+protocol+' --dport 53 -j ACCEPT')
        if item['mode']=='publicExceptPrivate':
            for destination in PRIVATE:
                output.append('-A '+forward+' -d '+destination+' -j REJECT')
            output.append('-A '+forward+' -j ACCEPT')
        else:output.append('-A '+forward+' -j REJECT')
        output.append('-A '+host+' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
        if item['brokerAccess']:
            broker=item['gateway'] if item.get('internal') else plan['broker_ip']
            output.append('-A '+host+' -d '+broker+' -p tcp --dport '+str(plan['broker_port'])+' -j ACCEPT')
        if item.get('httpsProxy'):
            proxy=item['httpsProxy']
            output.append('-A '+host+' -d '+proxy['host']+' -p tcp --dport '+str(proxy['port'])+' -j ACCEPT')
        output.append('-A '+host+' -j REJECT')
    output+=['-A '+FORWARD_CHAIN+' -j RETURN','-A '+HOST_CHAIN+' -j RETURN','COMMIT','']
    return '\n'.join(output)


def _validate_existing(item,found):
    data=json.loads(found.stdout)[0]
    config=data.get('IPAM',{}).get('Config',[])
    if (data.get('Driver')!='bridge' or data.get('EnableIPv6') or bool(data.get('Internal'))!=item.get('internal',False) or
        len(config)!=1 or config[0].get('Subnet')!=item['subnet'] or config[0].get('Gateway')!=item['gateway'] or
        data.get('Options',{}).get('com.docker.network.bridge.name')!=item['bridge']):
        raise ValueError('Existing Docker network does not match its policy')


def _write_readiness(policy,plan):
    readiness=policy.get('network_readiness')
    if readiness is None:return
    if not isinstance(readiness,dict) or set(readiness)!={'path','revision'}:
        raise ValueError('Invalid network readiness configuration')
    path=Path(readiness['path'])
    if not path.is_absolute() or not isinstance(readiness['revision'],str) or not readiness['revision']:
        raise ValueError('Invalid network readiness configuration')
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    content={'revision':readiness['revision'],'plan_hash':policy_fingerprint(policy),
             'networks':sorted(value['name'] for value in plan['networks'].values())}
    descriptor,temporary=tempfile.mkstemp(prefix=path.name+'.',dir=path.parent)
    temp=Path(temporary)
    try:
        with os.fdopen(descriptor,'w') as stream:
            stream.write(json.dumps(content,sort_keys=True)+'\n');stream.flush();os.fsync(stream.fileno())
            os.fchmod(stream.fileno(),0o644)
        temp.replace(path)
    finally:
        if temp.exists():temp.unlink()


def apply(policy):
    plan=normalized_plan(policy)
    # Readiness syntax is validated before any external action, too.
    readiness=policy.get('network_readiness')
    if readiness is not None and (not isinstance(readiness,dict) or set(readiness)!={'path','revision'} or
            not isinstance(readiness['path'],str) or not Path(readiness['path']).is_absolute() or
            not isinstance(readiness['revision'],str) or not readiness['revision']):
        raise ValueError('Invalid network readiness configuration')
    snapshot=run([_SAVE,'-t','filter']).stdout
    transaction=render_rules(plan,snapshot)
    run([_RESTORE,'--test','--noflush','--wait','5'],input=transaction)
    missing=[]
    for item in plan['networks'].values():
        found=run(['/usr/bin/docker','network','inspect',item['name']],False)
        if found.returncode:missing.append(item)
        else:_validate_existing(item,found)
    created=[]
    try:
        for item in missing:
            run(['/usr/bin/docker','network','create',*(['--internal'] if item.get('internal') else []),'--driver','bridge','--subnet',item['subnet'],
                 '--gateway',item['gateway'],'--opt','com.docker.network.bridge.name='+item['bridge'],
                 '--opt','com.docker.network.bridge.enable_icc=false',item['name']])
            created.append(item['name'])
        run([_RESTORE,'--noflush','--wait','5'],input=transaction)
    except Exception:
        for name in reversed(created):
            run(['/usr/bin/docker','network','rm',name],False)
        raise
    _write_readiness(policy,plan)
    print('Validated network policies activated atomically')
    return plan


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True)
    apply(json.loads(Path(parser.parse_args().config).read_text()))
