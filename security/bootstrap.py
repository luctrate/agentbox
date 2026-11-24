#!/usr/bin/env python3
"""Image entrypoint: seed selected model credentials privately, then exec harness.

The trusted launcher writes one JSON header before the ordinary harness protocol.
Read it without buffering ahead, so the harness receives every subsequent byte.
"""
import base64
import json
import os
from pathlib import Path
import sys

ALLOWED={'.claude/.credentials.json','.claude.json','.claude/CLAUDE.md',
         '.codex/auth.json','.codex/AGENTS.md','.config/agentbox/ca.pem'}


def main():
    raw=bytearray()
    while len(raw)<=2*1024*1024:
        value=os.read(0,1)
        if not value:raise ValueError('Missing bootstrap header')
        if value==b'\n':break
        raw.extend(value)
    else:raise ValueError('Bootstrap header too large')
    header=json.loads(raw)
    if set(header)!={'files'} or not isinstance(header['files'],dict):raise ValueError('Invalid bootstrap header')
    home=Path('/home/agent')
    os.umask(0o077)
    for name,encoded in header['files'].items():
        if name not in ALLOWED or not isinstance(encoded,str):raise ValueError('Invalid bootstrap file')
        content=base64.b64decode(encoded,validate=True)
        path=home/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with path.open('xb') as stream:stream.write(content)
    if os.environ.get('AGENTBOX_WORKSPACE_UNSHARED')=='1':
        (home/'work').mkdir(parents=True,exist_ok=True,mode=0o700)
        os.chdir(home/'work')
    os.execvp(sys.argv[1],sys.argv[1:])


if __name__=='__main__':
    try:main()
    except Exception:
        print('agentbox: private model bootstrap failed',file=sys.stderr);sys.exit(1)
