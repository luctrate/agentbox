#!/usr/bin/python3
"""Container-side agentbox client: only fixed-profile worker operations."""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid


def call(operation,data):
    url=os.environ['AGENTBOX_BROKER_URL']+'/v1/'+operation
    request=urllib.request.Request(url,json.dumps(data).encode(),
        {'Content-Type':'application/json','Authorization':'Bearer '+os.environ['AGENTBOX_BROKER_TOKEN']})
    try:
        with urllib.request.urlopen(request,timeout=90) as response:return json.load(response)
    except urllib.error.HTTPError as error:
        raise SystemExit('agentbox: '+json.load(error).get('error','Request failed'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    sub.add_parser('profiles')
    spawn=sub.add_parser('spawn')
    spawn.add_argument('--detach',action='store_true')
    spawn.add_argument('--request-id',help='Reuse a returned request ID to safely retry an ambiguous launch')
    spawn.add_argument('profile');spawn.add_argument('task')
    send=sub.add_parser('send',help='Send a follow-up to an owned worker without interrupting it')
    send.add_argument('--request-id',help='Reuse this ID to check a delivery without sending it twice')
    send.add_argument('id');send.add_argument('message')
    questions=sub.add_parser('questions',help='List an owned worker\'s structured clarification questions')
    questions.add_argument('id')
    answer=sub.add_parser('answer',help='Answer a clarification question; never approve a tool')
    answer.add_argument('--request-id',help='Reuse this ID to check a delivery without sending it twice')
    answer.add_argument('id');answer.add_argument('question_id')
    answer.add_argument('--answers',required=True,help='JSON object of exact question keys to answer strings')
    sub.add_parser('command-policy',help='Read this runtime command rules and limits')
    execute=sub.add_parser('exec',help='Submit an exact argv array to this runtime command policy')
    execute.add_argument('--request-id')
    execute.add_argument('argv',nargs=argparse.REMAINDER)
    for name in ['command-status','execute-command']:
        command=sub.add_parser(name);command.add_argument('id')
    sub.add_parser('review',help='Read this reviewer runtime assigned command')
    decide=sub.add_parser('decide',help='Decide only the command assigned to this reviewer')
    decide.add_argument('id');decide.add_argument('--fingerprint',required=True)
    decide.add_argument('--decision',choices=['allow','deny'],required=True);decide.add_argument('--reason',required=True)
    for name in ['status','logs','stop','archive','wait']:
        command=sub.add_parser(name);command.add_argument('id')
        command.add_argument('--json',action='store_true')
        if name=='wait':command.add_argument('--timeout',type=int,default=60)
    args=parser.parse_args()
    if args.operation=='command-policy':result=call('command-policy',{})
    elif args.operation=='exec':
        argv=args.argv[1:] if args.argv[:1]==['--'] else args.argv
        request_id=args.request_id or str(uuid.uuid4())
        try:result=call('command',{'argv':argv,'requestId':request_id})
        except (urllib.error.URLError,TimeoutError,OSError):
            raise SystemExit('agentbox: command delivery uncertain; retry the exact argv with --request-id '+request_id)
    elif args.operation in ('command-status','execute-command'):
        result=call('command-status' if args.operation=='command-status' else 'command-execute',{'id':args.id})
    elif args.operation=='review':result=call('review-request',{})
    elif args.operation=='decide':
        result=call('review-decision',{'id':args.id,'fingerprint':args.fingerprint,'decision':args.decision,'reason':args.reason})
    elif args.operation=='profiles':result=call('profiles',{})
    elif args.operation=='spawn':
        request_id=args.request_id or str(uuid.uuid4())
        try:result=call('spawn',{'profile':args.profile,'task':args.task,'requestId':request_id})
        except (urllib.error.URLError,TimeoutError,OSError):
            raise SystemExit('agentbox: broker unavailable; retry this exact task with --request-id '+request_id)
        if not args.detach and result.get('agentId'):result=wait(result['agentId'],60)
    elif args.operation=='wait':result=wait(args.id,args.timeout)
    elif args.operation in ('send','answer'):
        request_id=args.request_id or str(uuid.uuid4())
        data={'id':args.id,'requestId':request_id}
        if args.operation=='send':data['message']=args.message
        else:
            try:data['answers']=json.loads(args.answers)
            except ValueError:parser.error('--answers must be a JSON object')
            data['questionId']=args.question_id
        try:result=call(args.operation,data)
        except (urllib.error.URLError,TimeoutError,OSError):
            raise SystemExit('agentbox: delivery unconfirmed; check logs/questions and retry this exact request with --request-id '+request_id)
    else:result=call(args.operation,{'id':args.id})
    print(json.dumps(result,indent=2))


def wait(identifier,timeout):
    deadline=time.monotonic()+max(0,min(timeout,3600))
    while True:
        record=call('status',{'id':identifier})
        if record.get('PendingPermissions') or record.get('Status') not in ('running','starting','initializing'):
            return record
        if time.monotonic()>=deadline:return record
        time.sleep(2)


if __name__=='__main__':main()
