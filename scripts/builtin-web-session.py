#!/usr/bin/env python3
"""Owned local web services for the normal development App. No supplier calls.

prepare explicitly applies additive API migrations. ensure never migrates.
stop uses each Go service's normal SIGTERM handler and retains pending owners.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[1]
WORKSPACE=ROOT.parent
STATE=ROOT/'environments/local/generated/builtin-web'
API=WORKSPACE/'yijie-api'
CONNECTORS=WORKSPACE/'yijie-connectors'
RECORD=STATE/'services.json'

def require(ok,message):
    if not ok:raise RuntimeError(message)
def write(path,value):
    temporary=path.with_suffix(path.suffix+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w')as out:out.write(value)
    temporary.replace(path)
def run(args,cwd=ROOT,env=None):
    result=subprocess.run(args,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    if result.returncode:
        write(STATE/'last-command.log',result.stdout)
        raise RuntimeError('本机服务准备未完成；请查看受管日志，不会强制停止进程。')
    return result.stdout
def docker():
    cli=next((p for p in ['/usr/local/bin/docker','/opt/homebrew/bin/docker']if Path(p).is_file()),'docker')
    return [cli]
def postgres():
    # Original approved local dependency/volume; never recreate or delete it.
    run([*docker(),'compose','-f',str(ROOT/'docker-compose.local.yml'),'up','-d','--no-recreate','--wait','postgres'])
    info=json.loads(run([*docker(),'inspect','yijie-postgres']))[0]
    require(info['Config']['Labels'].get('com.docker.compose.service')=='postgres','PostgreSQL 服务身份不匹配。')
    require(info['HostConfig']['PortBindings'].get('5432/tcp')==[{'HostIp':'127.0.0.1','HostPort':'5432'}],'PostgreSQL 必须使用原 loopback 入口。')
    version=run([*docker(),'exec','yijie-postgres','psql','-U','yijie','-d','yijie_api','-Atc',"SELECT COALESCE((SELECT max(version_id) FROM goose_db_version WHERE is_applied),0)"] ) if table_exists() else '0'
    return int(version.strip())
def table_exists():
    return run([*docker(),'exec','yijie-postgres','psql','-U','yijie','-d','yijie_api','-Atc',"SELECT to_regclass('public.goose_db_version') IS NOT NULL"]).strip()=='t'
def fingerprint():
    h=hashlib.sha256()
    for repo,folders in [(API,['cmd/web-local-server','cmd/migrate','internal/app','internal/platform','internal/modules/authorization','internal/modules/tenancy','internal/modules/webretrieval','internal/contracts/builtinweb']), (CONNECTORS,['cmd/web-executor','internal/webexecutor','internal/worker','internal/contracts/builtinweb'])]:
        paths=[repo/'go.mod',repo/'go.sum']
        for folder in folders:paths+=list((repo/folder).rglob('*'))
        for path in sorted(p for p in paths if p.is_file() and not p.name.endswith('_test.go')):h.update(str(path.relative_to(WORKSPACE)).encode());h.update(path.read_bytes())
    return h.hexdigest()
def identity(pid):
    result=subprocess.run(['/bin/ps','-ww','-p',str(pid),'-o','lstart=','-o','command='],capture_output=True,text=True)
    return result.stdout.strip() if result.returncode==0 else None
def owned():return json.loads(RECORD.read_text()) if RECORD.exists() else {}
def active(state):
    result=[]
    for name,item in state.items():
        current=identity(item['pid'])
        if current:
            require(current==item['identity'],'原服务进程身份变化；保留现场。')
            result.append(name)
    return result
def certificates():
    if (STATE/'ca.pem').exists():return
    run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(STATE/'ca.key'),'-out',str(STATE/'ca.pem'),'-days','365','-subj','/CN=Yijie local web service CA'])
    for role in ['api','web-executor']:
        write(STATE/(role+'.ext'),'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost,URI:spiffe://yijie/services/'+role+'\n')
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(STATE/(role+'.key')),'-out',str(STATE/(role+'.csr')),'-subj','/CN='+role])
        run(['openssl','x509','-req','-in',str(STATE/(role+'.csr')),'-CA',str(STATE/'ca.pem'),'-CAkey',str(STATE/'ca.key'),'-CAcreateserial','-out',str(STATE/(role+'.pem')),'-days','90','-extfile',str(STATE/(role+'.ext'))])
def build():
    source=fingerprint();stamp=STATE/'build.json'
    if stamp.exists() and json.loads(stamp.read_text()).get('source')==source:return
    require(not active(owned()),'请先通过易界正常退出服务，再更新本机服务源码。')
    (STATE/'bin').mkdir(mode=0o700,exist_ok=True)
    for repo,target in [(API,'web-local-server'),(API,'migrate'),(CONNECTORS,'web-executor')]:
        run(['go','build','-o',str(STATE/'bin'/target),'./cmd/'+target],repo)
    write(stamp,json.dumps({'source':source}))
def configuration():
    policy=json.loads((WORKSPACE/'yijie-contracts/compatibility/builtin-web-retrieval/policy.json').read_text())
    require(policy['local_demo']['api_origin']=='http://127.0.0.1:18890','本机服务契约不匹配。')
    key=Path(os.environ.get('YIJIE_WEB_KIMI_KEY_FILE',str(WORKSPACE/'yijie-agent-host/.local/secrets/kimi-api-key')))
    require(key.is_absolute() and key.is_file(),'服务端 Kimi Key 文件不可用；不会向用户索取或从前端读取。')
    manifest=CONNECTORS/'bin/market-worker/current.json'
    require(manifest.is_file(),'请先由 canonical worker 构建入口准备产品 worker。')
    base={**os.environ,'YIJIE_ENV':'local','YIJIE_LOCAL_PROFILE':'demo_fast'}
    api={**base,'YIJIE_API_BUILTIN_WEB_ENABLED':'true','YIJIE_API_WEB_DAILY_TENANT_CALLS':'100','YIJIE_API_WEB_EXECUTOR_ORIGIN':'https://127.0.0.1:18891','YIJIE_API_WEB_INTERNAL_ADDRESS':'127.0.0.1:18892','YIJIE_API_WEB_CERT_FILE':str(STATE/'api.pem'),'YIJIE_API_WEB_KEY_FILE':str(STATE/'api.key'),'YIJIE_API_WEB_CA_FILE':str(STATE/'ca.pem'),'YIJIE_WEB_LOCAL_CREDENTIAL_FILE':str(STATE/'native.json'),'YIJIE_WEB_LOCAL_DSN_FILE':str(STATE/'postgres-dsn')}
    executor={**base,'YIJIE_WEB_EXECUTOR_ADDRESS':'127.0.0.1:18891','YIJIE_WEB_API_ORIGIN':'https://127.0.0.1:18892','YIJIE_WEB_SERVICE_CERT_FILE':str(STATE/'web-executor.pem'),'YIJIE_WEB_SERVICE_KEY_FILE':str(STATE/'web-executor.key'),'YIJIE_WEB_SERVICE_CA_FILE':str(STATE/'ca.pem'),'YIJIE_WEB_WORKER_MANIFEST':str(manifest),'YIJIE_WEB_KIMI_KEY_FILE':str(key)}
    return api,executor
def ready():
    try:
        credential=json.loads((STATE/'native.json').read_text())
        with urllib.request.urlopen('http://127.0.0.1:18890/readyz',timeout=2)as response:value=json.load(response)
        require(value.get('run_epoch')==credential['run_epoch'],'本机 API 身份不匹配。')
        # API readiness uses its production Go mTLS client to check the executor.
        return value.get('status')=='ready'
    except (OSError,ValueError,RuntimeError):return False
def ensure():
    require((STATE/'native.json').is_file(),'本机网页服务尚未 prepare；普通启动不会隐式迁移数据库。')
    require(postgres()==8,'本机 API schema 尚未迁移到 8；请执行显式 prepare。')
    build();state=owned();running=active(state)
    worker=json.loads((CONNECTORS/'bin/market-worker/current.json').read_text())['sha256']
    if len(running)==2 and ready():
        require(state['web-executor'].get('worker_sha256')==worker,'运行中的网页执行器使用旧版 worker，请通过易界正常退出后启动。')
        print('BUILTIN_WEB_READY');return
    require(not running,'本机网页服务尚未正常结束；不会覆盖或重放。')
    api,executor=configuration()
    for name,env in [('web-executor',executor),('web-local-server',api)]:
        log=os.open(STATE/(name+'.log'),os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
        process=subprocess.Popen([str(STATE/'bin'/name)],env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True);os.close(log)
        observed=identity(process.pid);require(observed is not None,'服务启动未完成，请查看受管日志。')
        state[name]={'pid':process.pid,'identity':observed}
        if name=='web-executor':state[name]['worker_sha256']=worker
        write(RECORD,json.dumps(state))
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        if ready():print('BUILTIN_WEB_READY');return
        time.sleep(.2)
    raise RuntimeError('服务未就绪；保留原进程和日志，不强杀。')
def stop():
    state=owned()
    for name in ['web-local-server','web-executor']:
        if name not in state:continue
        item=state[name];current=identity(item['pid'])
        if not current:continue
        require(current==item['identity'],'原进程身份变化；不发送退出请求。')
        # Both services explicitly implement graceful signal.NotifyContext.
        os.kill(item['pid'],signal.SIGTERM)
        deadline=time.monotonic()+55
        while identity(item['pid']) is not None and time.monotonic()<deadline:time.sleep(.2)
        require(identity(item['pid']) is None,'STOP_PENDING：仍在正常退出；保留进程，不强杀。')
    write(RECORD,'{}');print('BUILTIN_WEB_STOPPED')
def prepare():
    require(not active(owned()),'请先正常退出易界和本机网页服务。')
    postgres();build();certificates()
    if not (STATE/'native.json').exists():write(STATE/'native.json',json.dumps({'schema_version':1,'run_epoch':str(uuid.uuid4()),'token':secrets.token_hex(32)}))
    # Approved local dependency credentials, never copied into public config.
    write(STATE/'postgres-dsn','postgres://yijie:yijie@127.0.0.1:5432/yijie_api?sslmode=disable')
    env={**os.environ,'YIJIE_API_POSTGRES_DSN':(STATE/'postgres-dsn').read_text()}
    run([str(STATE/'bin/migrate'),'up'],API,env)
    print('BUILTIN_WEB_PREPARED: schema and private local identity ready; supplier requests=0')
def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['prepare','ensure','stop','ready']);args=parser.parse_args()
    os.umask(0o077);STATE.mkdir(parents=True,mode=0o700,exist_ok=True)
    require(STATE.resolve()==STATE and STATE.stat().st_uid==os.geteuid() and STATE.stat().st_mode&0o077==0,'本机服务状态目录必须属于当前用户且私有。')
    with (STATE/'controller.lock').open('a+')as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action=='ready':require(ready(),'BUILTIN_WEB_NOT_READY');print('BUILTIN_WEB_READY')
        else:globals()[args.action]()
if __name__=='__main__':
    try:main()
    except (RuntimeError,OSError,ValueError,subprocess.SubprocessError)as error:print(str(error),file=sys.stderr);sys.exit(1)
