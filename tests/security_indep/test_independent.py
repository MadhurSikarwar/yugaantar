"""Independent local-only assessment. Failing assertions express required invariants.

All keys are generated at runtime; state is isolated in OS temporary directories.
Run from workspace: .venv/Scripts/python.exe -B -m pytest tests/security -v
"""
import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from t4.crypto import sig
from t4.node.authority import Authority
from t4.node.common import open_log, b64e
from t4.node.device import Device
from t4.node.freshness import Node
from t4.node.request import respond
from t4.audit.log import AuditLog, load_or_create_signer, LOG_NAME, CHECKPOINT_NAME, canonical
from t4.audit.verify import verify_log
from t4.backup import Vault
from t4.detect.ingest import Event, Approval, iso_z
from t4.detect.engine import analyze

ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / 'track4_service.py'

@pytest.fixture
def folder():
    with tempfile.TemporaryDirectory(prefix='independent-security-') as directory:
        yield Path(directory)

def call(folder, request):
    env = dict(os.environ, TRACK4_STATE_DIR=str(folder), PYTHONDONTWRITEBYTECODE='1')
    raw = request if isinstance(request, bytes) else json.dumps(request).encode()
    p = subprocess.run([sys.executable, '-B', str(ENTRY)], input=raw, capture_output=True,
                       cwd=ENTRY.parent, env=env, timeout=8)
    assert b'Traceback' not in p.stderr
    return p

def ok(folder, request):
    p = call(folder, request)
    assert p.returncode == 0, p.stderr.decode()
    return json.loads(p.stdout)

def setup(folder):
    marker = secrets.token_hex(24)
    request = dict(op='setup', owners={'a':'alice','b':'bob','d':'disabled'},
                   contents={'a':'synthetic-A','b':'synthetic-B','d':'synthetic-D'},
                   disabled=['disabled'], key_material=marker)
    p = call(folder, request)
    assert p.returncode == 0 and json.loads(p.stdout) == {'ready':True}
    assert marker.encode() not in p.stdout + p.stderr
    assert all(marker.encode() not in f.read_bytes() for f in folder.rglob('*') if f.is_file())
    return request

@pytest.mark.parametrize('actor,asset,allowed', [('alice','a',True),('bob','b',True),
    ('bob','a',False),('missing','a',False),('alice','missing',False),('disabled','d',False)])
def test_adapter_policy(folder, actor, asset, allowed):
    setup(folder)
    result = ok(folder,dict(op='read',actor=actor,asset=asset,request_id='r'))
    assert result == ({'decision':'allow','body':'synthetic-'+asset.upper()} if allowed else {'decision':'deny'})
    audit = ok(folder,dict(op='audit',request_id='r'))
    assert audit['decision'] == result['decision'] and audit['request_id'] == 'r'

def test_adapter_revoke_duplicate_and_reset(folder):
    request = setup(folder)
    read = dict(op='read',actor='alice',asset='a',request_id='same')
    assert ok(folder,read)['decision']=='allow'
    assert ok(folder,dict(op='revoke',actor='alice'))=={}
    assert ok(folder,read)=={'decision':'deny'}
    assert ok(folder,dict(op='audit',request_id='same'))['decision']=='allow'
    assert ok(folder,dict(op='read',actor='bob',asset='b',request_id='peer'))['decision']=='allow'
    assert ok(folder,dict(op='revoke',actor='unknown'))=={}
    assert ok(folder,dict(op='nonsense'))=={'error':'unsupported_operation'}
    assert ok(folder,request)=={'ready':True}
    assert ok(folder,dict(op='audit',request_id='same'))=={'error':'unknown_request'}
    assert ok(folder,read)['decision']=='allow'

def test_kem_proof_independent_client(folder):
    from pqcrypto.kem import ml_kem_768
    setup(folder)
    pk, sk = ml_kem_768.generate_keypair()
    req = dict(op='protected_read',actor='alice',asset='a',challenge='fresh\u2603',public_key=b64e(pk))
    out=ok(folder,req)
    ss=ml_kem_768.decrypt(sk,base64.b64decode(out['ciphertext'],validate=True))
    proof=lambda c,b:hmac.new(ss,(c+b).encode(),hashlib.sha256).hexdigest()
    assert hmac.compare_digest(out['proof'],proof(req['challenge'],'synthetic-A'))
    assert out['proof']!=proof('changed','synthetic-A')
    assert out['proof']!=proof(req['challenge'],'changed')
    assert ok(folder,{**req,'actor':'bob'})=={'decision':'deny'}
    assert all(ss not in p.read_bytes() for p in folder.rglob('*') if p.is_file())
    assert ok(folder,req)['ciphertext'] != out['ciphertext']

@pytest.mark.parametrize('raw',[b'',b'{',b'[]',b'null',b'{"op":"read","op":"setup"}',
    b'{"op":NaN}',b'{"op":Infinity}',b'{"op":1e999}',b'{"op":{}}',
    b'{"op":"read","actor":null,"asset":"a","request_id":"r"}',
    b'{"op":"protected_read","actor":"alice","asset":"a","challenge":"c","public_key":"!"}',
    b'{"op":"read","actor":"\\ud800","asset":"a","request_id":"r"}',
    b'['*18+b'0'+b']'*18, b'\xff'])
def test_adapter_invalid_inputs(folder, raw):
    setup(folder)
    p=call(folder,raw)
    assert p.returncode != 0 and not p.stdout
    assert b'synthetic-' not in p.stderr
    assert ok(folder,dict(op='read',actor='alice',asset='a',request_id='after'))['decision']=='allow'

@pytest.mark.parametrize('name',['','a\n{"decision":"allow"}\r\u2028','../x\x00','\u2603', 'a'*4096])
def test_opaque_identifiers_and_log_injection(folder,name):
    ok(folder,dict(op='setup',owners={name:name},contents={name:'synthetic'},disabled=[]))
    assert ok(folder,dict(op='read',actor=name,asset=name,request_id=name))['body']=='synthetic'
    lines=(folder/'audit'/LOG_NAME).read_bytes().splitlines()
    assert len(lines)==2 and all(isinstance(json.loads(x),dict) for x in lines)
    assert verify_log(folder/'audit').ok

def test_state_corruption_denies(folder):
    setup(folder)
    p=folder/'state.json'; data=json.loads(p.read_bytes()); data['docs']['assets']['a']['owner']='bob'
    p.write_text(json.dumps(data))
    result=call(folder,dict(op='read',actor='bob',asset='a',request_id='attack'))
    assert result.returncode!=0 and b'synthetic-A' not in result.stdout+result.stderr

def test_bounded_concurrency_revocation(folder):
    setup(folder)
    jobs=[dict(op='read',actor='alice',asset='a',request_id=str(i)) for i in range(12)]
    jobs.insert(6,dict(op='revoke',actor='alice'))
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(lambda r:ok(folder,r),jobs))
    assert len(results)==13
    assert ok(folder,dict(op='read',actor='alice',asset='a',request_id='last'))=={'decision':'deny'}
    assert verify_log(folder/'audit').ok

def system(folder, vault=None):
    a=Authority.create(folder/'authority',sig,open_log(folder/'authority/log'),freshness=10,skew=2,vault=vault)
    d=Device.create(folder/'device',sig,'device-a','alice'); d.enroll(a,100)
    peer=Device.create(folder/'peer',sig,'device-b','bob'); peer.enroll(a,100)
    n=Node.provision(folder/'node',sig,open_log(folder/'node/log'),node_id='n',authority_pk=a.public_key,
                     owners={'a':'alice','b':'bob'},contents={'a':'synthetic-A','b':'synthetic-B'},freshness=10,skew=2)
    assert n.accept_list(a.issue_list(100),100)
    return a,d,peer,n

def test_node_authentication_replay_and_binding(folder):
    a,d,peer,n=system(folder)
    req=d.make_request('n','a',101)
    assert respond(n,req,101)['body']=='synthetic-A'
    restarted=Node(folder/'node',sig,open_log(folder/'node/log'))
    assert respond(restarted,req,101)=={'decision':'deny'}
    for request in [d.make_request('other','a',102),d.make_request('n','b',102,actor='bob'),
                    d.make_request('n','b',102),d.make_request('n','a',1)]:
        assert respond(n,request,102)=={'decision':'deny'}
    for field,value in [('actor','bob'),('asset','b'),('node_id','other'),('key_version',2),('nonce','changed')]:
        altered=copy.deepcopy(d.make_request('n','a',102)); altered['body'][field]=value
        assert respond(n,altered,102)=={'decision':'deny'}
    assert respond(n,peer.make_request('n','b',103),103)['body']=='synthetic-B'

def test_node_revocation_grants_and_replacement(folder):
    a,d,peer,n=system(folder)
    a.grant('bob','a',101); assert n.accept_list(a.issue_list(101),101)
    assert respond(n,peer.make_request('n','a',101),101)['body']=='synthetic-A'
    a.ungrant('bob','a',102); assert n.accept_list(a.issue_list(102),102)
    assert respond(n,peer.make_request('n','a',102),102)=={'decision':'deny'}
    a.revoke_device('device-a',103); assert n.accept_list(a.issue_list(103),103)
    assert respond(n,d.make_request('n','a',103),103)=={'decision':'deny'}
    new=Device.create(folder/'new',sig,'replacement','alice'); new.enroll(a,104)
    assert n.accept_list(a.issue_list(104),104)
    assert respond(n,new.make_request('n','a',104),104)['body']=='synthetic-A'
    a.revoke_actor('alice',105); assert n.accept_list(a.issue_list(105),105)
    assert respond(n,new.make_request('n','a',105),105)=={'decision':'deny'}
    assert respond(n,peer.make_request('n','b',105),105)['body']=='synthetic-B'

def test_forged_old_future_stale_policy(folder):
    a,d,peer,n=system(folder)
    old=a.issue_list(101); newer=a.issue_list(102)
    assert n.accept_list(newer,102)
    assert not n.accept_list(old,102)
    forged=copy.deepcopy(a.issue_list(103)); forged['body']['revoked_actors']=['bob']
    assert not n.accept_list(forged,103)
    assert not n.accept_list(a.issue_list(110),103)
    assert respond(n,d.make_request('n','a',112.001),112.001)=={'decision':'deny'}
    assert respond(n,peer.make_request('n','b',112.001),112.001)=={'decision':'deny'}

def test_rotation_cutoff(folder):
    a,d,peer,n=system(folder)
    cutoff=d.rotate(a,101,114)
    old=d.make_request('n','a',113)
    assert n.accept_list(a.issue_list(113),113)
    assert respond(n,old,113)['decision']=='allow'
    old2=d.make_request('n','a',113.5)
    assert respond(n,old2,cutoff)=={'decision':'deny'}
    assert respond(n,d.make_request('n','a',cutoff),cutoff)['decision']=='allow'

def test_backup_keeps_revocations_and_grant_removals(folder):
    v=Vault.create(folder/'vaultkeys',folder/'backups','authority')
    a,d,peer,n=system(folder,v.location())
    a.grant('bob','a',101); v.backup(a.store,'authority',102)
    a.ungrant('bob','a',103); a.revoke_device('device-a',104)
    v.restore(folder/'authority','authority')
    assert n.accept_list(a.issue_list(105),105)
    assert respond(n,d.make_request('n','a',105),105)=={'decision':'deny'}
    assert respond(n,peer.make_request('n','a',105),105)=={'decision':'deny'}

@pytest.mark.parametrize('mutation',['edit','delete','reorder','truncate','partial','checkpoint'])
def test_pinned_audit_detects_damage(folder,mutation):
    log=AuditLog(folder,load_or_create_signer(folder),checkpoint_every=1)
    for i in range(4): log.append(actor='alice',action='read',target='a',decision='allow',rule='test',request_id=str(i))
    pin=log.head(); pk=log.signer.public_key
    lines=(folder/LOG_NAME).read_bytes().splitlines(keepends=True)
    if mutation=='edit':
        item=json.loads(lines[0]); item['actor']='mallory'; lines[0]=canonical(item)+b'\n'
    elif mutation=='delete': del lines[1]
    elif mutation=='reorder': lines[0],lines[1]=lines[1],lines[0]
    elif mutation=='truncate': lines=lines[:-1]
    elif mutation=='partial': lines.append(b'{')
    else:
        rows=(folder/CHECKPOINT_NAME).read_bytes().splitlines()
        item=json.loads(rows[0]); item['sig']='00'*3309; rows[0]=canonical(item)
        (folder/CHECKPOINT_NAME).write_bytes(b'\n'.join(rows)+b'\n')
    (folder/LOG_NAME).write_bytes(b''.join(lines))
    assert not verify_log(folder,pin,pk).ok

def test_live_append_must_reject_earlier_log_damage(folder):
    """SA-001: expected to fail until the live audit integrity gap is fixed."""
    setup(folder)
    for i in range(5): ok(folder,dict(op='read',actor='alice',asset='a',request_id=str(i)))
    path=folder/'audit'/LOG_NAME
    lines=path.read_bytes().splitlines(); item=json.loads(lines[1]); item['decision']='deny'
    lines[1]=canonical(item); path.write_bytes(b'\n'.join(lines)+b'\n')
    assert not verify_log(folder/'audit').ok
    result=call(folder,dict(op='read',actor='alice',asset='a',request_id='after-damage'))
    assert result.returncode!=0 or json.loads(result.stdout)=={'decision':'deny'}, 'damaged history still permits a protected read'

def event(eid, when=1, received=None, **kw):
    base=datetime(2026,1,1,tzinfo=timezone.utc)
    t=base+timedelta(seconds=when); r=base+timedelta(seconds=when if received is None else received)
    values=dict(event_id=eid,event_time_utc=iso_z(t),received_time_utc=iso_z(r),source_clock_offset_ms=0,
        actor='alice',source_service='client',target_service='catalog',action='read',role_before='viewer',
        role_after='viewer',outcome='allow',approval_id='',session_id='s',correlation_id='c',receipt_index=0,
        event_time=t,received_time=r)
    values.update(kw); return Event(**values)

def approval(**kw):
    base=datetime(2026,1,1,tzinfo=timezone.utc)
    values=dict(approval_id='approved',approved_by='user-admin',subject='alice',operation='grant_role',
                role='report-reader',scope=('reports-east',),valid_from=base,valid_until=base+timedelta(seconds=60),effective_at=None)
    values.update(kw); return Approval(**values)

def test_detector_approval_scope_required():
    """SA-002: an approval for one service must not approve another service."""
    e=event('wrong-scope',target_service='reports-west',action='grant',role_after='report-reader',approval_id='approved')
    result=analyze([e],{'approved':approval()})
    assert result.predicted()['wrong-scope']=='unexpected_role_change', result.predicted()

def test_detector_cannot_emit_before_evidence_arrives():
    """SA-003: delayed role change arrives after the privileged access."""
    read=event('use',when=2,received=3,role_before='operator',role_after='operator',receipt_index=0)
    change=event('change',when=1,received=30,action='grant',role_after='operator',receipt_index=1)
    result=analyze([read,change],{})
    alert=next(a for a in result.alerts if a.rule=='DET-REVIEW-AFTER-ROLE-CHANGE')
    assert alert.emitted_at >= change.received_time_utc, 'alert timestamp predates receipt of necessary evidence'

def test_detector_unauthorized_revoke_does_not_suppress_alert():
    """SA-004: unapproved revocations must not explain away multi-service probing."""
    revoke=approval(operation='revoke_role',approved_by='intruder',role='report-reader',
                    effective_at=datetime(2026,1,1,tzinfo=timezone.utc))
    grant=approval(scope=('reports-east','reports-west'))
    events=[event('e1',target_service='reports-east',outcome='deny'),
            event('e2',when=2,target_service='reports-west',outcome='deny',receipt_index=1)]
    result=analyze(events,{'bad-revoke':revoke,'grant':grant})
    assert any(a.rule=='DET-LATERAL-MOVEMENT' for a in result.alerts), result.predicted()

def test_backup_removal_survives_authority_without_attached_vault(folder):
    """SA-005: restore promises to merge removals from readable current state too."""
    a,d,peer,n=system(folder)
    v=Vault.create(folder/'vaultkeys',folder/'backups','authority')
    a.grant('bob','a',101); v.backup(a.store,'authority',102)
    a.ungrant('bob','a',103)
    v.restore(folder/'authority','authority')
    assert n.accept_list(a.issue_list(104),104)
    assert respond(n,peer.make_request('n','a',104),104)=={'decision':'deny'}, 'removed grant restored'

def test_owner_mismatch_not_attributed_to_victim(folder):
    """SA-006: signature verifies device ownership, not an arbitrary actor claim."""
    from t4.detect.export import run_export, LogSource
    a,d,peer,n=system(folder)
    assert respond(n,d.make_request('n','b',101,actor='bob'),101)=={'decision':'deny'}
    exported=run_export([LogSource(folder/'node/log','node','n')],{},owners={'n':{'a':'alice','b':'bob'}})
    row=next(r for r in exported.rows if r['outcome']=='deny')
    assert row['actor']!='bob', 'denied impersonation is attributed to the victim'

@pytest.mark.parametrize('step,version',[('prepared',1),('committed',2),('applied',2),('published',2),('acknowledged',2)])
def test_external_process_kill_rotation(folder,step,version):
    """External termination after actual durable rotation steps, real ML-DSA."""
    import time
    a,d,peer,n=system(folder)
    marker=folder/'reached'
    p=subprocess.Popen([sys.executable,'-B',str(Path(__file__).with_name('crash_worker.py')),
                        str(folder),step],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    deadline=time.monotonic()+10
    try:
        while not marker.exists() and p.poll() is None and time.monotonic()<deadline:
            time.sleep(.01)
        assert marker.exists(), 'child did not reach durable step'
        p.kill(); p.communicate(timeout=5)
        restarted=Device(folder/'device',sig)
        assert restarted.info()['current']==version
        # Complete publication after restart, then check actual node authorization.
        if not restarted.info()['keys'][str(version)]['published'] or version==1:
            restarted.rotate(a,101,114)
        assert n.accept_list(a.issue_list(114),114)
        assert respond(n,restarted.make_request('n','a',114),114)['decision']=='allow'
        a.revoke_device('device-a',115)
        assert n.accept_list(a.issue_list(115),115)
        assert respond(n,restarted.make_request('n','a',115),115)=={'decision':'deny'}
    finally:
        if p.poll() is None: p.kill()
        p.communicate(timeout=5)

def test_backup_corruption_fallback(folder):
    v=Vault.create(folder/'keys',folder/'copies','authority')
    a,d,peer,n=system(folder,v.location())
    v.backup(a.store,'authority',101); v.backup(a.store,'authority',102)
    (folder/'copies/backup-00000002.json').write_bytes(b'{}')
    a.revoke_actor('alice',103)
    report=v.restore(folder/'authority','authority')
    assert report.used_id==1 and report.fell_back and report.damaged
    assert n.accept_list(a.issue_list(104),104)
    assert respond(n,d.make_request('n','a',104),104)=={'decision':'deny'}

def test_single_state_rollback_is_documented_limit(folder):
    setup(folder); old=(folder/'state.json').read_bytes()
    ok(folder,dict(op='revoke',actor='alice'))
    (folder/'state.json').write_bytes(old)
    assert ok(folder,dict(op='read',actor='alice',asset='a',request_id='rollback'))['decision']=='allow'

@pytest.mark.parametrize('offset',[-2,0,2])
def test_disconnected_revocation_bound(folder,offset):
    a,d,peer,n=system(folder)
    a.revoke_device('device-a',100.001)
    at=112.002
    assert respond(n,d.make_request('n','a',at),at+offset)=={'decision':'deny'}
    assert respond(n,peer.make_request('n','b',at),at+offset)=={'decision':'deny'}
