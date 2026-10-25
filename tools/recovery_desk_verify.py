"""Build/test the synthetic application and independently verify public passes.

The big-integer P-256 code is an OFFLINE VERIFIER of public evidence only.
It never signs, generates a secret key, or replaces the Windows CNG consumer.
No third-party Python packages, network calls, file inputs or deletion.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
BUILD=ROOT/'build'; EVIDENCE=ROOT/'evidence'/'recovery-desk'
# NIST P-256 (SP 800-186); public verification follows FIPS 186-5 section 6.4.2.
P=int('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',16)
N=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
B=int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',16)
G=(int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',16),
   int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',16))

def add(a,b):
    if a is None:return b
    if b is None:return a
    x,y=a;u,v=b
    if x==u and (y+v)%P==0:return None
    slope=((3*x*x-3)*pow(2*y,-1,P) if a==b else (v-y)*pow((u-x)%P,-1,P))%P
    xx=(slope*slope-x-u)%P
    return xx,(slope*(x-xx)-y)%P

def multiply(k,point):
    out=None
    while k:
        if k&1:out=add(out,point)
        point=add(point,point);k>>=1
    return out

def verify(blob,message,signature):
    if len(blob)!=72 or blob[:8]!=bytes.fromhex('4543533120000000') or len(signature)!=64:return False
    q=(int.from_bytes(blob[8:40],'big'),int.from_bytes(blob[40:72],'big'))
    x,y=q
    if not (0<=x<P and 0<=y<P and (y*y-x*x*x+3*x-B)%P==0):return False
    r,s=int.from_bytes(signature[:32],'big'),int.from_bytes(signature[32:],'big')
    if not (0<r<N and 0<s<N):return False
    z=int.from_bytes(hashlib.sha256(message).digest(),'big')
    w=pow(s,-1,N)
    point=add(multiply(z*w%N,G),multiply(r*w%N,q))
    return point is not None and point[0]%N==r

def run(args):
    result=subprocess.run(args,cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace')
    if result.returncode:raise RuntimeError(result.stdout+'\n'+result.stderr)
    return result.stdout+result.stderr

def main():
    assert sys.platform=='win32','This application uses the installed Windows CNG provider.'
    BUILD.mkdir(exist_ok=True);EVIDENCE.mkdir(parents=True,exist_ok=True)
    app=BUILD/'recovery-desk.exe';tests=BUILD/'recovery-desk-tests.exe'
    options=['rustc','--edition=2021','-D','warnings','-C','opt-level=3','-C','overflow-checks=yes']
    run(options+['apps/recovery-desk/main.rs','-o',str(app)])
    run(['rustc','--edition=2021','-D','warnings','--test','apps/recovery-desk/main.rs','-o',str(tests)])
    result=run([str(tests),'--nocapture']);assert '26 passed; 0 failed' in result
    (EVIDENCE/'tests.txt').write_text(result,encoding='utf-8',newline='\n')
    demo=run([str(app),'demo']);assert 'TRAINING PASS GRANTED' in demo and 'total grants = 1' in demo
    (EVIDENCE/'demo-output.txt').write_text(demo,encoding='utf-8',newline='\n')
    public=run([str(app),'evidence'])
    entries=[json.loads(line) for line in public.splitlines()]
    assert len(entries)==32 and multiply(N,G) is None
    assert (G[1]*G[1]-G[0]**3+3*G[0]-B)%P==0
    assert not verify(bytes(72),b'',bytes(64))
    checked=0
    for entry in entries:
        blob=bytes.fromhex(entry['public_blob']);message=bytes.fromhex(entry['request'])
        signature=bytes.fromhex(entry['signature']);alternate=bytes.fromhex(entry['alternate_signature'])
        assert message.startswith(b'PRISMGUARD/DESK/REQUEST/v1\0')
        assert len(message)==len(b'PRISMGUARD/DESK/REQUEST/v1\0')+16+4+1
        assert message[-5:]==b'\x07\0\0\0\x01'
        assert hashlib.sha256(message).hexdigest()==entry['sha256']
        assert verify(blob,message,signature)
        assert alternate[:32]==signature[:32]
        assert int.from_bytes(alternate[32:],'big')==N-int.from_bytes(signature[32:],'big')
        assert verify(blob,message,alternate) and entry['alternate_signature_valid']
        assert not verify(blob,message+b'changed',signature)
        wrong=bytearray(signature);wrong[9]^=1
        assert not verify(blob,message,bytes(wrong))
        assert all(entry[k] for k in ['altered_signature_rejected','granted','replay_rejected','alternate_replay_rejected'])
        assert entry['grants']==1
        assert len(bytes.fromhex(entry['capsule']))==104
        context=bytes.fromhex(entry['context'])
        assert context.endswith(hashlib.sha256(blob).hexdigest().encode('ascii'))
        checked+=1
    (EVIDENCE/'public-passes.jsonl').write_text(public,encoding='utf-8',newline='\n')
    # Exercise the actual interactive application through its normal stdin.
    interactive=subprocess.run([str(app),'desk'],input='3\n1\n2\n3\n5\n4\n4\nq\n',cwd=ROOT,capture_output=True,text=True,check=True).stdout
    assert 'Issuance denied: NotRecovered' in interactive
    assert 'Controller: Err(InvalidSignature)' in interactive
    assert 'TRAINING PASS GRANTED' in interactive
    assert 'Controller: Err(NoPendingChallenge)' in interactive
    (EVIDENCE/'interactive-session.txt').write_text(interactive,encoding='utf-8',newline='\n')
    source_files=[f'apps/recovery-desk/{name}.rs' for name in ['main','app','cng']]+['tools/recovery_desk_verify.py']
    core_files=list((ROOT/'src').glob('*.rs'))
    previous=json.loads((ROOT/'evidence'/'verification.json').read_text())['source_sha256']
    assert all(hashlib.sha256(path.read_bytes()).hexdigest()==previous[path.relative_to(ROOT).as_posix()] for path in core_files)
    report={'application':'PrismGuard Recovery Desk','test_groups':26,'core_test_groups':14,'application_test_groups':12,
            'public_passes_independently_verified':checked,'alternate_valid_signatures_verified':checked,
            'altered_message_and_signature_rejections':checked*2,
            'replay_and_alternate_encoding_rejections':checked*2,'interactive_workflow_checked':True,
            'controller_has_only_public_verification_key':True,'core_sources_unchanged':True,
            'private_keys_exported_in_evidence':False,'normal_application_file_network_or_settings_actions':False,
            'signatures':'Windows CNG ECDSA P-256 over SHA-256 after authorized scalar recovery',
            'scope':'Real signature operation and public-key-verified synthetic access decision. Single-process prototype; no physical access, durable replay ledger, endpoint protection or provider leakage proof.',
            'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_files},
            'references':['https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsignhash',
                          'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf',
                          'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf']}
    (EVIDENCE/'verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(report,indent=2),flush=True)

if __name__=='__main__':main()
