"""Independent unmasked big-integer oracle. Published test data only.
This is not the protected implementation or an operational cryptographic tool.
"""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT=Path(__file__).resolve().parents[1]
P=2**61-1
INV9=pow(9,-1,P)
INV17=pow(17,-1,P-1)
MASK64=2**64-1

def fixture_words(seed):
    state=seed
    while True:
        state=(state+0x9e3779b97f4a7c15)&MASK64
        z=((state^(state>>30))*0xbf58476d1ce4e5b9)&MASK64
        z=((z^(z>>27))*0x94d049bb133111eb)&MASK64
        v=(z^(z>>31))&P
        yield 0 if v==P else v

def logical_material(seed):
    rng=fixture_words(seed)
    values=[]
    for i in range(12):
        v=next(rng)
        while i in [8,10] and v==0:v=next(rng)
        values.append(v)
    return values

def chunks(data,width):
    return [int.from_bytes(data[i:i+width],'little') for i in range(0,len(data),width)]

def matrix(v):return [(x+sum(v))%P for x in v]
def inverse_matrix(v):return [(x-sum(v)*INV9)%P for x in v]
def polynomial(alpha,words):
    n=len(words)
    return (pow(alpha,n+1,P)+sum(t*pow(alpha,n-i,P) for i,t in enumerate(words)))%P

def seal(seed,secret,context):
    key=logical_material(seed)
    ident=bytes((seed+i*17)%256 for i in range(16))
    z=[(a+r)%P for a,r in zip(matrix(chunks(secret,4)),key[:8])]
    c=matrix([pow(x,17,P) for x in z])
    transcript=[0x504755415244,2,*chunks(ident,7),len(context),*chunks(context,7),*c]
    tags=[(polynomial(key[j],transcript)+key[j+1])%P for j in [8,10]]
    return b'PGUARD\x00\x02'+ident+b''.join(w.to_bytes(8,'little') for w in c+tags)

def recover(seed,capsule):
    key=logical_material(seed)
    z=[pow(w,INV17,P) for w in inverse_matrix(chunks(capsule[24:88],8))]
    plain=inverse_matrix([(w-r)%P for w,r in zip(z,key[:8])])
    return b''.join(w.to_bytes(4,'little') for w in plain)

def reuse_attack():
    # Deliberate forbidden provisioning reuse: the attack must succeed.
    m0=bytes(range(32));m1=bytes(255-i for i in range(32));seed=11
    c0=seal(seed,m0,b'reuse');c1=seal(seed,m1,b'reuse')
    z0=[pow(w,INV17,P) for w in inverse_matrix(chunks(c0[24:88],8))]
    z1=[pow(w,INV17,P) for w in inverse_matrix(chunks(c1[24:88],8))]
    delta=inverse_matrix([(b-a)%P for a,b in zip(z0,z1)])
    result=b''.join(((a+d)%P).to_bytes(4,'little') for a,d in zip(chunks(m0,4),delta))
    assert result==m1
    return {'attack':'known plaintext plus reused logical pad','second_key_recovered':True,
            'meaning':'Expected failure outside the permitted one-use model, retained as a negative control.'}

def check_shared_schedule():
    # Independently enumerate the 19 observed wires over F5 and compare all
    # input-pair histograms. This mirrors the published schedule, not its code.
    reference=None
    for a in range(5):
      for b in range(5):
        hist=[[0]*5 for _ in range(19)]
        for u in range(5):
          for v in range(5):
            for da in range(5):
              for db in range(5):
                for rho in range(5):
                  ar=(a-u)%5;br=(b-v)%5
                  x=(u+da)%5;xr=(ar-da)%5;y=(v+db)%5;yr=(br-db)%5
                  p00=x*y%5;p01=x*yr%5;p10=xr*y%5;p11=xr*yr%5
                  left=(p00+rho)%5;t0=(p01-rho)%5;t1=(t0+p10)%5;right=(t1+p11)%5
                  wires=[u,ar,da,x,xr,v,br,db,y,yr,rho,p00,p01,p10,p11,left,t0,t1,right]
                  assert (left+right)%5==a*b%5
                  for i,w in enumerate(wires):hist[i][w]+=1
        if reference is None:reference=hist
        assert hist==reference,(a,b)
    return {'independent_python_executions':25*5**5,'observed_wires':19,'input_pairs':25,
            'distribution_mismatches':0,'scope':'small-field multiplication gadget only'}

def retry_toy():
    # One-word transcript differences yield delta*alpha; conditioned on a valid
    # masked tag, each independent nonzero alpha is still uniform. Eight
    # different guesses cover exactly eight of 100 possible alpha pairs.
    p=11;guesses={(a,1) for a in range(1,9)}
    wins=sum((a,b) in guesses for a in range(1,p) for b in range(1,p))
    assert wins==8
    return {'field':p,'hidden_alpha_pairs':100,'guesses':8,'success_probability':wins/100,
            'bound_q_over_alpha_pairs':8/100,'scope':'illustrative one-word toy; not the production transcript'}

def main():
    raw=subprocess.check_output([str(ROOT/'build'/'audit.exe'),'vectors'],cwd=ROOT)
    vectors=[json.loads(line) for line in raw.splitlines()]
    assert len(vectors)==512
    for v in vectors:
        s=bytes.fromhex(v['secret']);a=bytes.fromhex(v['context']);c=bytes.fromhex(v['capsule'])
        assert seal(v['seed'],s,a)==c,v['seed']
        assert recover(v['seed'],c)==s,v['seed']
    arithmetic=subprocess.check_output([str(ROOT/'build'/'audit.exe'),'arithmetic'],cwd=ROOT)
    checked=0
    for line in arithmetic.splitlines():
        a,b,add,sub,mul=map(int,line.split(b','));assert (add,sub,mul)==((a+b)%P,(a-b)%P,(a*b)%P);checked+=1
    assert checked==20000
    s=4
    for _ in range(59):s=(s*s-2)%P
    assert s==0
    report={'wire_vectors':len(vectors),'arithmetic_cases':checked,'arithmetic_operations':checked*3,
            'max_seal_blinding_words':max(v['seal_words'] for v in vectors),
            'max_open_blinding_words':max(v['open_words'] for v in vectors),
            'lucas_lehmer_residue':s,'inverse9':INV9,'inverse17':INV17,
            'single_attempt_bound':(52/(P-1))**2,'eight_attempt_bound':8*(52/(P-1))**2,
            'independent_gadget_check':check_shared_schedule(),'reuse_attack':reuse_attack(),
            'bounded_retry_toy':retry_toy(),'vectors_sha256':hashlib.sha256(raw).hexdigest()}
    (ROOT/'evidence'/'vectors.jsonl').write_bytes(raw)
    (ROOT/'evidence'/'reference.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
