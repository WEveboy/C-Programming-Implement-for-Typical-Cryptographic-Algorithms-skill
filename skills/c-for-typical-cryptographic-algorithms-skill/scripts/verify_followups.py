"""Resolve two remaining source readings without rewriting the historical 40 cases."""
import hashlib
import json
import math
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    path=ROOT/'evaluation/followup-cases.json'
    data=json.loads(path.read_text(encoding='utf-8')); rows=[]
    def check(name,actual,expected): rows.append(dict(id=name,actual=actual,expected=expected,passed=actual==expected))
    d=data['mh']; b=d['private']; n=d['modulus']; w=d['multiplier']
    check('mh-superincreasing',all(x>sum(b[:i]) for i,x in enumerate(b)),True)
    check('mh-modulus-bound',n>sum(b),True)
    check('mh-inverse',pow(w,-1,n),d['inverse'])
    a=[x*w%n for x in b];check('mh-public-all16',a,d['public'])
    c=sum(x*int(bit) for x,bit in zip(a,d['bits']));check('mh-cipher',format(c,'x'),d['cipher_hex'])
    remain=c*pow(w,-1,n)%n; decoded=[0]*len(b)
    for i in range(len(b)-1,-1,-1):
        if b[i]<=remain: decoded[i]=1;remain-=b[i]
    check('mh-decode',dict(bits=''.join(map(str,decoded)),remaining=remain),dict(bits=d['bits'],remaining=0))
    s=data['signature'];p=s['p'];g=s['generator'];a=s['private'];k=s['nonce'];h=s['hash_integer'];y=pow(g,a,p)
    r=pow(g,k,p);z=pow(k,-1,p-1)*(h+a*r)%(p-1)
    check('signature-synthetic',dict(r=r,s=z),dict(r=s['expected_r'],s=s['expected_s']))
    check('signature-equation',pow(r,z,p),pow(g,h,p)*pow(y,r,p)%p)
    check('signature-invalid-k',math.gcd(s['invalid_nonce'],p-1)>1,True)
    verified=[]
    for nonce in range(1,p-1):
        if math.gcd(nonce,p-1)!=1: continue
        r=pow(g,nonce,p)
        for h in range(p-1):
            z=pow(nonce,-1,p-1)*(h+a*r)%(p-1)
            verified.append(pow(r,z,p)==pow(g,h,p)*pow(y,r,p)%p)
    check('signature-all40-valid-small-inputs',dict(count=len(verified),all_valid=all(verified)),dict(count=40,all_valid=True))
    result=dict(scope='supplemental MH book instance and synthetic sign-plus identity; no security claim',
                input_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                checks=len(rows),passed=sum(x['passed'] for x in rows),results=rows)
    (ROOT/'evaluation/reports/followups.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(dict(checks=result['checks'],passed=result['passed'])))
    raise SystemExit(result['checks']!=result['passed'])
if __name__=='__main__': main()
