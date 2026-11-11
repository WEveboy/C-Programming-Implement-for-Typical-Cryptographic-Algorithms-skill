"""Exact educational witnesses. This does not run or validate any book C code."""
import hashlib
import itertools
import json
import math
import platform
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / 'evaluation/cases.json'
results = []

def check(name, actual, expected, kind='arithmetic', known_discrepancy=False):
    if isinstance(actual, tuple):
        actual = list(actual)
    if isinstance(expected, tuple):
        expected = list(expected)
    results.append(dict(id=name, kind=kind, actual=actual, expected=expected,
                        passed=actual == expected, known_discrepancy=known_discrepancy))

def add(P, Q, p, a):
    if P is None: return Q
    if Q is None: return P
    x,y = P; u,v = Q
    if x == u and (y+v) % p == 0: return None
    slope = ((3*x*x+a)*pow(2*y,-1,p) if P == Q else (v-y)*pow(u-x,-1,p)) % p
    rx = (slope*slope-x-u) % p
    return rx, (slope*(x-rx)-y) % p

def mul(k,P,p,a):
    out = None
    while k:
        if k & 1: out = add(out,P,p,a)
        P = add(P,P,p,a); k >>= 1
    return out

def conv(a,b):
    n=len(a); c=[0]*n
    for i,x in enumerate(a):
        for j,y in enumerate(b): c[(i+j)%n] += x*y
    return c

def row(v,M):
    return [sum(x*r[j] for x,r in zip(v,M)) % 2 for j in range(len(M[0]))]

def mat(A,B): return [row(r,B) for r in A]
def transpose(A): return list(map(list,zip(*A)))

def main():
    spec=json.loads(SPEC.read_text(encoding='utf-8'))
    original={x['id']:x for x in spec['original_expectations']}
    def book(name, actual):
        case=original[name]
        check(name,actual,case['expected'],'original_book',case.get('known_discrepancy',False))
    n=43*59; phi=42*58; d=pow(13,-1,phi)
    check('rsa-private',d,937)
    book('rsa-book-first-block',pow(224,13,n))
    check('rsa-all-residues',sum(pow(pow(m,13,n),d,n)==m for m in range(n)),n)
    check('rsa-crt-all-residues',all((lambda mp,mq: mq+59*((mp-mq)*pow(59,-1,43)%43))(
        pow(c,d%42,43),pow(c,d%58,59)) == pow(c,d,n) for c in range(n)),True)
    p=11; g=2; a=5; k=7; m=6
    c1=pow(g,k,p); c2=m*pow(pow(g,a,p),k,p)%p
    book('elgamal-book',[c1,c2])
    check('elgamal-decrypt',c2*pow(pow(c1,a,p),-1,p)%p,m)
    check('elgamal-reused-nonce-ratio',(3*pow(10,k,p)%p)*pow(c2,-1,p)%p,3*pow(6,-1,p)%p)
    n=77; g=5652; lam=30
    check('paillier-mu',pow((pow(g,lam,n*n)-1)//n,-1,n),74)
    for r in [42,23]:
        c=pow(g,42,n*n)*pow(r,n,n*n)%(n*n)
        book(f'paillier-book-{"r42" if r==42 else "formula-r23"}',c)
        if math.gcd(r,n)!=1:
            check(f'paillier-r{r}-rejected',math.gcd(r,n)>1,True,'boundary')
        else:
            check(f'paillier-decrypt-r{r}',((pow(c,lam,n*n)-1)//n)*74%n,42)
    enc=lambda m,r: pow(78,m,5929)*pow(r,77,5929)%5929
    dec=lambda c: ((pow(c,30,5929)-1)//77)*pow(30,-1,77)%77
    check('paillier-all-messages',all(dec(enc(m,2))==m for m in range(77)),True)
    check('paillier-additive-wrap',dec(enc(70,2)*enc(20,3)%5929),13)
    check('paillier-invalid-r-detected',math.gcd(7,77)!=1,True,'precondition')
    G=(2,86); p=211
    Q=mul(112,G,p,1); R=mul(57,G,p,1); S=mul(57,Q,p,1)
    for name,v in [('public',Q),('ephemeral',R),('shared',S),('embedded',add((56,200),S,p,1))]:
        book('ecc-book-'+name,v)
    check('ecc-book-multiplicative-cipher',190*S[0]%p,136)
    check('ecc-book-multiplicative-decrypt',136*pow(S[0],-1,p)%p,190)
    check('ecc-book-point-count',1+sum((y*y-x*x*x-x-1)%p==0 for x in range(p) for y in range(p)),223)
    check('ecc-order',mul(223,G,p,1),None)
    check('ecc-repeated-add-vs-double-add',all((lambda k: repeat(k,G,p,1)==mul(k,G,p,1))(k) for k in range(224)),True)
    check('ecc-inverse-pair',add(G,(G[0],-G[1]%p),p,1),None,'boundary')
    check('sm2-toy-public',mul(7,(2,7),11,1),[7,2])
    book('sm2-book-shared-point',mul(7,mul(7,(2,7),11,1),11,1))
    check('sm2-toy-consistent-shared',mul(7,mul(7,(2,7),11,1),11,1),mul(49,(2,7),11,1),'cross-check')
    f=[-1,1,0,0,1]; inv=[-1,0,1,1,0]; gg=[0,-1,0,1,0]
    h=[1,2,0,-2,-1]; msg=[1,-1,1,0,0]; rand=[-1,1,0,0,0]
    check('ntru-inverse-mod3',[x%3 for x in conv(f,inv)],[1,0,0,0,0])
    check('ntru-inverse-mod16',[x%16 for x in conv(f,inv)],[1,0,0,0,0])
    check('ntru-public-key',[x%16 for x in conv(inv,gg)],[x%16 for x in h])
    c=[3*x+y for x,y in zip(conv(rand,h),msg)]
    book('ntru-book-cipher',c)
    centered=[(x+8)%16-8 for x in conv(f,c)]
    check('ntru-center-lift',centered,[-2,6,-5,-2,4])
    check('ntru-decrypt',[((x+1)%3)-1 for x in conv(inv,centered)],msg)
    # Transcribed from print 188-189; brute-force nearest-codeword is toy-only.
    GM=[[1,0,0,0,1,1,0],[0,1,0,0,1,0,1],[0,0,1,0,0,1,1],[0,0,0,1,1,1,1]]
    SS=[[1,1,0,1],[1,0,0,1],[0,1,1,1],[1,1,0,0]]
    PP=[[0,1,0,0,0,0,0],[0,0,0,0,1,0,0],[0,0,0,0,0,0,1],[1,0,0,0,0,0,0],
        [0,0,1,0,0,0,0],[0,0,0,0,0,1,0],[0,0,0,1,0,0,0]]
    pub=mat(mat(SS,GM),PP); message=[1,1,0,1]; error=[0,0,0,0,1,0,0]
    cipher=[x^y for x,y in zip(row(message,pub),error)]
    book('mceliece-book-toy-cipher',cipher)
    messages=list(map(list,itertools.product([0,1],repeat=4)))
    code=[row(v,GM) for v in messages]
    check('mceliece-toy-distance',min(sum(x^y for x,y in zip(u,v)) for i,u in enumerate(code) for v in code[i+1:]),3)
    passed=0
    for v in messages:
        for j in range(8):
            e=[int(i==j) for i in range(7)]
            noisy=[x^y for x,y in zip(row(v,pub),e)]
            unscrambled=row(noisy,transpose(PP))
            dist=[sum(x^y for x,y in zip(unscrambled,cw)) for cw in code]
            recovered_ms=messages[dist.index(min(dist))]
            recovered=[u for u in messages if row(u,SS)==recovered_ms]
            passed+=recovered==[v]
    check('mceliece-toy-16-messages-8-errors',passed,128)
    mh=spec['synthetic_expected']['mh']; weights=[x*mh['w']%mh['N'] for x in mh['b']]
    check('mh-synthetic-cipher',sum(x*y for x,y in zip(weights,mh['bits'])),mh['cipher'])
    good=0
    for bits in itertools.product([0,1],repeat=5):
        c=sum(x*y for x,y in zip(weights,bits)); target=c*pow(mh['w'],-1,mh['N'])%mh['N']; out=[0]*5
        for i in reversed(range(5)):
            if target>=mh['b'][i]: out[i]=1; target-=mh['b'][i]
        good+=(list(bits)==out and target==0)
    check('mh-all-32-messages',good,32)
    check('sha3-256-empty-oracle',hashlib.sha3_256(b'').hexdigest(),spec['synthetic_expected']['sha3_256_empty'],'external_library_oracle')
    report=dict(schema_version=1, execution_mode='actual_execution', test_scope='Python exact small-parameter self-check',
                c_implementations_tested=0, blind_evaluation=False, python=platform.python_version(),
                cases_sha256=hashlib.sha256(SPEC.read_bytes()).hexdigest(),
                script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                planned=len(results),completed=len(results),assertions_passed=sum(x['passed'] for x in results),
                known_source_mismatches=[x['id'] for x in results if not x['passed'] and x['known_discrepancy']],
                unexpected_failures=[x['id'] for x in results if not x['passed'] and not x['known_discrepancy']],results=results)
    dest=ROOT/'evaluation/reports/witnesses.json'; dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='results'},ensure_ascii=False))
    raise SystemExit(bool(report['unexpected_failures']))

def repeat(k,P,p,a):
    out=None
    for _ in range(k): out=add(out,P,p,a)
    return out

if __name__=='__main__': main()
