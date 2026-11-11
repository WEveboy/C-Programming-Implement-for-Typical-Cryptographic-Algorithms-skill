"""Finite algebraic checks on transcribed tables; not a second visual transcription."""
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def mul(a,b):
    out=0
    while b:
        if b&1: out^=a
        a=((a<<1)^ (0x11b if a&128 else 0))&255
        b>>=1
    return out

def main():
    rows=[]
    def check(name,actual,expected,count):
        rows.append(dict(id=name,elements=count,passed=actual==expected))
    s=json.loads((ROOT/'research/constants/sboxes.json').read_text(encoding='utf-8'))
    tables={k:list(bytes.fromhex(v['hex'])) for k,v in s.items() if isinstance(v,dict) and 'hex' in v}
    for k,v in tables.items(): check(k+'-permutation',sorted(v),list(range(256)),256)
    derived=[]
    for x in range(256):
        inv=0 if not x else next(y for y in range(1,256) if mul(x,y)==1)
        out=inv^0x63
        for n in range(1,5): out^=((inv<<n)|(inv>>(8-n)))&255
        derived.append(out)
    check('aes-s-algebraic',tables['aes_s'],derived,256)
    check('aes-inverse-composition',[tables['aes_inv'][x] for x in tables['aes_s']],list(range(256)),256)
    f=[2,3,1,1]; g=[14,11,13,9]
    matrix=[]
    for i in range(4):
        row=[]
        for j in range(4):
            x=0
            for k in range(4): x^=mul(f[(k-i)%4],g[(j-k)%4])
            row.append(x)
        matrix.append(row)
    check('aes-mix-inverse',matrix,[[int(i==j) for j in range(4)] for i in range(4)],16)
    d=json.loads((ROOT/'research/constants/des-tables.json').read_text(encoding='utf-8'))
    check('des-ip-fp',[d['ip'][i-1] for i in d['fp']],list(range(1,65)),64)
    check('des-pc1-parity',sorted(d['pc1']),[x for x in range(1,65) if x%8],56)
    check('des-pc2-unique',len(set(d['pc2'])),48,48)
    check('des-p-permutation',sorted(d['p']),list(range(1,33)),32)
    check('des-shift-total',sum(d['shifts']),28,16)
    check('des-s-row-permutations',[sorted(v[i:i+16]) for v in d['s'] for i in range(0,64,16)],[list(range(16))]*32,512)
    h=json.loads((ROOT/'research/constants/hash-version-tables.json').read_text(encoding='utf-8'))
    check('blake-sigma-permutations',[sorted(v) for v in h['blake']['sigma']],[list(range(16))]*10,160)
    for n in [4,8,16]:
        check(f'skein-permutation-{n}',sorted(h['skein'][f'permutation{n}']),list(range(n)),n)
    rotations=[x for n in [4,8,16] for row in h['skein'][f'book_rotation{n}'] for x in row]
    check('skein-old-rotation-range',len(rotations)==112 and all(0<x<64 for x in rotations),True,112)
    paths=sorted((ROOT/'research/constants').glob('*.json'))
    result=dict(scope='algebraic and shape checks; source visual review is separate',checks=len(rows),
                passed=sum(r['passed'] for r in rows),results=rows,
                input_sha256={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (ROOT/'evaluation/reports/constant-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(dict(checks=result['checks'],passed=result['passed'])))
    raise SystemExit(result['passed']!=result['checks'])

if __name__=='__main__': main()
