"""Freeze explicit vectors before C execution; compare to independent library oracles."""
import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--cc',default='gcc'); args=parser.parse_args()
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    import cryptography
    rng=random.Random(20261111); cases=[]
    def add(case_id,alg,key,msg,expected,direction='enc',kind='cross-implementation'):
        cases.append(dict(id=case_id,algorithm=alg,direction=direction,key=key.hex(),input=msg.hex(),
                          expected=expected,kind=kind))
    # Published FIPS-197 Appendix C values, frozen independently of this C program.
    pt=bytes.fromhex('00112233445566778899aabbccddeeff')
    for size,expected in [(16,'69c4e0d86a7b0430d8cdb78070b4c55a'),(24,'dda97ca4864cdfe06eaf70a0ec0d7191'),(32,'8ea2b7ca516745bfeafc49904b496089')]:
        add(f'aes-{size*8}-fips','aes',bytes(range(size)),pt,expected,kind='published-vector')
    add('des-classic','des',bytes.fromhex('133457799bbcdff1'),bytes.fromhex('0123456789abcdef'),'85e813540f0ab405',kind='reference-vector')
    trace=json.loads((ROOT/'research/constants/sm4-rounds.json').read_text(encoding='utf-8'))
    add('sm4-book','sm4',bytes.fromhex(trace['key']),bytes.fromhex(trace['plaintext']),trace['ciphertext'],kind='book-vector')
    # GSMA/SAGE v1.1 test data: source availability recorded separately.
    for i,(key,iv,expected) in enumerate([
        ('00'*16,'00'*16,'27bede74018082da'),('ff'*16,'ff'*16,'0657cfa07096398b'),
        ('3d4c4be96a82fdaeb58f641db17b455b','84319aa8de6915ca1f6bda6bfbd8c766','14f1c2723279c419')]):
        add(f'zuc-sage-{i+1}','zuc',bytes.fromhex(key),bytes.fromhex(iv),expected,kind='external-test-data-transcription')
    for alg,sizes,block in [('aes',[16,24,32],16),('sm4',[16],16),('des',[8],8)]:
        for size in sizes:
            for i in range(32):
                key=rng.randbytes(size); msg=rng.randbytes(block)
                oracle=algorithms.AES(key) if alg=='aes' else algorithms.SM4(key) if alg=='sm4' else TripleDES(key*3)
                ctx=Cipher(oracle,modes.ECB()).encryptor(); encrypted=ctx.update(msg)+ctx.finalize()
                add(f'{alg}-{size}-{i}-enc',alg,key,msg,encrypted.hex())
                add(f'{alg}-{size}-{i}-dec',alg,key,encrypted,msg.hex(),'dec')
    for bits in [224,256,384,512]:
        rate=200-2*(bits//8)
        for n in sorted({0,1,3,7,8,31,63,64,rate-1,rate,rate+1,2*rate-1,2*rate,2*rate+1,1024,4096}):
            msg=rng.randbytes(n)
            add(f'sha3-{bits}-{n}',f'sha3-{bits}',b'',msg,getattr(hashlib,f'sha3_{bits}')(msg).hexdigest(),kind='hashlib-independent-oracle')
    add('legacy-keccak-empty','keccak-256',b'',b'','c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',kind='legacy-domain-regression')
    plan=ROOT/'evaluation/c-audit-cases.json'
    plan.write_text(json.dumps(dict(seed=20261111,oracle=f'cryptography {cryptography.__version__} / hashlib',cases=cases),indent=2)+'\n',encoding='utf-8',newline='\n')
    subprocess.run([sys.executable,str(ROOT/'scripts/generate_constant_header.py')],cwd=ROOT,check=True,capture_output=True,text=True)
    build=ROOT/'tmp/build';build.mkdir(parents=True,exist_ok=True)
    cc=shutil.which(args.cc)
    if cc is None: raise RuntimeError('C compiler unavailable')
    compiler=subprocess.check_output([cc,'--version'],text=True).splitlines()[0]
    runs=[]
    for opt in ['-O0','-O2']:
        exe=build/('audit'+opt+'.exe' if os.name=='nt' else 'audit'+opt)
        command=[cc,'-std=c11','-Wall','-Wextra','-Wpedantic','-Werror',opt,str(ROOT/'reference-c/audit_cli.c'),'-o',str(exe)]
        compiled=subprocess.run(command,capture_output=True,text=True)
        if compiled.returncode: raise RuntimeError(compiled.stderr)
        rows=[]
        for case in cases:
            r=subprocess.run([str(exe),case['algorithm'],case['direction'],case['key'],case['input']],capture_output=True,text=True,timeout=10)
            actual=r.stdout.strip()
            rows.append(dict(id=case['id'],exit_code=r.returncode,actual=actual,expected=case['expected'],passed=r.returncode==0 and actual==case['expected']))
        tr=subprocess.run([str(exe),'sm4trace','enc',trace['key'],trace['plaintext']],capture_output=True,text=True,check=True).stdout.splitlines()
        for i,line in enumerate(tr[:32]):
            actual=line.split(); expected=[trace['rk'][i],trace['state_after_round'][i]]
            rows.append(dict(id=f'sm4-round-{i}',actual=actual,expected=expected,passed=actual==expected))
        bad=[['aes','enc','00','00'],['sm4','enc','gg','00'],['des','enc','00'*8,'00'*9],
             ['zuc','dec','00'*16,'00'*16],['sha3-257','enc','',''],['sha3-256','dec','',''],['aes','oops','','']]
        for i,argv in enumerate(bad):
            r=subprocess.run([str(exe),*argv],capture_output=True,text=True)
            rows.append(dict(id=f'reject-{i}',exit_code=r.returncode,expected_exit=2,passed=r.returncode==2 and not r.stdout))
        runs.append(dict(optimization=opt,compile_flags=command[1:6],compile_exit=compiled.returncode,
                         compiler_diagnostics=compiled.stderr,exe_sha256=sha(exe),tests=len(rows),passed=sum(x['passed'] for x in rows),results=rows))
    report=dict(scope='independent reconstruction for numeric audit, not original book compilation or certified library',
                compiler=compiler,oracle_version=cryptography.__version__,case_plan_sha256=sha(plan),
                source_sha256=sha(ROOT/'reference-c/audit_cli.c'),header_sha256=sha(ROOT/'reference-c/constants.h'),
                scripts_sha256={p.name:sha(p) for p in [Path(__file__),ROOT/'scripts/generate_constant_header.py']},
                runs=runs,total_checks=sum(x['tests'] for x in runs),passed=sum(x['passed'] for x in runs))
    out=ROOT/'evaluation/reports/c-audit.json';out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ['runs','scripts_sha256']},ensure_ascii=False))
    for run in runs:
        failed=[x for x in run['results'] if not x['passed']]
        print(json.dumps(dict(optimization=run['optimization'],tests=run['tests'],passed=run['passed'],failures=failed),ensure_ascii=False))
    raise SystemExit(report['passed']!=report['total_checks'])
if __name__=='__main__': main()
