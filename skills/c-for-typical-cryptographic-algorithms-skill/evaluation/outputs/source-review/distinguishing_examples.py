"""New distinguishing inputs for C01; independent of the C audit executable."""
import hashlib
import json
from pathlib import Path
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

ROOT = Path(__file__).resolve().parents[3]
T = json.loads((ROOT/'research/constants/des-tables.json').read_text(encoding='utf-8'))

def perm(v, table, width):
    out = 0
    for bit in table:
        out = (out << 1) | ((v >> (width-bit)) & 1)
    return out

def subkeys(key):
    x = perm(int.from_bytes(key,'big'), T['pc1'], 64)
    c, d = x >> 28, x & ((1<<28)-1)
    out = []
    for s in T['shifts']:
        c = ((c << s) | (c >> (28-s))) & ((1<<28)-1)
        d = ((d << s) | (d >> (28-s))) & ((1<<28)-1)
        out.append(perm((c<<28)|d, T['pc2'],56))
    return out

def f(r,k):
    x = perm(r,T['e'],32)^k
    y = 0
    for i in range(8):
        b = (x >> (42-6*i)) & 63
        row = ((b >> 5)<<1)|(b & 1)
        col = (b >> 1)&15
        y = (y<<4)|T['s'][i][row*16+col]
    return perm(y,T['p'],32)

def des_decrypt(ciphertext,key,wrong_ingress=False):
    x = perm(int.from_bytes(ciphertext,'big'), T['fp'] if wrong_ingress else T['ip'],64)
    l,r = x>>32,x&0xffffffff
    for k in reversed(subkeys(key)):
        l,r = r,l^f(r,k)
    return perm((r<<32)|l,T['fp'],64).to_bytes(8,'big')

def transpose(b):
    return bytes(b[4*c+r] for r in range(4) for c in range(4))

def main():
    key = bytes.fromhex('1a2b3c4d5e6f7081')
    msg = bytes.fromhex('63616e676a693230')
    enc = Cipher(TripleDES(key*3),modes.ECB()).encryptor()
    ct = enc.update(msg)+enc.finalize()
    good = des_decrypt(ct,key)
    bad = des_decrypt(ct,key,True)
    assert good == msg and bad != msg
    ak = bytes.fromhex('134b507c9aa2d8e1fe2735416980b6cd')
    am = bytes.fromhex('000306090c0f1215181b1e2124272a2d')
    def aes(b):
        e = Cipher(algorithms.AES(ak),modes.ECB()).encryptor()
        return e.update(b)+e.finalize()
    standard = aes(am)
    endpoints_only = transpose(aes(transpose(am)))
    assert standard != endpoints_only
    result = dict(
        execution_mode='actual_execution',python='default task python',oracle=f'cryptography {cryptography.__version__}',
        des=dict(key=key.hex(),plaintext=msg.hex(),ciphertext=ct.hex(),correct_decrypt=good.hex(),wrong_initial_fp_decrypt=bad.hex(),passed=True),
        aes=dict(key=ak.hex(),plaintext=am.hex(),standard_ciphertext=standard.hex(),only_endpoint_transposition_ciphertext=endpoints_only.hex(),passed=True),
        limitations=['Tables from frozen book transcription; library provides independent implementation oracle.',
                     'AES example models endpoint-only transposition while retaining internal transforms and expanded-key layout.',
                     'No book C/C++ source compilation; no global host loading claim.'])
    result['script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    out = Path(__file__).with_name('distinguishing-results.json')
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))

if __name__ == '__main__':
    main()
