"""Compile reviewed numeric data into the audit harness, preserving a single source."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    tables=json.loads((ROOT/'research/constants/sboxes.json').read_text(encoding='utf-8'))
    out=['/* Generated from research/constants; run scripts/generate_constant_header.py. */']
    for name,record in tables.items():
        if not isinstance(record,dict) or 'hex' not in record: continue
        values=bytes.fromhex(record['hex'])
        if len(values)!=256 or len(set(values))!=256: raise ValueError(f'{name}: not a 256-byte permutation')
        out.append(f'static const uint8_t {name}[256] = {{')
        out.extend(','.join(f'0x{x:02x}' for x in values[i:i+16])+',' for i in range(0,256,16))
        out.append('};')
    des=json.loads((ROOT/'research/constants/des-tables.json').read_text(encoding='utf-8'))
    for name in ['ip','fp','pc1','pc2','e','p','shifts']:
        data=des[name]
        out.append(f'static const uint8_t des_{name}[{len(data)}] = {{'+','.join(map(str,data))+'};')
    assert len(des['s'])==8 and all(len(x)==64 for x in des['s'])
    out.append('static const uint8_t des_s[8][64] = {')
    out.extend('{'+','.join(map(str,x))+'},' for x in des['s'])
    out.append('};')
    dest=ROOT/'reference-c/constants.h'
    dest.parent.mkdir(exist_ok=True)
    dest.write_text('\n'.join(out)+'\n',encoding='utf-8',newline='\n')
    print('generated 5 x 256-byte S-boxes and DES permutation/S-box tables')
if __name__=='__main__': main()
