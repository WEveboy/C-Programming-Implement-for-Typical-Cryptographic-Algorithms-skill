"""Compare fetched complete remote tree JSON to a frozen local public tree."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser();p.add_argument('public_root',type=Path);p.add_argument('remote_tree',type=Path);a=p.parse_args()
    tree=json.loads(a.remote_tree.read_text(encoding='utf-8'))
    if tree.get('truncated'): raise SystemExit('remote tree truncated')
    remote={x['path']:x['sha'] for x in tree['tree'] if x['type']=='blob'}
    local={}
    for f in a.public_root.rglob('*'):
        if f.is_file():
            b=f.read_bytes();local[f.relative_to(a.public_root).as_posix()]=hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest()
    errors=[key for key in set(remote)|set(local) if remote.get(key)!=local.get(key)]
    print(json.dumps(dict(expected=len(local),remote=len(remote),matched=sum(remote.get(k)==v for k,v in local.items()),differences=sorted(errors))))
    raise SystemExit(bool(errors))


if __name__=='__main__': main()
