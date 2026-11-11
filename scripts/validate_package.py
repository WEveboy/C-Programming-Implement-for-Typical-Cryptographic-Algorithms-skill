"""Validate a copied skill's self-contained links, metadata, resources and provenance."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def validate(root):
    failures = []
    skill = root/'skills/c-for-typical-cryptographic-algorithms-skill'
    if not skill.is_dir(): skill = root
    entry = (skill/'SKILL.md').read_text(encoding='utf-8')
    if not entry.startswith('---\nname: c-for-typical-cryptographic-algorithms-skill\n') or '\ndescription: ' not in entry:
        failures.append('frontmatter')
    links = 0
    for p in skill.rglob('*.md'):
        for link in re.findall(r'\]\(([^)]+)\)', p.read_text(encoding='utf-8')):
            if '://' in link or link.startswith('#'): continue
            dest = (p.parent/link.split('#')[0]).resolve()
            links += 1
            if not dest.is_relative_to(skill.resolve()) or not dest.exists(): failures.append(f'{p.relative_to(skill)}: {link}')
    for p in skill.rglob('*'):
        if not p.is_file(): continue
        if p.suffix in ['.exe','.png','.pdf','.pyc']: failures.append('unapproved binary '+str(p.relative_to(skill)))
        data = p.read_bytes()
        if (b'C:'+b'/Users/') in data or (b'C:'+b'\\Users\\') in data: failures.append('host path '+str(p.relative_to(skill)))
    cards = list((skill/'references/capabilities').glob('*.md'))
    for p in cards:
        text = p.read_text(encoding='utf-8')
        if any('## '+h not in text for h in ['R','I','A1','A2','E','B']): failures.append('incomplete card '+p.name)
    for report in ['c-audit.json','exact-agent-review.json','source-review-agent.json','hash-source-defects.json']:
        if not (skill/'evaluation/reports'/report).exists(): failures.append('missing '+report)
    ca = json.loads((skill/'evaluation/reports/c-audit.json').read_text(encoding='utf-8'))
    for rel, expected in [('reference-c/audit_cli.c',ca['source_sha256']),('reference-c/constants.h',ca['header_sha256']),('evaluation/c-audit-cases.json',ca['case_plan_sha256'])]:
        if hashlib.sha256((skill/rel).read_bytes()).hexdigest() != expected: failures.append('stale '+rel)
    exact=json.loads((skill/'evaluation/reports/exact-agent-review.json').read_text(encoding='utf-8'))
    for rel, key in [('scripts/exact_instance.py','subject_sha256'),('scripts/test_exact_instances.py','test_script_sha256'),('evaluation/tasks/exact-agent-cases.json','frozen_plan_sha256')]:
        if hashlib.sha256((skill/rel).read_bytes()).hexdigest()!=exact[key]: failures.append('stale '+rel)
    semantic=json.loads((skill/'evaluation/reports/source-review-agent.json').read_text(encoding='utf-8'))
    for case in semantic['cases']:
        if hashlib.sha256((skill/case['output_path']).read_bytes()).hexdigest()!=case['output_sha256']: failures.append('stale semantic output '+case['case_id'])
    result = dict(scope='structure, resource isolation and hash binding; no host installation claim',relative_links=links,cards=len(cards),failures=failures)
    print(json.dumps(result,ensure_ascii=False))
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);args=parser.parse_args()
    raise SystemExit(bool(validate(args.root)['failures']))
