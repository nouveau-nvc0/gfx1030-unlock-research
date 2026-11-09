#!/usr/bin/env python3
"""Check archive integrity, script syntax and curated documentation without hardware."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote
from check_public_export import audit as audit_public_export

ROOT = Path(__file__).resolve().parents[1]

def main():
    errors = []
    manifest = json.loads((ROOT/'archive/export-manifest.json').read_text())
    entries = manifest['included'] + json.loads((ROOT/'tools/catalog.json').read_text())
    for entry in entries:
        p = ROOT/entry['path']
        if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != entry['sha256']:
            errors.append('Missing or changed archive input: '+entry['path'])
    scripts = list((ROOT/'scripts').glob('*.py'))+list((ROOT/'tools').glob('*.py'))
    for p in scripts:
        try:
            ast.parse(p.read_text(), filename=str(p))
        except SyntaxError as exc:
            errors.append(str(exc))
    docs = [ROOT/'README.md',ROOT/'AGENTS.md',ROOT/'NOTICE.md',*list((ROOT/'docs').glob('*.md'))]
    for p in docs:
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text()):
            target=unquote(target.split('#',1)[0])
            if not target or '://' in target or target.startswith('mailto:'):
                continue
            if not (p.parent/target).exists():
                errors.append(f'Broken curated link: {p.relative_to(ROOT)} -> {target}')
    for p in ROOT.rglob('*'):
        rel=p.relative_to(ROOT)
        if rel.parts[0] in {'.git','work','inputs','downloads'} or rel.parts[0].startswith('.venv'):
            continue
        if p.is_symlink():
            errors.append('Unexpected symlink: '+str(rel))
    privacy = audit_public_export()
    errors.extend(f"Public export: {x['path']}: {x['reason']}" for x in privacy['errors'])
    report={'archive_files_checked':len(manifest['included']), 'catalog_scripts_checked':len(entries)-len(manifest['included']),
            'python_syntax_checked':len(scripts),'curated_markdown_checked':len(docs),'errors':errors,'passed':not errors}
    print(json.dumps(report,indent=2))
    return 1 if errors else 0

if __name__=='__main__':
    sys.exit(main())
