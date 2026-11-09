#!/usr/bin/env python3
"""Run explicit archival audits against a disposable evidence copy; no GPU access."""
import argparse
import ast
import contextlib
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
PREFIX = '/usr/lib/firmware/amdgpu/'
HASHES = {
    'rlc': '19d19bce396b6dc725acb87cdf419e6151a1b2961ff43d6e026e17ecf20c83d0',
    'smc': '0eb99764288f764fd853d6973693ffa52419cc7ba62074aee85df4a3e8d0286d',
    'sos': '67706b9e1545bf68850bf9cea97660af5972574ecb0ca30041174efbb59fac37',
}

class Relocate(ast.NodeTransformer):
    """Only replace the historical firmware path prefix in string constants."""
    def __init__(self, firmware_dir):
        self.firmware_dir = str(firmware_dir) + '/'
    def visit_Constant(self, node):
        if isinstance(node.value, str) and node.value.startswith(PREFIX):
            return ast.copy_location(ast.Constant(self.firmware_dir + node.value[len(PREFIX):]), node)
        return node

def main():
    if sys.flags.optimize:
        raise SystemExit("Python optimization disables audit assertions; use normal Python")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('audits', nargs='*', help='Exact script filenames from --list')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--all', action='store_true', help='All audits in the explicit allowlist, not all scripts')
    parser.add_argument('--firmware-dir', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    allow = json.loads((ROOT/'tools/offline-allowlist.json').read_text())
    if args.list:
        print('\n'.join(allow)); return 0
    if args.all and args.audits:
        parser.error('Choose --all or named audits')
    names = allow if args.all else args.audits
    if not names or any(n not in allow for n in names):
        parser.error('Specify allowlisted audit names or --all; use --list')
    if args.firmware_dir is None or args.output is None:
        parser.error('--firmware-dir and --output are required')
    firmware_dir = args.firmware_dir.resolve()
    output = args.output.resolve()
    if output.exists():
        parser.error('--output must be a new directory; existing results are never overwritten')
    # Always pin all three images, including dynamic filename construction in some audits.
    inputs = {}
    for kind, expected in HASHES.items():
        p = firmware_dir / f'sienna_cichlid_{kind}.bin.xz'
        actual = hashlib.sha256(lzma.decompress(p.read_bytes())).hexdigest()
        if actual != expected:
            parser.error(f'Firmware hash mismatch: {p.name}: {actual}')
        inputs[p.name] = actual
    catalog = {Path(x['path']).name:x for x in json.loads((ROOT/'tools/catalog.json').read_text())}
    for name in names:
        if hashlib.sha256((ROOT/'scripts'/name).read_bytes()).hexdigest() != catalog[name]['sha256']:
            parser.error(f'Archival script changed: {name}; review and update its provenance first')
    output.mkdir(parents=True)
    workspace = output/'workspace'
    shutil.copytree(ROOT/'evidence', workspace/'evidence')
    shutil.copytree(ROOT/'scripts', workspace/'scripts')
    logs = output/'logs'; logs.mkdir()
    original = Path.cwd()
    results = []
    try:
        os.chdir(workspace)
        for name in names:
            source = ROOT/'scripts'/name
            tree = Relocate(firmware_dir).visit(ast.parse(source.read_text(), filename=str(source)))
            ast.fix_missing_locations(tree)
            stream = io.StringIO(); passed = True
            with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
                try:
                    exec(compile(tree, str(source), 'exec'), {'__name__':'__main__','__file__':str(source)})
                except Exception:
                    passed = False; traceback.print_exc()
            (logs/(name+'.log')).write_text(stream.getvalue())
            results.append({'script':name,'passed':passed,'script_sha256':catalog[name]['sha256']})
            print(('PASS ' if passed else 'FAIL ') + name, flush=True)
    finally:
        os.chdir(original)
    report = {'scope':'Selected local assertions on pinned bytes and existing listings; not full firmware or hardware validation',
              'firmware_sha256_decompressed':inputs,'path_adaptation':'In-memory AST string-prefix substitution only; original scripts unchanged',
              'results':results,'passed':all(x['passed'] for x in results)}
    (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
