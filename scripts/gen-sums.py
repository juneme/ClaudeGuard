"""Deterministic source manifest for the Windows-only project."""
import hashlib
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
files = [p for base in ('src', 'scripts') for p in (root / base).rglob('*')
         if p.is_file() and p.suffix in ('.cs', '.csproj', '.xaml', '.manifest', '.ico', '.py', '.sh')
         and not {'bin', 'obj', '__pycache__'}.intersection(p.relative_to(root).parts)]
files += [root / name for name in ('Directory.Build.props', 'NuGet.Config', 'global.json', 'VERSION', 'README.md', 'SECURITY.md', 'AGENTS.md', 'LICENSE', '.gitignore', '.gitattributes')]
content = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n' for p in sorted(files))
manifest = root / 'SHA256SUMS'
if '--check' in sys.argv:
    if manifest.read_text(encoding='utf-8') != content:
        raise SystemExit('SHA256SUMS is stale; run python scripts/gen-sums.py')
    print('Source checksums verified')
else:
    manifest.write_text(content, encoding='utf-8', newline='\n')
    print('SHA256SUMS updated')
