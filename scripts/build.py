"""Build Windows-only self-contained deliverables. Never install or run the service."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--dotnet', default='dotnet')
parser.add_argument('--source', help='Optional offline NuGet feed')
parser.add_argument('--rid', default='win-x64', choices=['win-x64', 'win-arm64'])
parser.add_argument('--output-root', type=Path, default=ROOT / 'build', help='Separate directory for review builds; existing packages are never overwritten')
args = parser.parse_args()
dotnet = str(Path(args.dotnet).resolve()) if Path(args.dotnet).exists() else args.dotnet
env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1', DOTNET_GENERATE_ASPNET_CERTIFICATE='false')
version = (ROOT / 'VERSION').read_text().strip()
out = args.output_root.resolve() / f'ClaudeGuard-{version}-{args.rid}'
if out.exists():
    raise SystemExit(f'Refusing to overwrite existing package: {out}')

for project, folder in [('Service', 'service'), ('App', 'app')]:
    command = ['publish', ROOT / 'src' / f'ClaudeGuard.{project}' / f'ClaudeGuard.{project}.csproj',
               '-c', 'Release', '-r', args.rid, '--self-contained', 'true', '-o', out / folder,
               '-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true',
               '-p:EnableCompressionInSingleFile=true',
               '-p:DebugType=None', '-p:RestoreConfigFile=' + str(ROOT / 'NuGet.Config')]
    if args.source:
        command += ['--source', str(Path(args.source).resolve())]
    if project == 'App':
        command += ['-p:ServicePayload=' + str(out / 'service' / 'ClaudeGuard.Service.exe')]
    subprocess.run([dotnet, *map(str, command)], cwd=ROOT, env=env, check=True)
standalone = out.parent / f'ClaudeGuard-{version}-{args.rid}.exe'
shutil.copy2(out / 'app' / 'ClaudeGuard.exe', standalone)
standalone.with_suffix('.exe.sha256').write_text(hashlib.sha256(standalone.read_bytes()).hexdigest() + '  ' + standalone.name + '\n', encoding='utf-8')
for name in ['README.md', 'SECURITY.md', 'LICENSE', 'VERSION']:
    shutil.copy2(ROOT / name, out / name)
entries = sorted(p for p in out.rglob('*') if p.is_file())
(out / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}\n' for p in entries), encoding='utf-8', newline='\n')
archive = out.parent / (out.name + '.zip')
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
    for file in sorted(out.rglob('*')):
        if file.is_file():
            z.write(file, file.relative_to(out.parent))
archive.with_suffix('.zip.sha256').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n', encoding='utf-8')
print(archive)
