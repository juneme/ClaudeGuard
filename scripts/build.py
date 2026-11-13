"""Build Windows-only self-contained deliverables. Never install or run the service."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--dotnet', default='dotnet')
parser.add_argument('--source', help='Optional offline NuGet feed')
parser.add_argument('--rid', default='win-x64', choices=['win-x64', 'win-arm64'])
parser.add_argument('--output-root', type=Path, default=ROOT / 'build', help='Output folder; the single EXE for this architecture is replaced after a successful build')
args = parser.parse_args()
dotnet = str(Path(args.dotnet).resolve()) if Path(args.dotnet).exists() else args.dotnet
env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1', DOTNET_GENERATE_ASPNET_CERTIFICATE='false')
output_root = args.output_root.resolve()
output_root.mkdir(parents=True, exist_ok=True)
standalone = output_root / f'ClaudeGuard-{args.rid}.exe'

with tempfile.TemporaryDirectory(dir=output_root, prefix='.staging-') as staging:
    out = Path(staging)
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
    # Stage beside the destination so replacement is atomic even when TEMP is on another drive.
    # A build/copy failure keeps the previous working EXE; no historical packages are created.
    pending = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_root, prefix='ClaudeGuard-', suffix='.tmp', delete=False) as file:
            pending = Path(file.name)
            with (out / 'app' / 'ClaudeGuard.exe').open('rb') as source:
                shutil.copyfileobj(source, file)
        digest = hashlib.sha256(pending.read_bytes()).hexdigest()
        os.replace(pending, standalone)
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    standalone.with_suffix('.exe.sha256').write_text(digest + '  ' + standalone.name + '\n', encoding='utf-8')
print(standalone)
