"""Vendor the pinned PDF.js browser assets without running package scripts."""
import base64
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
from urllib.request import urlopen

VERSION = '6.4.299'
destination = Path(__file__).resolve().parents[2] / 'src/QuillSign/wwwroot/vendor/pdfjs'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--verify', action='store_true', help='Check committed files without downloading anything.')
if parser.parse_args().verify:
    manifest = json.loads((destination / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['version'] == VERSION and manifest['license'] == 'Apache-2.0'
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    assert actual - {'manifest.json'} == set(manifest['sha256']), 'Unexpected or missing vendor file'
    for filename, expected in manifest['sha256'].items():
        path = PurePosixPath(filename)
        assert not path.is_absolute() and '..' not in path.parts
        assert hashlib.sha256(destination.joinpath(*path.parts).read_bytes()).hexdigest() == expected, filename
    print(f'Verified PDF.js {VERSION}: {len(manifest["sha256"])} files.')
    raise SystemExit(0)
with urlopen(f'https://registry.npmjs.org/pdfjs-dist/{VERSION}', timeout=30) as response:
    package = json.load(response)
assert package['version'] == VERSION and package['license'] == 'Apache-2.0'
distribution = package['dist']
assert distribution['tarball'] == f'https://registry.npmjs.org/pdfjs-dist/-/pdfjs-dist-{VERSION}.tgz'
with urlopen(distribution['tarball'], timeout=60) as response:
    archive = response.read(64 * 1024 * 1024 + 1)
assert len(archive) <= 64 * 1024 * 1024
integrity = 'sha512-' + base64.b64encode(hashlib.sha512(archive).digest()).decode()
assert integrity == distribution['integrity'], 'Package integrity mismatch'
files = {}
with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as source:
    for member in source.getmembers():
        name = PurePosixPath(member.name)
        if not member.isfile() or name.parts[0] != 'package' or '..' in name.parts:
            continue
        relative = PurePosixPath(*name.parts[1:])
        selected = str(relative) in {'build/pdf.mjs', 'build/pdf.worker.mjs', 'web/pdf_viewer.css', 'LICENSE'}
        selected |= relative.parts[0] in {'cmaps', 'standard_fonts', 'wasm'}
        # This app renders documents without the optional PDF scripting sandbox.
        if relative.name.startswith('quickjs-eval'):
            selected = False
        if not selected:
            continue
        data = source.extractfile(member).read()
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files[str(relative)] = hashlib.sha256(data).hexdigest()
assert {'build/pdf.mjs', 'build/pdf.worker.mjs', 'web/pdf_viewer.css', 'LICENSE'} <= files.keys()
manifest = {'package': 'pdfjs-dist', 'version': VERSION, 'license': 'Apache-2.0',
            'source': distribution['tarball'], 'integrity': integrity, 'sha256': dict(sorted(files.items()))}
(destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
print(f'Vendored PDF.js {VERSION}: {len(files)} files.')
