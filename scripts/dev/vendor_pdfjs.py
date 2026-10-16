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
FONT_VERSION = '2.1.5'
FONT_URL = 'https://github.com/liberationfonts/liberation-fonts/files/7261482/liberation-fonts-ttf-2.1.5.tar.gz'
FONT_ARCHIVE_SHA256 = '7191c669bf38899f73a2094ed00f7b800553364f90e2637010a69c0e268f25d0'
FONT_HASHES = {
    'LiberationSans-Regular.ttf': '76d04c18ea243f426b7de1f3ad208e927008f961dc5945e5aad352d0dfde8ee8',
    'LiberationSans-Bold.ttf': '788abee4c806d660e8aee46689dd8540cd4bb98da03dcc9d171ce3efd99a9173',
    'LiberationSans-Italic.ttf': 'e5bae5c4cde31f22142753855f4f8fb86da6ff39955ed3c0a11248b0d16948b0',
    'LiberationSans-BoldItalic.ttf': '698da70fc191cc5f33ad4d6d3fe830fe4624b898ea2e3169955928b7c491f1ee',
    'LICENSE': '93fed46019c38bbe566b479d22148e2e8a1e85ada614accb0211c37b2c61c19b',
}
destination = Path(__file__).resolve().parents[2] / 'src/QuillSign/wwwroot/vendor/pdfjs'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--verify', action='store_true', help='Check committed files without downloading anything.')
if parser.parse_args().verify:
    manifest = json.loads((destination / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['version'] == VERSION and manifest['license'] == 'Apache-2.0'
    assert manifest['fonts'] == {'version': FONT_VERSION, 'license': 'OFL-1.1', 'source': FONT_URL, 'archiveSha256': FONT_ARCHIVE_SHA256}
    actual = {path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
    assert actual - {'manifest.json'} == set(manifest['sha256']), 'Unexpected or missing vendor file'
    for filename, expected in manifest['sha256'].items():
        path = PurePosixPath(filename)
        assert not path.is_absolute() and '..' not in path.parts
        assert hashlib.sha256(destination.joinpath(*path.parts).read_bytes()).hexdigest() == expected, filename
    for filename, expected in FONT_HASHES.items():
        target = destination / 'standard_fonts' / ('LICENSE_LIBERATION' if filename == 'LICENSE' else filename)
        assert hashlib.sha256(target.read_bytes()).hexdigest() == expected, filename
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
        # The npm distribution's older Liberation assets are GPL with a font exception.
        # Replace them below with the upstream OFL release, retaining compatible metrics.
        if relative.name.startswith('LiberationSans-') or relative.name == 'LICENSE_LIBERATION':
            selected = False
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
with urlopen(FONT_URL, timeout=60) as response:
    font_archive = response.read(4 * 1024 * 1024 + 1)
assert len(font_archive) <= 4 * 1024 * 1024
assert hashlib.sha256(font_archive).hexdigest() == FONT_ARCHIVE_SHA256, 'Font archive integrity mismatch'
with tarfile.open(fileobj=io.BytesIO(font_archive), mode='r:gz') as source:
    for filename, expected in FONT_HASHES.items():
        member = source.getmember(f'liberation-fonts-ttf-{FONT_VERSION}/{filename}')
        assert member.isfile()
        data = source.extractfile(member).read()
        assert hashlib.sha256(data).hexdigest() == expected, filename
        relative = 'standard_fonts/' + ('LICENSE_LIBERATION' if filename == 'LICENSE' else filename)
        destination.joinpath(*PurePosixPath(relative).parts).write_bytes(data)
        files[relative] = expected
assert {'build/pdf.mjs', 'build/pdf.worker.mjs', 'web/pdf_viewer.css', 'LICENSE'} <= files.keys()
manifest = {'package': 'pdfjs-dist', 'version': VERSION, 'license': 'Apache-2.0',
            'source': distribution['tarball'], 'integrity': integrity,
            'fonts': {'version': FONT_VERSION, 'license': 'OFL-1.1', 'source': FONT_URL, 'archiveSha256': FONT_ARCHIVE_SHA256},
            'sha256': dict(sorted(files.items()))}
(destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
print(f'Vendored PDF.js {VERSION}: {len(files)} files.')
