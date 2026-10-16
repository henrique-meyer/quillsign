"""Verify pinned interact.js bytes and the original license in a build or publish directory, offline."""
import argparse
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('directory', type=Path, help='Directory containing interact.min.js and LICENSE.')
args = parser.parse_args()
manifest = json.loads((root / 'src/QuillSign/Build/interact.manifest.json').read_text(encoding='utf-8'))
assert manifest['version'] == '1.10.28' and manifest['license'] == 'MIT'
target = (root / 'src/QuillSign/Build/BrowserAssets.targets').read_text(encoding='utf-8')
assert manifest['source'] in target and manifest['integrity'][7:] in target
for filename, digest in manifest['sha256'].items():
    assert digest in target
    assert hashlib.sha256((args.directory / filename).read_bytes()).hexdigest() == digest, filename
print('Verified interact.js 1.10.28 and its unmodified MIT license.')
