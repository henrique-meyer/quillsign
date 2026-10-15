"""Exercise an already-running Compose stack using synthetic local data only."""
import base64
import email.utils
import hashlib
import hmac
import json
import os
from pathlib import Path
import smtplib
import subprocess
import time
import urllib.parse
import urllib.request
import uuid
from email.message import EmailMessage

ROOT = Path(__file__).resolve().parents[2]
os.chdir(ROOT)
for line in (ROOT / '.env').read_text(encoding='utf-8-sig').splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        key, value = line.split('=', 1)
        os.environ.setdefault(key.strip(), value.strip().strip('\"\''))


def compose(*args, data=None, check=True):
    result = subprocess.run(['docker', 'compose', *args], input=data, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace'))
    return result


def http(path):
    with urllib.request.urlopen(path, timeout=10) as response:
        return response.read()


def port(name, default):
    return os.environ.get(name) or str(default)


app = 'http://127.0.0.1:' + port('QUILLSIGN_APP_PORT', 5080)
mail = 'http://127.0.0.1:' + port('QUILLSIGN_MAIL_PORT', 8025)
blob = 'http://127.0.0.1:' + port('QUILLSIGN_BLOB_PORT', 10000)
account = 'quillsigndev'
marker = uuid.uuid4().hex
container = 'smoke-' + marker
database = 'QuillSignSmoke' + marker
payload = b'QuillSign synthetic persistence check'


def blob_request(method, path, body=None, query='', extra=None):
    headers = {
        'x-ms-date': email.utils.formatdate(usegmt=True),
        'x-ms-version': '2023-11-03',
    }
    headers.update(extra or {})
    length = str(len(body)) if body else ''
    canonical_headers = ''.join(k + ':' + v + '\n' for k, v in sorted(headers.items()))
    resource = '/' + account + '/' + account + '/' + path
    for key, values in sorted(urllib.parse.parse_qs(query).items()):
        resource += '\n' + key.lower() + ':' + ','.join(sorted(values))
    fields = [method, '', '', length, '', '', '', '', '', '', '', '']
    signing = '\n'.join(fields) + '\n' + canonical_headers + resource
    signature = base64.b64encode(hmac.new(
        base64.b64decode(os.environ['AZURITE_ACCOUNT_KEY']),
        signing.encode(), hashlib.sha256).digest()).decode()
    headers['Authorization'] = 'SharedKey ' + account + ':' + signature
    url = blob + '/' + account + '/' + path + ('?' + query if query else '')
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    # urllib would otherwise add a content type that is absent from the signed headers.
    if body is not None:
        request.add_header('Content-Length', str(len(body)))
        request.add_header('Content-Type', '')
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read()


def sql(query):
    return compose('exec', '-T', 'sql', 'sh', '-c',
        'SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" /opt/mssql-tools18/bin/sqlcmd '
        '-S localhost -U sa -C -b -h -1 -W', data=query.encode()).stdout


def find_message():
    for _ in range(20):
        messages = json.loads(http(mail + '/api/v1/messages'))['messages']
        if any(message['Subject'] == marker for message in messages):
            return
        time.sleep(0.5)
    raise AssertionError('SMTP message did not appear in Mailpit')


def check_services():
    assert json.loads(http(app + '/health')) == {'status': 'ok'}
    assert b'QuillSign' in http(app + '/')
    for path in ['/site.css', '/logo.svg', '/logo-mark.svg']:
        assert http(app + path)
    assert http(mail + '/readyz') is not None
    compose('exec', '-T', 'app', 'curl', '--fail', '--silent',
        'http://gotenberg:3000/health')


check_services()
sql(f'CREATE DATABASE [{database}];\nGO\nUSE [{database}];\n'
    'CREATE TABLE Persistence (Value int NOT NULL);\nINSERT Persistence VALUES (8);\nGO\n')
blob_request('PUT', container, b'', query='restype=container')
blob_request('PUT', container + '/check.txt', payload, extra={'x-ms-blob-type': 'BlockBlob'})
message = EmailMessage()
message['From'] = 'sender@example.invalid'
message['To'] = 'recipient@example.invalid'
message['Subject'] = marker
message.set_content('Synthetic local SMTP capture check; never sent to an external provider.')
with smtplib.SMTP('127.0.0.1', int(port('QUILLSIGN_SMTP_PORT', 1025)), timeout=10) as client:
    client.send_message(message)
find_message()

# An actual LibreOffice conversion must work without giving the converter internet access.
pdf = compose('exec', '-T', 'app', 'curl', '--fail', '--silent', '--max-time', '60',
    '-F', 'files=@-;filename=smoke.txt', 'http://gotenberg:3000/forms/libreoffice/convert',
    data=b'QuillSign local conversion check').stdout
assert pdf.startswith(b'%PDF-'), 'Converter did not produce a PDF'
converter_id = compose('ps', '-q', 'gotenberg').stdout.decode().strip()
network_settings = json.loads(subprocess.check_output(['docker', 'inspect', converter_id]))[0]['NetworkSettings']
assert not any(network_settings['Ports'].values()), 'Converter has a published port'
assert len(network_settings['Networks']) == 1
network_id = next(iter(network_settings['Networks'].values()))['NetworkID']
assert json.loads(subprocess.check_output(['docker', 'network', 'inspect', network_id]))[0]['Internal']

# Confirm the target responds from the ordinary app network before checking denial.
probe = ['curl', '--noproxy', '*', '--silent', '--output', '/dev/null',
         '--connect-timeout', '3', '--max-time', '5', 'http://1.1.1.1']
compose('exec', '-T', 'app', *probe)
assert compose('exec', '-T', 'gotenberg', *probe, check=False).returncode != 0, 'Converter reached public internet'
print('Service health, SMTP capture, PDF conversion, and converter isolation passed.')

compose('down')
compose('up', '-d', '--no-build', '--wait', '--wait-timeout', '180')
check_services()
assert b'8' in sql(f'SELECT Value FROM [{database}].dbo.Persistence;\nGO\n')
assert blob_request('GET', container + '/check.txt') == payload
find_message()
sql(f'DROP DATABASE [{database}];\nGO\n')
blob_request('DELETE', container, query='restype=container')
print('Stop/start and SQL, Blob, and Mailpit volume persistence passed.')
