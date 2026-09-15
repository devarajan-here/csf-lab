"""Test the actual Python source embedded in the three-file installer."""
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.fixture(scope='module')
def support(tmp_path_factory):
    installer = (Path(__file__).resolve().parents[1] / 'setup_vulnerabilities.sh').read_text()
    source = installer.split('<<\'PY\'\n', 1)[1].split('\nPY\n', 1)[0]
    compile(source, 'lab_support.py', 'exec')
    destination = tmp_path_factory.mktemp('support') / 'lab_support.py'
    destination.write_text(source)
    return destination


def exchange(support, port, request=b''):
    return subprocess.run([sys.executable, str(support), 'listener', str(port)],
                          input=request, capture_output=True, check=True, timeout=5).stdout


def test_banner_protocols(support):
    assert b'CYBERLAB Recon' in exchange(support, 7777)
    assert b'LAB{socket_sleuth}' in exchange(support, 9001)


def test_http_auth_and_content_length(support):
    rejected = exchange(support, 8080, b'GET / HTTP/1.1\r\nHost: lab\r\n\r\n')
    assert rejected.startswith(b'HTTP/1.1 401')
    assert b'WWW-Authenticate: Basic' in rejected
    assert b'lab_session' not in rejected
    response = exchange(support, 8080, b'GET / HTTP/1.1\r\nHost: lab\r\nAuthorization: Basic c3R1ZGVudDpsZWFybmluZw==\r\n\r\n')
    headers, body = response.split(b'\r\n\r\n', 1)
    assert response.startswith(b'HTTP/1.1 200')
    assert b'Set-Cookie: lab_session=LAB{http_is_a_postcard}' in headers
    length = next(line.split(b': ')[1] for line in headers.split(b'\r\n') if line.startswith(b'Content-Length:'))
    assert int(length) == len(body)


def test_ftp_disclosure_and_bounded_commands(support):
    response = exchange(support, 2121, b'SYST\r\nSITE LABFLAG\r\nQUIT\r\n')
    assert response.startswith(b'220 CyberLab FTP Training')
    assert b'215 UNIX Type: L8' in response
    assert b'200 LAB{verify_dont_assume}' in response
    assert response.endswith(b'221 Goodbye\r\n')
    assert b'502 Command not implemented' in exchange(support, 2121, b'whoami\r\n')
    assert exchange(support, 2121, b'A' * 2048).count(b'\r\n') == 1


def test_empty_health_connections_do_not_hang(support):
    assert exchange(support, 8080) == b''
    assert exchange(support, 2121).startswith(b'220 ')
