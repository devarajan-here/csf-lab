import hashlib
from pathlib import Path
import socket
import threading

from app import app
from run_lab import handle_client


def test_preview_does_not_impersonate_ssh():
    client, server = socket.socketpair()
    worker = threading.Thread(target=handle_client, args=(server, ('local', 0), 22))
    worker.start()
    with client:
        client.settimeout(2)
        assert client.recv(1024) == b''
    worker.join(timeout=2)


def test_preview_assets_and_provenance():
    original_folder = app.static_folder
    original_preview = app.config.get('LAB_PREVIEW', False)
    try:
        app.static_folder = str(Path(__file__).resolve().parents[1] / 'preview_assets')
        app.config['LAB_PREVIEW'] = True
        with app.test_client() as client:
            assert 'Local preview' in client.get('/').text
            assert client.get('/static/hashes.txt').text.strip() == hashlib.md5(b'admin').hexdigest()
            assert 'LAB{' in client.get('/static/hidden_vault/').text
            assert client.get('/static/icmp.pcap').status_code == 200
    finally:
        app.static_folder = original_folder
        app.config['LAB_PREVIEW'] = original_preview
