import json
import re
from unittest.mock import patch

import pytest

from app import MODULES, app


@pytest.fixture
def client():
    app.config['TESTING'] = True
    return app.test_client()


@pytest.mark.parametrize('module', MODULES, ids=[m['title'].split(' · ')[0] for m in MODULES])
def test_answer_contract(client, module):
    good = client.post('/api/verify', json={'task_id': module['id'], 'answer': ' ' + module['answer'] + '\n'})
    assert good.status_code == 200
    assert good.json['correct'] is True
    bad = client.post('/api/verify', json={'task_id': module['id'], 'answer': 'definitely incorrect'})
    assert bad.json['correct'] is False
    assert module['answer'] not in bad.json['message']


@pytest.mark.parametrize('payload', [None, [], 'text', {}, {'task_id': True, 'answer': 'open'},
    {'task_id': 99, 'answer': 'open'}, {'task_id': 1, 'answer': None}, {'task_id': 1, 'answer': 7},
    {'task_id': 1, 'answer': ['open']}, {'task_id': 1, 'answer': 'x' * 257}])
def test_bad_inputs(client, payload):
    result = client.post('/api/verify', data=json.dumps(payload), content_type='application/json')
    assert result.status_code == 400
    assert result.json['correct'] is False


def test_oversize_and_invalid_json(client):
    assert client.post('/api/verify', data='{' + 'x' * 5000, content_type='application/json').status_code == 413
    assert client.post('/api/verify', data='{bad', content_type='application/json').status_code == 400


def test_burp_requires_form_tampering(client):
    assert client.post('/challenge/burp', data={'role': 'guest'}).status_code == 403
    assert client.post('/challenge/burp', json={'role': 'admin'}).status_code == 403
    response = client.post('/challenge/burp', data={'role': 'admin'})
    assert response.status_code == 200
    assert response.json['flag'] == MODULES[6]['answer']


def test_public_page_contract(client):
    response = client.get('/')
    assert response.status_code == 200
    data = json.loads(re.search(r'<script id="module-data" type="application/json">(.*?)</script>', response.text, re.S).group(1))
    assert len(data) == 15
    assert [m['id'] for m in data] == list(range(1, 16))
    for module in data:
        assert 'answer' not in module
        assert all(module[key] for key in ['theory', 'analogy', 'steps', 'command', 'flags', 'question', 'hint', 'flow'])
    assert 'https://' not in response.text
    assert 'window.location.hostname' in response.text
    assert response.headers['Cache-Control'] == 'no-store'


def test_health_reports_partial(client):
    with patch('app.socket.create_connection', side_effect=OSError):
        response = client.get('/api/health')
        assert response.json['status'] == 'partial'
        assert not any(response.json['services'].values())


def test_health_reports_ready(client):
    with patch('app.socket.create_connection'):
        response = client.get('/api/health')
        assert response.json['status'] == 'ready'
        assert all(response.json['services'].values())


def test_static_does_not_expose_source(client):
    assert client.get('/static/../app.py').status_code == 404
    assert client.get('/app.py').status_code == 404
