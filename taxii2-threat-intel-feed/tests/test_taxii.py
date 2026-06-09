"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

"""Tests for the TAXII Threat Intel Feed connector — focused on the v2.0.0 auth + custom-headers changes."""

from base64 import b64encode

import pytest


@pytest.fixture
def ops(load_connector):
    return load_connector('taxii2-threat-intel-feed')


def _config(**overrides):
    base = {
        'server_url': 'https://taxii.example.com/taxii/root',
        'auth_type': 'Basic',
        'username': 'alice',
        'password': 'secret', #pragma: allowlist secret
        'headers': {},
        'verify_ssl': False,
    }
    base.update(overrides)
    return base


def test_basic_auth_header(ops):
    client = ops.TAXIIFeed(_config())
    assert client.headers['Authorization'].startswith('Basic ')
    expected = 'Basic ' + b64encode(b'alice:secret').decode()
    assert client.headers['Authorization'] == expected


def test_bearer_auth_header(ops):
    client = ops.TAXIIFeed(_config(auth_type='Bearer Token', bearer_token='tok-xyz',
                                    username=None, password=None))
    assert client.headers['Authorization'] == 'Bearer tok-xyz'


def test_api_key_header_auth(ops):
    client = ops.TAXIIFeed(_config(auth_type='API Key Header',
                                    api_key_header_name='X-API-Key', api_key='abc', #pragma: allowlist secret
                                    username=None, password=None))
    assert client.headers['X-API-Key'] == 'abc'
    assert 'Authorization' not in client.headers


def test_api_key_header_requires_name(ops):
    with pytest.raises(Exception) as exc:
        ops.TAXIIFeed(_config(auth_type='API Key Header', api_key_header_name='', api_key='abc'))
    assert 'API Key Header Name' in str(exc.value)


def test_none_auth_yields_no_auth_header(ops):
    client = ops.TAXIIFeed(_config(auth_type='None', username=None, password=None))
    assert 'Authorization' not in client.headers


def test_custom_headers_merged_into_self_headers(ops):
    client = ops.TAXIIFeed(_config(
        auth_type='Bearer Token', bearer_token='tok',
        headers={'X-Tenant': 'acme', 'User-Agent': 'FortiSOAR'},
        username=None, password=None,
    ))
    assert client.headers['X-Tenant'] == 'acme'
    assert client.headers['User-Agent'] == 'FortiSOAR'
    assert client.headers['Authorization'] == 'Bearer tok'


def test_unsupported_auth_type_raises(ops):
    with pytest.raises(Exception) as exc:
        ops.TAXIIFeed(_config(auth_type='Magic'))
    assert 'Unsupported Authentication Type' in str(exc.value)


def test_make_request_attaches_auth_and_custom_headers(ops, requests_mock):
    requests_mock.get('https://taxii.example.com/taxii/root/foo',
                      json={'ok': True}, status_code=200)
    client = ops.TAXIIFeed(_config(headers={'X-Tenant': 'acme'}))
    result = client.make_request('foo', headers={'Accept': 'application/taxii+json'})
    assert result == {'ok': True}
    sent = requests_mock.last_request.headers
    # Auth header from config + custom header from config + per-call header all present.
    assert sent['Authorization'].startswith('Basic ')
    assert sent['X-Tenant'] == 'acme'
    assert sent['Accept'] == 'application/taxii+json'
