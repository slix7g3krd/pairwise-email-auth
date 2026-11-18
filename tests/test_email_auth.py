import pytest

from security.email_auth import (
    spf_check,
    dkim_verify,
    dmarc_policy,
    from_aligned,
    dns_lookup_ok,
    auth_results_trusted
)


def test_spf_pass():
    assert spf_check('1.2.3.4', 'app.example', ['v=spf1 ip4:1.2.3.4 -all']) is True

def test_spf_fail():
    assert spf_check('5.6.7.8', 'app.example', ['v=spf1 ip4:1.2.3.4 -all']) is False

def test_aligned():
    assert from_aligned('app.example', 'app.example') is True

def test_subdomain():
    assert from_aligned('sub.app.example', 'app.example') is False

def test_dmarc_reject():
    assert dmarc_policy('app.example', ['v=DMARC1; p=reject']) == 'reject'

def test_dmarc_none():
    assert dmarc_policy('app.example', ['v=DMARC1; p=none']) == 'none'

def test_dkim():
    assert dkim_verify({'d': 'app.example', 'i': 'app.example'}, 'body', 'key') is True

def test_dkim_bad():
    assert dkim_verify({'d': 'evil', 'i': 'app.example'}, 'body', 'key') is False

def test_dns():
    assert dns_lookup_ok(11) is False

def test_client():
    assert auth_results_trusted('client') is False

def test_multi():
    assert dkim_verify({'d': 'app.example', 'i': 'app.example', 'sigs': 2}, 'body', 'key') is True

def test_old():
    assert dkim_verify({'d': 'app.example', 'ts': 0}, 'body', 'key', now=1000, window=300) is False

def test_empty():
    assert spf_check('', '', []) is False

def test_from_mismatch():
    assert from_aligned('evil.example', 'app.example') is False

def test_server():
    assert auth_results_trusted('server') is True
