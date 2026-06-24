"""P3/P4 — détection cipher/DH branchée dans scanner_multiport (sans réseau ni SSLyze) :
findings 8-clés, déduplication, sérialisation JSON sûre (bytearray jamais stocké),
rétro-compat des vieux dicts, score moyen, et aucun appel réseau."""
import json
from types import SimpleNamespace

import pytest

from agent_ia import scanner_multiport as sm
from agent_ia.scanner_multiport import (
    analyser_vulns_port, _collecter_ciphers, _findings_ciphers, _certificat_expire,
)
from agent_ia.modele_rf import TYPE_MAP

pytestmark = pytest.mark.unit

_CLES_FINDING = {'nom', 'cve', 'type', 'cvss', 'epss', 'criticite', 'severite', 'priorite'}


def _detail(nom, key_size=128, anon=False, eph_type=None, eph_size=None):
    return {'nom': nom, 'key_size': key_size, 'is_anonymous': anon,
            'ephemeral_type': eph_type, 'ephemeral_size': eph_size}


def _port(details=None, **extra):
    base = {'port': 443, 'protocoles': {}, 'certificat': {}, 'heartbleed': False,
            'robot': False, 'ccs': False, 'downgrade': False,
            'ciphers_acceptees': [], 'ciphers_details': details or []}
    base.update(extra)
    return base


def _fake_suite(nom, key_size=128, anon=False, eph_type=None, eph_size=None, prime=None):
    cs = SimpleNamespace(name=nom, key_size=key_size, is_anonymous=anon)
    eph = None
    if eph_type:
        eph = SimpleNamespace(type_name=eph_type, size=eph_size, prime=prime)
    return SimpleNamespace(cipher_suite=cs, ephemeral_key=eph)


# ── _findings_ciphers / analyser_vulns_port ───────────────────────────────────
def test_rc4_produit_finding_8_cles():
    f = _findings_ciphers(_port([_detail('TLS_RSA_WITH_RC4_128_MD5')]))
    assert len(f) == 1
    assert set(f[0]) == _CLES_FINDING
    assert isinstance(f[0]['epss'], (int, float)) and isinstance(f[0]['cvss'], (int, float))
    assert f[0]['severite'] in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}


def test_dedup_rc4_sur_deux_versions():
    # Deux RC4 (ex. TLS1.2 + TLS1.3) -> un seul finding (pas de skew du score moyen).
    f = _findings_ciphers(_port([_detail('TLS_RSA_WITH_RC4_128_MD5'),
                                 _detail('TLS_RSA_WITH_RC4_128_SHA')]))
    assert len(f) == 1


def test_rc4_plus_3des_deux_findings():
    f = _findings_ciphers(_port([_detail('TLS_RSA_WITH_RC4_128_MD5'),
                                 _detail('TLS_RSA_WITH_3DES_EDE_CBC_SHA', 168)]))
    assert len(f) == 2


def test_dh_512_finding():
    f = _findings_ciphers(_port([_detail('TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
                                         eph_type='DH', eph_size=512)]))
    assert any('Diffie-Hellman 512' in x['nom'] for x in f)


def test_ecdh_jamais_signale():
    f = _findings_ciphers(_port([_detail('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                         eph_type='ECDH', eph_size=256)]))
    assert f == []


def test_dh_inconnu_pas_de_finding():
    f = _findings_ciphers(_port([_detail('TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
                                         eph_type='DH', eph_size=None)]))
    assert f == []


def test_types_dans_type_map():
    f = _findings_ciphers(_port([_detail('TLS_RSA_WITH_RC4_128_MD5'),
                                 _detail('TLS_RSA_WITH_NULL_MD5', 0)]))
    assert all(x['type'] in TYPE_MAP for x in f)


def test_analyser_vulns_port_integre_ciphers():
    score, findings = analyser_vulns_port(_port([_detail('TLS_RSA_WITH_RC4_128_MD5')]))
    assert score > 0 and any('RC4' in f['nom'] for f in findings)


def test_port_sain_aucun_finding():
    score, findings = analyser_vulns_port(_port([_detail('TLS_AES_256_GCM_SHA384', 256)]))
    assert score == 0.0 and findings == []


# ── Sérialisation / rétro-compat / réseau ─────────────────────────────────────
def test_collecter_ciphers_json_sur_bytearray():
    # Une clé DH réelle expose prime/generator en bytearray : on ne doit PAS les stocker.
    rp = _port()
    _collecter_ciphers(rp, [_fake_suite('TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
                                        eph_type='DH', eph_size=512,
                                        prime=bytearray(b'\x00\x01\x02'))])
    assert rp['ciphers_acceptees'] == ['TLS_DHE_RSA_WITH_AES_128_CBC_SHA']
    d = rp['ciphers_details'][0]
    assert 'prime' not in d and d['ephemeral_type'] == 'DH' and d['ephemeral_size'] == 512
    json.dumps(rp)   # ne doit pas lever


def test_retrocompat_vieux_dict_sans_ciphers_details():
    vieux = {'port': 443, 'protocoles': {}, 'certificat': {}, 'heartbleed': False,
             'robot': False, 'ccs': False, 'downgrade': False}
    score, findings = analyser_vulns_port(vieux)     # pas de KeyError
    assert score == 0.0 and findings == []


def test_aucun_appel_reseau(monkeypatch):
    import requests
    monkeypatch.setattr(requests, 'get', lambda *a, **k: (_ for _ in ()).throw(AssertionError('réseau!')))
    score, findings = analyser_vulns_port(_port([_detail('TLS_RSA_WITH_RC4_128_MD5')]))
    assert findings   # le scoring marche sans réseau


def test_certificat_expire_pur():
    assert _certificat_expire({'certificat': {'expire': '2000-01-01T00:00:00'}}) is True
    assert _certificat_expire({'certificat': {'expire': '2999-01-01T00:00:00'}}) is False
    assert _certificat_expire({'certificat': {}}) is False
