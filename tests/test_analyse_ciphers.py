"""P3/P4 — classifieurs purs cipher + DH (NOM-pilote ; tailles de clé réelles SSLyze)."""
import pytest

from agent_ia.analyse_ciphers import (
    classer_faiblesse_cipher, classer_faiblesse_dh, META_CIPHER,
    CIPHER_NULL, CIPHER_EXPORT, CIPHER_ANON, CIPHER_RC4, CIPHER_3DES, CIPHER_DES,
    DH_512, DH_1024, DH_INCONNU, LABELS_CIPHER, LABELS_DH,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('nom,ks,anon,attendu', [
    ('TLS_RSA_WITH_RC4_128_MD5', 128, False, CIPHER_RC4),          # ks=128, détecté par nom
    ('TLS_RSA_WITH_3DES_EDE_CBC_SHA', 168, False, CIPHER_3DES),    # ks=168, par nom
    ('TLS_RSA_WITH_NULL_MD5', 0, False, CIPHER_NULL),             # ks=0 (falsy géré)
    ('TLS_RSA_EXPORT_WITH_RC4_40_MD5', 40, False, CIPHER_EXPORT),  # export gagne sur rc4
    ('TLS_RSA_EXPORT1024_WITH_RC4_56_SHA', 56, False, CIPHER_EXPORT),  # pas DES
    ('TLS_RSA_WITH_DES_CBC_SHA', 56, False, CIPHER_DES),          # même ks=56, pas export
    ('TLS_DH_anon_WITH_AES_128_GCM_SHA256', 128, True, CIPHER_ANON),
    ('TLS_AES_256_GCM_SHA384', 256, False, None),                # TLS1.3 sain
])
def test_classer_cipher(nom, ks, anon, attendu):
    assert classer_faiblesse_cipher(nom, ks, anon) == attendu


@pytest.mark.parametrize('nom', [None, '', 'TLS_GREASE_0A0A'])
def test_classer_cipher_robuste(nom):
    assert classer_faiblesse_cipher(nom) is None


@pytest.mark.parametrize('tn,size,attendu', [
    ('DH', 512, DH_512), ('DH', 1024, DH_1024),
    ('DH', 768, DH_1024), ('DH', 1023, DH_1024),
    ('DH', 2048, None), ('ECDH', 256, None),
    ('DH', None, DH_INCONNU), (None, None, None),
])
def test_classer_dh(tn, size, attendu):
    assert classer_faiblesse_dh(tn, size) == attendu


def test_toutes_etiquettes_findings_ont_meta():
    # dh_inconnu volontairement absent (non bloquant, pas un finding).
    assert (LABELS_CIPHER | LABELS_DH) <= set(META_CIPHER)
    assert DH_INCONNU not in META_CIPHER


def test_meta_types_dans_type_map():
    from agent_ia.modele_rf import TYPE_MAP
    for _, (_nom, _cve, type_v, cvss, epss) in META_CIPHER.items():
        assert type_v in TYPE_MAP
        assert isinstance(cvss, (int, float)) and isinstance(epss, (int, float))
