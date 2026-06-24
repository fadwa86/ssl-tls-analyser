"""
Classification PURE (hors-ligne) des faiblesses de chiffrement TLS, à partir des
données qu'un scan SSLyze a déjà renvoyées : nom RFC de la suite, taille de clé
symétrique, anonymat, et clé éphémère (Diffie-Hellman). Aucun réseau, aucune cible
codée en dur — on ne fait que classer ce que le scanner a observé.

Pourquoi NOM-pilote et pas taille-de-clé : RC4=128 bits et 3DES=168 bits sont
invisibles à un seuil de taille ; EXPORT1024-RC4-56 et single-DES-56 partagent la
même taille (56) — seul le nom RFC les distingue. La taille ne sert que pour NULL (0).
"""

# ── Espace d'étiquettes canonique (produit par CE module) ─────────────────────
CIPHER_NULL = 'cipher_null'
CIPHER_EXPORT = 'cipher_export'        # FREAK
CIPHER_ANON = 'cipher_anon'
CIPHER_RC4 = 'cipher_rc4'
CIPHER_3DES = 'cipher_3des'            # Sweet32
CIPHER_DES = 'cipher_des'
DH_512 = 'dh_512'                      # Logjam (export)
DH_1024 = 'dh_1024'
DH_INCONNU = 'dh_inconnu'              # non bloquant : DHE sans taille connue

LABELS_CIPHER = frozenset({CIPHER_NULL, CIPHER_EXPORT, CIPHER_ANON,
                           CIPHER_RC4, CIPHER_3DES, CIPHER_DES})
LABELS_DH = frozenset({DH_512, DH_1024})   # dh_inconnu n'est pas un finding

# (nom_fr, cve, type, cvss_statique, epss_statique) — alimente les findings 8-clés.
# `type` ∈ TYPE_MAP de modele_rf (pas de ré-entraînement). CVE FREAK = CVE-2015-0204
# (réutilisé intentionnellement, cf. mapping TLS 1.1 du catalogue).
META_CIPHER = {
    CIPHER_NULL:   ('Chiffrement NULL accepté',          'CVE-2014-0224', 'Chiffrement faible', 9.1, 0.40),
    CIPHER_EXPORT: ('Suite EXPORT acceptée (FREAK)',      'CVE-2015-0204', 'Chiffrement faible', 7.4, 0.60),
    CIPHER_ANON:   ('Suite anonyme (sans authentification)', '-',          'Chiffrement faible', 7.4, 0.30),
    CIPHER_RC4:    ('RC4 accepté',                        'CVE-2013-2566', 'Chiffrement faible', 7.5, 0.50),
    CIPHER_3DES:   ('3DES accepté (Sweet32)',             'CVE-2016-2183', 'Chiffrement faible', 7.5, 0.45),
    CIPHER_DES:    ('DES accepté',                        '-',             'Chiffrement faible', 7.0, 0.30),
    DH_512:        ('Diffie-Hellman 512 bits (Logjam)',   'CVE-2015-4000', 'Chiffrement faible', 7.5, 0.55),
    DH_1024:       ('Diffie-Hellman 1024 bits (faible)',  'CVE-2015-4000', 'Chiffrement faible', 5.9, 0.30),
}


def classer_faiblesse_cipher(nom_rfc, key_size=None, is_anonymous=False):
    """Nom RFC d'une suite -> étiquette de faiblesse, ou None si saine. Pire d'abord."""
    nom = (nom_rfc or '').upper()
    if not nom:
        return None
    if key_size == 0 or 'WITH_NULL' in nom or '_NULL_' in nom or nom.endswith('_NULL'):
        return CIPHER_NULL
    if 'EXPORT' in nom:                       # avant RC4/DES : FREAK prime sur le reste
        return CIPHER_EXPORT
    if is_anonymous or '_ANON_' in nom or 'DH_ANON' in nom:
        return CIPHER_ANON
    if 'RC4' in nom:
        return CIPHER_RC4
    if '3DES' in nom or 'DES_EDE' in nom:
        return CIPHER_3DES
    if '_DES_' in nom or 'DES_CBC' in nom:
        return CIPHER_DES
    return None


def classer_faiblesse_dh(type_name, size):
    """Clé éphémère -> faiblesse DH. ECDH jamais signalé. DHE sans taille -> dh_inconnu."""
    if type_name != 'DH':
        return None
    if not size:
        return DH_INCONNU
    if size <= 512:
        return DH_512
    if size <= 1024:
        return DH_1024
    return None


if __name__ == '__main__':
    c = classer_faiblesse_cipher
    assert c('TLS_RSA_WITH_RC4_128_MD5', 128) == CIPHER_RC4
    assert c('TLS_RSA_WITH_3DES_EDE_CBC_SHA', 168) == CIPHER_3DES
    assert c('TLS_RSA_WITH_NULL_MD5', 0) == CIPHER_NULL
    assert c('TLS_RSA_EXPORT_WITH_RC4_40_MD5', 40) == CIPHER_EXPORT      # export > rc4
    assert c('TLS_RSA_EXPORT1024_WITH_RC4_56_SHA', 56) == CIPHER_EXPORT  # pas DES
    assert c('TLS_RSA_WITH_DES_CBC_SHA', 56) == CIPHER_DES               # pas export
    assert c('TLS_DH_anon_WITH_AES_128_GCM_SHA256', 128, True) == CIPHER_ANON
    assert c('TLS_AES_256_GCM_SHA384', 256) is None
    assert c(None) is None and c('') is None and c('TLS_GREASE_0A0A') is None
    d = classer_faiblesse_dh
    assert d('DH', 512) == DH_512 and d('DH', 1024) == DH_1024
    assert d('DH', 768) == DH_1024 and d('DH', 1023) == DH_1024
    assert d('DH', 2048) is None and d('ECDH', 256) is None
    assert d('DH', None) == DH_INCONNU and d(None, None) is None
    assert all(m in META_CIPHER for m in LABELS_CIPHER | LABELS_DH)
    print('analyse_ciphers.py : auto-vérification OK')
