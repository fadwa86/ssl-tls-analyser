"""
Classification PURE des échecs de certificat à partir d'une « vue de validation »
sérialisable extraite d'un déploiement SSLyze 6.3.1.

Réalités de SSLyze 6.3.1 / cryptography 46 encodées ici :
- La validation passe par le ServerVerifier Rust de cryptography ; `validation_error`
  est un message *cryptography* instable (« candidates exhausted », « no matching
  subjectAltName »…), PAS une chaîne OpenSSL. On dérive donc untrusted_root de façon
  STRUCTURELLE (aucun chemin de validation réussi), et on n'utilise le texte QUE pour
  le hostname, ancré sur la sous-chaîne stable 'no matching subjectAltName'.
- `leaf_certificate_subject_matches_hostname` et `openssl_error_string` n'existent plus.
- Subtilité corrigée : un certificat FIABLE mais au mauvais hôte (wrong.host) échoue
  aussi la validation (le hostname fait partie de verify()). On ne doit donc PAS
  émettre untrusted_root quand l'erreur est un échec de hostname — sinon faux positif.
"""

CERT_SELF_SIGNED = 'cert_self_signed'
CERT_UNTRUSTED = 'cert_untrusted_root'
CERT_HOSTNAME = 'cert_hostname_mismatch'
CERT_CHAIN_INCOMPLETE = 'cert_chain_incomplete'
CERT_SHA1 = 'hash_sha1'
CERT_NO_SCT = 'no_sct'
CERT_EXPIRE = 'cert_expire'            # produit par le chemin existant ('Certificat expiré')

LABELS_CERT = frozenset({CERT_SELF_SIGNED, CERT_UNTRUSTED, CERT_HOSTNAME,
                         CERT_CHAIN_INCOMPLETE, CERT_SHA1, CERT_NO_SCT})

# Sous-chaîne stable de cryptography 46.0.7 (cf. fixture versionnée).
_TEXTE_HOSTNAME = 'no matching subjectAltName'

# (nom_fr, cve, type, cvss, epss) — type ∈ TYPE_MAP ('Protocole faible'), pas de ré-entraînement RF.
# Les échecs de VALIDITÉ du certificat sont de VRAIES vulnérabilités : pas de CVE unique,
# on porte donc un identifiant CWE → est_informatif=False (comptés/statut/grade/PCI).
# SHA-1 et no-SCT restent informationnels (cve '-').
META_CERT = {
    CERT_SELF_SIGNED:      ('Certificat auto-signé',                'CWE-295', 'Protocole faible', 7.4, 0.30),
    CERT_UNTRUSTED:        ('Autorité de certification non fiable', 'CWE-295', 'Protocole faible', 7.4, 0.30),
    CERT_HOSTNAME:         ("Nom d'hôte du certificat invalide",    'CWE-297', 'Protocole faible', 6.5, 0.25),
    CERT_CHAIN_INCOMPLETE: ('Chaîne de certificats incomplète',     'CWE-296', 'Protocole faible', 5.3, 0.20),
    CERT_EXPIRE:           ('Certificat expiré',                    'CWE-298', 'Protocole faible', 7.0, 0.60),
    CERT_SHA1:             ('Signature de certificat SHA-1',        '-',       'Chiffrement faible', 5.3, 0.20),
    CERT_NO_SCT:           ('Aucun SCT embarqué (Certificate Transparency)', '-', 'Protocole faible', 3.7, 0.10),
}


def classer_echec_certificat(vue):
    """vue (dict sérialisable) -> liste d'étiquettes d'échec. Tolérant aux clés absentes.

    vue attendue : {issuer_eq_subject: bool, path_validation_ok: bool|None,
                    validation_error: str|None, chain_order: True|False|None,
                    anchor_present: True|False|None}
    """
    echecs = []
    if not isinstance(vue, dict):
        return echecs

    issuer_eq = vue.get('issuer_eq_subject')
    ok = vue.get('path_validation_ok')
    err = vue.get('validation_error') or ''
    order = vue.get('chain_order')

    hostname_fail = _TEXTE_HOSTNAME in err

    if issuer_eq:
        echecs.append(CERT_SELF_SIGNED)            # prime sur untrusted_root
    elif ok is False and not hostname_fail:
        # Validation échouée sans erreur de hostname -> racine non fiable (structurel).
        echecs.append(CERT_UNTRUSTED)

    if hostname_fail:
        echecs.append(CERT_HOSTNAME)               # mauvais hôte (cert peut être fiable)

    if order is False:                             # False explicite (None = inconnu, pas incomplet)
        echecs.append(CERT_CHAIN_INCOMPLETE)

    if vue.get('sha1_signature') is True:          # True explicite seulement
        echecs.append(CERT_SHA1)

    if vue.get('scts_count') == 0:                 # ==0 explicite (None = inconnu, pas no_sct)
        echecs.append(CERT_NO_SCT)

    return echecs


if __name__ == '__main__':
    f = classer_echec_certificat
    assert f({'issuer_eq_subject': True, 'path_validation_ok': False}) == [CERT_SELF_SIGNED]
    assert f({'issuer_eq_subject': False, 'path_validation_ok': False,
              'validation_error': 'validation failed: candidates exhausted'}) == [CERT_UNTRUSTED]
    # Fiable mais mauvais hôte -> hostname SEUL (pas untrusted).
    assert f({'issuer_eq_subject': False, 'path_validation_ok': False,
              'validation_error': 'leaf certificate has no matching subjectAltName'}) == [CERT_HOSTNAME]
    # no-SAN (texte proche mais SANS 'matching') -> NE déclenche PAS hostname.
    assert f({'issuer_eq_subject': False, 'path_validation_ok': False,
              'validation_error': 'leaf server certificate has no subjectAltName'}) == [CERT_UNTRUSTED]
    assert f({'issuer_eq_subject': False, 'path_validation_ok': True,
              'chain_order': False}) == [CERT_CHAIN_INCOMPLETE]
    assert f({'issuer_eq_subject': False, 'path_validation_ok': True, 'chain_order': True}) == []
    assert f({'chain_order': None, 'path_validation_ok': True}) == []     # None != incomplet
    assert f({'path_validation_ok': True, 'sha1_signature': True}) == [CERT_SHA1]
    assert f({'path_validation_ok': True, 'scts_count': 0}) == [CERT_NO_SCT]
    assert f({'path_validation_ok': True, 'scts_count': None}) == []      # None != no_sct
    assert f({}) == [] and f(None) == []
    assert LABELS_CERT <= set(META_CERT)
    # CERT_EXPIRE est dans META_CERT (pour le finding CWE-298) mais PAS dans LABELS_CERT
    # (classer_echec_certificat ne le produit pas ; il vient de findings_certificat via la date).
    assert CERT_EXPIRE in META_CERT and CERT_EXPIRE not in LABELS_CERT
    print('analyse_certificat.py : auto-vérification OK')
