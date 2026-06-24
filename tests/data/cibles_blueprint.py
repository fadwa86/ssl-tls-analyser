"""
Corpus de cibles de test transcrit du BLUEPRINT §5 — UNIQUE endroit du dépôt où des
hôtes de test apparaissent (aucun dans agent_ia/ ni routes/).

Schéma de ligne : (host, port, mode, labels_attendus: set[str], polarite)
  - host       : sans schéma ni « :port »
  - polarite   : 'cible' (faiblesse attendue) ou 'controle' (aucune faiblesse)
Les ports non standards (1010/1011) seront passés EXPLICITEMENT à la découverte.
"""

CIBLES = [
    # ── Crypto faible ─────────────────────────────────────────────────────────
    ('rc4.badssl.com',             443, 'manuel', {'cipher_rc4'},            'cible'),
    ('3des.badssl.com',            443, 'manuel', {'cipher_3des'},           'cible'),
    ('null.badssl.com',            443, 'manuel', {'cipher_null'},           'cible'),
    ('export.badssl.com',          443, 'manuel', {'cipher_export'},         'cible'),
    ('dh512.badssl.com',           443, 'manuel', {'dh_512'},                'cible'),
    ('dh1024.badssl.com',          443, 'manuel', {'dh_1024'},               'cible'),
    # ── Certificat ────────────────────────────────────────────────────────────
    ('expired.badssl.com',         443, 'manuel', {'cert_expire'},           'cible'),
    ('self-signed.badssl.com',     443, 'manuel', {'cert_self_signed'},      'cible'),
    ('untrusted-root.badssl.com',  443, 'manuel', {'cert_untrusted_root'},   'cible'),
    ('wrong.host.badssl.com',      443, 'manuel', {'cert_hostname_mismatch'},'cible'),
    ('incomplete-chain.badssl.com',443, 'manuel', {'cert_chain_incomplete'}, 'cible'),
    ('sha1-intermediate.badssl.com',443,'manuel', {'hash_sha1'},             'cible'),
    # ── Versions de protocole (ports non standards) ──────────────────────────
    ('tls-v1-0.badssl.com',       1010, 'manuel', {'proto_tls10'},           'cible'),
    ('tls-v1-1.badssl.com',       1011, 'manuel', {'proto_tls11'},           'cible'),
    # ── Contrôle positif : AUCUNE faiblesse attendue ─────────────────────────
    # Seul mozilla-modern est réellement « propre » (TLS1.2/1.3, pas de legacy).
    ('mozilla-modern.badssl.com',  443, 'manuel', set(),                     'controle'),
    # NOTE : badssl.com et sha256.badssl.com sont décrits « bons » par le blueprint,
    # mais leurs endpoints LIVE offrent encore TLS 1.0/1.1 + 3DES (le site parent est
    # volontairement permissif). Ce sont donc des cibles à faiblesse réelle, pas des
    # contrôles. On y attend proto_tls10 (constant) ; la détection les flagge à raison.
    ('badssl.com',                 443, 'manuel', {'proto_tls10'},           'cible'),
    ('sha256.badssl.com',          443, 'manuel', {'proto_tls10'},           'cible'),
]
