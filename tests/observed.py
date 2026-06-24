"""
Dérivation de l'espace d'étiquettes UNIQUE depuis un résultat de scan (resultats_port).
Côté test : combine les classifieurs purs (cipher/DH/cert, qui PRODUISENT déjà leurs
labels) avec un dériveur de familles SANS classifieur (protocole/heartbleed/robot/ccs/
downgrade/expiré, qui ne sont que des booléens/noms dans l'app). C'est l'unique pont
permettant à `labels_attendus ⊆ observed` de comparer dans un seul vocabulaire.
"""
from agent_ia.analyse_ciphers import (
    classer_faiblesse_cipher, classer_faiblesse_dh, LABELS_CIPHER, LABELS_DH)
from agent_ia.analyse_certificat import classer_echec_certificat, LABELS_CERT

PROTO_LABELS = {'ssl2': 'proto_ssl2', 'ssl3': 'proto_ssl3', 'tls10': 'proto_tls10',
                'tls11': 'proto_tls11', 'tls12': 'proto_tls12', 'tls13': 'proto_tls13'}

PROTO_FAIBLES = {'proto_ssl2', 'proto_ssl3', 'proto_tls10', 'proto_tls11'}
PROTO_POSITIFS = {'proto_tls12', 'proto_tls13'}
FAMILLES = {'heartbleed', 'robot', 'ccs', 'fallback_scsv_missing', 'cert_expire'}

# Étiquettes « faibles » : un contrôle positif ne doit en présenter AUCUNE.
WEAK_LABELS = set(LABELS_CIPHER) | set(LABELS_DH) | set(LABELS_CERT) | PROTO_FAIBLES | FAMILLES
# Espace total produisible (pour le garde anti-orphelin du corpus).
TOUTES_ETIQUETTES = WEAK_LABELS | PROTO_POSITIFS


def derive_labels(resultats_port):
    """resultats_port (dict d'un scan) -> set d'étiquettes dans le vocabulaire unique."""
    obs = set()

    proto = resultats_port.get('protocoles', {}) or {}
    for cle, lab in PROTO_LABELS.items():
        if proto.get(cle):
            obs.add(lab)

    for d in resultats_port.get('ciphers_details', []) or []:
        lab = classer_faiblesse_cipher(d.get('nom'), d.get('key_size'), d.get('is_anonymous', False))
        if lab:
            obs.add(lab)
        ldh = classer_faiblesse_dh(d.get('ephemeral_type'), d.get('ephemeral_size'))
        if ldh in LABELS_DH:
            obs.add(ldh)

    cert = resultats_port.get('certificat', {}) or {}
    for lab in (cert.get('echecs') or classer_echec_certificat(cert.get('vue_validation') or {})):
        obs.add(lab)

    if resultats_port.get('heartbleed'):
        obs.add('heartbleed')
    if resultats_port.get('robot'):
        obs.add('robot')
    if resultats_port.get('ccs'):
        obs.add('ccs')
    if resultats_port.get('downgrade'):
        obs.add('fallback_scsv_missing')

    from agent_ia.scanner_multiport import _certificat_expire
    if _certificat_expire(resultats_port):
        obs.add('cert_expire')

    return obs
