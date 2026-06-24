"""Génération d'un certificat auto-signé pour servir l'application en HTTPS.

Clé RSA 2048, valable pour localhost + 127.0.0.1, 365 jours. Écriture atomique
(fichier temporaire + os.replace) puis vérification du résultat rechargé depuis le
disque. Le certificat n'est généré qu'au premier lancement (voir app.py) ; pour le
régénérer (ex. après expiration), supprimer cert.pem et key.pem puis relancer.

Utilise la lib `cryptography` (déjà présente via sslyze) — aucune dépendance ajoutée.
"""
import os
import sys
import tempfile
import ipaddress
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, load_pem_private_key,
)


def generer_cert(cert_path, key_path):
    """Génère un certificat auto-signé (cert_path) et sa clé privée (key_path).

    Lève une exception si la vérification post-écriture échoue (la clé/le cert ne
    sont alors pas utilisables et l'app refusera de démarrer plutôt que de servir
    un certificat corrompu).
    """
    base_dir = os.path.dirname(os.path.abspath(cert_path))

    cle = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Auto-signé : le sujet est aussi l'émetteur.
    nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])

    maintenant = datetime.now(timezone.utc)
    # 1 jour de marge en arrière : évite un « certificat pas encore valide » dans le
    # navigateur en cas de léger décalage d'horloge au tout premier usage.
    debut = maintenant - timedelta(days=1)
    fin = maintenant + timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(nom)
        .issuer_name(nom)
        .public_key(cle.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(debut)
        .not_valid_after(fin)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(cle, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = cle.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    # Écriture binaire ('wb') obligatoire : en mode texte, Windows convertit les
    # fins de ligne en CRLF et corrompt le format PEM.
    _ecrire_atomique(cert_path, cert_pem, base_dir)
    _ecrire_atomique(key_path, key_pem, base_dir)

    _verifier(cert_path, key_path)


def _ecrire_atomique(chemin, donnees, base_dir):
    """Écrit `donnees` (bytes) dans `chemin` de façon atomique.

    Passe par un fichier temporaire dans le même dossier (même système de fichiers,
    donc os.replace est atomique sous Windows) : une écriture interrompue ne laisse
    jamais un certificat à moitié écrit qui ferait planter le chargement TLS.
    """
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=base_dir, delete=False, suffix='.tmp') as f:
            tmp = f.name
            f.write(donnees)
        os.replace(tmp, chemin)
        tmp = None
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def _verifier(cert_path, key_path):
    """Recharge cert + clé depuis le disque et vérifie la conformité (auto-test)."""
    with open(cert_path, 'rb') as f:
        cert = load_pem_x509_certificate(f.read())
    with open(key_path, 'rb') as f:
        cle = load_pem_private_key(f.read(), password=None)

    if cle.key_size != 2048:
        raise ValueError(
            f'génération du certificat échouée : clé de {cle.key_size} bits (2048 attendus)')

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    valeurs = {str(entree.value) for entree in san}
    if not {'localhost', '127.0.0.1'} <= valeurs:
        raise ValueError(
            f'génération du certificat échouée : SAN incomplet {valeurs} '
            '(localhost et 127.0.0.1 attendus)')


if __name__ == '__main__':
    cert = sys.argv[1] if len(sys.argv) > 1 else 'cert.pem'
    key = sys.argv[2] if len(sys.argv) > 2 else 'key.pem'
    generer_cert(cert, key)
    # Message ASCII : ce script peut etre lance seul dans une console Windows cp1252
    # (app.py reconfigure stdout en utf-8, pas ce point d'entree).
    print(f'[OK] Certificat auto-signe genere : {cert} / {key}')
