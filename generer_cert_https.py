"""
Génère, pour le développement local, une autorité de certification (CA) locale et un
certificat serveur signé par cette CA, valable pour `localhost` et `127.0.0.1`.

Pourquoi : le certificat auto-signé par défaut (generate_cert.py) déclenche l'avertissement
« connexion non sécurisée ». Avec une CA locale que VOUS installez dans le magasin racine,
le navigateur affiche le cadenas vert sur https://localhost:5000.

Sortie (dans ce dossier) :
  - cert.pem    : certificat serveur + CA (chaîne complète, lu par app.py)
  - key.pem     : clé privée du serveur
  - ca-local.crt: certificat de la CA — À INSTALLER une fois (voir README, section HTTPS)

Lancer :  python generer_cert_https.py
Puis    :  installer ca-local.crt (Trusted Root) puis  python app.py
"""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = os.path.dirname(os.path.abspath(__file__))
now = datetime.datetime.now(datetime.timezone.utc)
PEM = serialization.Encoding.PEM

# ── CA racine locale ──────────────────────────────────────────────────────────
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, 'TLS Analyser Local CA'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'PFE Local'),
])
ca = (x509.CertificateBuilder()
      .subject_name(ca_name).issuer_name(ca_name)
      .public_key(ca_key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(now - datetime.timedelta(days=1))
      .not_valid_after(now + datetime.timedelta(days=1825))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
      .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                   content_commitment=False, key_encipherment=False,
                                   data_encipherment=False, key_agreement=False,
                                   encipher_only=False, decipher_only=False), critical=True)
      .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
      .sign(ca_key, hashes.SHA256()))

# ── Certificat serveur (SAN localhost + 127.0.0.1) signé par la CA ────────────
srv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
srv = (x509.CertificateBuilder()
       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
       .issuer_name(ca.subject)
       .public_key(srv_key.public_key())
       .serial_number(x509.random_serial_number())
       .not_valid_before(now - datetime.timedelta(days=1))
       .not_valid_after(now + datetime.timedelta(days=397))      # <= 398 j (exigence Chrome)
       .add_extension(x509.SubjectAlternativeName([
           x509.DNSName('localhost'),
           x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
       ]), critical=False)
       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
       .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
       .sign(ca_key, hashes.SHA256()))

with open(os.path.join(ROOT, 'cert.pem'), 'wb') as f:
    f.write(srv.public_bytes(PEM) + ca.public_bytes(PEM))   # chaîne : serveur + CA
with open(os.path.join(ROOT, 'key.pem'), 'wb') as f:
    f.write(srv_key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
with open(os.path.join(ROOT, 'ca-local.crt'), 'wb') as f:
    f.write(ca.public_bytes(PEM))

print('OK : cert.pem, key.pem, ca-local.crt générés.')
print('Étape suivante : installer ca-local.crt (Trusted Root) puis lancer  python app.py')
