"""Diagnostic ponctuel : pourquoi expired.badssl.com ne remonte aucun finding.
Scanne UNIQUEMENT le certificat de la cible et affiche si sslyze a renvoyé
un résultat ou une ERREUR (slow connection vs bug de parsing).
Lancer :  python diag_cert.py   [hote]  [port]
"""
import sys
from sslyze import (Scanner, ServerScanRequest, ServerNetworkLocation,
                    ServerNetworkConfiguration)
from sslyze.plugins.scan_commands import ScanCommand

host = sys.argv[1] if len(sys.argv) > 1 else 'expired.badssl.com'
port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

print(f"== Scan certificat {host}:{port} ==")
req = ServerScanRequest(
    server_location=ServerNetworkLocation(hostname=host, port=port),
    network_configuration=ServerNetworkConfiguration(
        tls_server_name_indication=host, network_timeout=15, network_max_retries=5),
    scan_commands={ScanCommand.CERTIFICATE_INFO},
)
sc = Scanner()
sc.queue_scans([req])

for result in sc.get_results():
    # Statut de connexion globale
    print("connectivity:", result.connectivity_status)
    if result.scan_result is None:
        print(">>> AUCUN scan_result (connexion échouée) :",
              getattr(result, 'connectivity_error_trace', None))
        continue
    ci = result.scan_result.certificate_info
    print("cert status:", ci.status)              # COMPLETED / ERROR
    if ci.error_trace:
        print(">>> ERREUR scan certificat (réseau/timeout probable) :")
        print(ci.error_trace)
        continue
    # Succès : afficher la date d'expiration
    for dep in ci.result.certificate_deployments:
        cert = dep.received_certificate_chain[0]
        exp = getattr(cert, 'not_valid_after_utc', None) or getattr(cert, 'not_valid_after', None)
        print(">>> OK — certificat expire le :", exp)
        print("    chaîne vérifiée :", bool(dep.verified_certificate_chain))
