from flask import Blueprint, render_template, session, redirect, url_for, request
from models.models import db, Scan, Cible, ResultatScan, Recommandation, Administrateur
from agent_ia.agent import analyser_resultats
import json

prio_bp = Blueprint('priorisation', __name__)

RECOMMANDATIONS = {
    'TLS 1.0 activé': {
        'description': 'TLS 1.0 est un protocole obsolète vulnérable aux attaques BEAST et POODLE. Il ne respecte plus les standards PCI-DSS depuis 2018.',
        'nginx'  : {'etapeCorrection': 'Modifier /etc/nginx/nginx.conf ou /etc/nginx/conf.d/ssl.conf', 'solution': 'ssl_protocols TLSv1.2 TLSv1.3;'},
        'apache' : {'etapeCorrection': 'Modifier /etc/apache2/mods-enabled/ssl.conf ou httpd.conf',    'solution': 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'},
        'iis'    : {'etapeCorrection': 'Utiliser IIS Crypto Tool ou modifier le registre Windows',     'solution': 'HKLM\\SYSTEM\\...\\TLS 1.0 → Enabled = 0'},
        'inconnu': {'etapeCorrection': 'Accéder à la configuration SSL/TLS de votre serveur',          'solution': 'Désactiver TLS 1.0 et activer uniquement TLS 1.2 et TLS 1.3'}
    },
    'TLS 1.1 activé': {
        'description': 'TLS 1.1 est déprécié depuis mars 2021 (RFC 8996). Il présente des vulnérabilités connues.',
        'nginx'  : {'etapeCorrection': 'Modifier la directive ssl_protocols dans nginx.conf',  'solution': 'ssl_protocols TLSv1.2 TLSv1.3;'},
        'apache' : {'etapeCorrection': 'Modifier SSLProtocol dans ssl.conf',                   'solution': 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'},
        'iis'    : {'etapeCorrection': 'Utiliser IIS Crypto Tool pour désactiver TLS 1.1',    'solution': 'HKLM\\SYSTEM\\...\\TLS 1.1 → Enabled = 0'},
        'inconnu': {'etapeCorrection': 'Accéder à la configuration SSL/TLS de votre serveur', 'solution': 'Désactiver TLS 1.1 et activer uniquement TLS 1.2 et TLS 1.3'}
    },
    'POODLE - SSL 3.0 activé': {
        'description': 'SSL 3.0 est vulnérable à l attaque POODLE (CVE-2014-3566) permettant le déchiffrement du trafic HTTPS.',
        'nginx'  : {'etapeCorrection': 'Modifier ssl_protocols dans nginx.conf',           'solution': 'ssl_protocols TLSv1.2 TLSv1.3;'},
        'apache' : {'etapeCorrection': 'Modifier SSLProtocol dans ssl.conf',               'solution': 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'},
        'iis'    : {'etapeCorrection': 'Désactiver SSL 3.0 via le registre Windows',      'solution': 'SSL 3.0 → Enabled = 0'},
        'inconnu': {'etapeCorrection': 'Désactiver SSL 3.0 dans la configuration serveur','solution': 'Activer uniquement TLS 1.2 et TLS 1.3'}
    },
    'SSL 2.0 activé': {
        'description': 'SSL 2.0 présente de graves failles cryptographiques.',
        'nginx'  : {'etapeCorrection': 'Modifier ssl_protocols dans nginx.conf',    'solution': 'ssl_protocols TLSv1.2 TLSv1.3;'},
        'apache' : {'etapeCorrection': 'Modifier SSLProtocol dans ssl.conf',        'solution': 'SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1'},
        'iis'    : {'etapeCorrection': 'Désactiver SSL 2.0 via le registre Windows','solution': 'SSL 2.0 → Enabled = 0'},
        'inconnu': {'etapeCorrection': 'Désactiver SSL 2.0 immédiatement',          'solution': 'Mettre à jour OpenSSL et activer uniquement TLS 1.2 et TLS 1.3'}
    },
    'HEARTBLEED': {
        'description': 'Heartbleed (CVE-2014-0160) est une vulnérabilité critique d OpenSSL permettant la lecture de la mémoire du serveur.',
        'nginx'  : {'etapeCorrection': 'Mettre à jour OpenSSL puis recompiler Nginx',  'solution': 'apt-get upgrade openssl libssl-dev && service nginx restart'},
        'apache' : {'etapeCorrection': 'Mettre à jour OpenSSL puis redémarrer Apache', 'solution': 'apt-get upgrade openssl libssl-dev && service apache2 restart'},
        'iis'    : {'etapeCorrection': 'Appliquer le patch Microsoft MS14-066',        'solution': 'Installer KB2992611 via Windows Update'},
        'inconnu': {'etapeCorrection': 'Mettre à jour OpenSSL immédiatement',          'solution': 'Mettre à jour OpenSSL vers 1.0.1g+, révoquer et regénérer les certificats'}
    },
    'ROBOT Attack': {
        'description': 'ROBOT (CVE-2017-13099) permet à un attaquant d effectuer des opérations RSA et potentiellement déchiffrer les communications.',
        'nginx'  : {'etapeCorrection': 'Modifier ssl_ciphers dans nginx.conf',       'solution': 'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!RSA;'},
        'apache' : {'etapeCorrection': 'Modifier SSLCipherSuite dans ssl.conf',      'solution': 'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:!RSA'},
        'iis'    : {'etapeCorrection': 'Désactiver RSA key exchange via IIS Crypto', 'solution': 'Utiliser IIS Crypto pour désactiver les cipher suites RSA'},
        'inconnu': {'etapeCorrection': 'Désactiver les cipher suites RSA',           'solution': 'Utiliser uniquement des cipher suites avec Perfect Forward Secrecy (ECDHE)'}
    }
}

# ── Remédiation adaptée aux serveurs MAIL (Postfix/Dovecot/Exim/Sendmail) ────────
# Injectée dans le dict ci-dessus pour ne pas dupliquer 6 fois les mêmes clés.
# La priorité de lookup (service mail → logiciel) est dans rapport.py::_cle_remediation.
_MAIL_PROTO = {
    'postfix':  {'etapeCorrection': 'Modifier /etc/postfix/main.cf puis recharger Postfix',
                 'solution': 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\nsmtp_tls_protocols  = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'},
    'dovecot':  {'etapeCorrection': 'Modifier /etc/dovecot/conf.d/10-ssl.conf puis recharger Dovecot',
                 'solution': 'ssl_min_protocol = TLSv1.2'},
    'exim':     {'etapeCorrection': 'Modifier la configuration Exim (section TLS)',
                 'solution': 'openssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1'},
    'sendmail': {'etapeCorrection': 'Modifier /etc/mail/sendmail.mc puis recompiler',
                 'solution': "define(`confTLS_SRV_OPTIONS', `V')dnl  # restreindre aux protocoles modernes"},
}
_MAIL_OPENSSL = {
    logiciel: {'etapeCorrection': 'Mettre à jour OpenSSL système puis redémarrer le service mail',
               'solution': f'apt-get upgrade openssl && systemctl restart {service}'}
    for logiciel, service in (('postfix', 'postfix'), ('dovecot', 'dovecot'),
                              ('exim', 'exim4'), ('sendmail', 'sendmail'))
}
for _nom in ('TLS 1.0 activé', 'TLS 1.1 activé', 'POODLE - SSL 3.0 activé', 'SSL 2.0 activé'):
    RECOMMANDATIONS[_nom].update(_MAIL_PROTO)
for _nom in ('HEARTBLEED', 'ROBOT Attack'):
    RECOMMANDATIONS[_nom].update(_MAIL_OPENSSL)


def severite_vers_priorite(severite):
    """Convertit la sévérité RF en priorité cohérente."""
    if severite in ('CRITICAL', 'HIGH'):
        return 'HAUTE'
    elif severite == 'MEDIUM':
        return 'MOYENNE'
    else:
        return 'BASSE'


@prio_bp.route('/priorisation')
def priorisation():
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    admin = Administrateur.query.get(session['admin_id'])

    scans_cibles = db.session.query(Scan, Cible).join(
        Cible, Scan.cibleId == Cible.id
    ).filter(Scan.adminId == session['admin_id']).order_by(Scan.dateDebut.desc()).all()

    scans = []
    for scan, cible in scans_cibles:
        scan.cible_url = cible.url
        scan.date      = scan.dateDebut.strftime('%d/%m/%Y %H:%M')
        scans.append(scan)

    if not scans:
        return render_template('priorisation.html',
            scans=[], vulnerabilites=[], recommandations=[],
            nb_immediate=0, nb_rapide=0, nb_surveiller=0,
            scan_actuel=None, type_serveur='inconnu',
            version_serveur='Non détecté', admin=admin)

    scan_id     = request.args.get('scan_id', scans[0].id)
    scan_actuel = int(scan_id)

    resultat        = ResultatScan.query.filter_by(scanId=scan_actuel).first()
    vulnerabilites  = []
    recommandations = []
    type_serveur    = 'inconnu'
    version_serveur = 'Non détecté'

    if resultat and resultat.donneesSSL:
        try:
            donnees      = json.loads(resultat.donneesSSL)
            serveur_info = donnees.get('serveur', {})
            type_serveur    = serveur_info.get('type', 'inconnu')
            version_serveur = serveur_info.get('version', 'Non détecté')

            vulns_raw = analyser_resultats(donnees)

            class VulnObj: pass
            class RecoObj: pass

            for v in vulns_raw:
                # ── Objet vulnérabilité ──────────────────────────────────
                obj           = VulnObj()
                obj.nom       = v['nom']
                obj.cve       = v['cve']
                obj.severite  = v['severite']   # ← sévérité calculée par RF
                obj.criticite = v['criticite']  # ← score RF
                vulnerabilites.append(obj)

                # ── Objet recommandation ─────────────────────────────────
                if v['nom'] in RECOMMANDATIONS:
                    reco_data      = RECOMMANDATIONS[v['nom']]
                    config_serveur = reco_data.get(type_serveur, reco_data['inconnu'])

                    reco                 = RecoObj()
                    reco.nom             = v['nom']
                    reco.description     = reco_data['description']
                    reco.etapeCorrection = config_serveur['etapeCorrection']
                    reco.solution        = config_serveur['solution']
                    reco.severite        = v['severite']                      # ✅ sévérité RF
                    reco.priorite        = severite_vers_priorite(v['severite'])  # ✅ priorité dynamique
                    reco.serveur         = type_serveur
                    reco.version_serveur = version_serveur
                    recommandations.append(reco)

                    # ── Sauvegarde BDD (upsert) ──────────────────────────
                    existing = Recommandation.query.filter_by(
                        description=reco_data['description']
                    ).first()

                    if not existing:
                        nouvelle_reco = Recommandation(
                            description     = reco_data['description'],
                            etapeCorrection = config_serveur['etapeCorrection'],
                            solution        = config_serveur['solution'],
                            priorite        = severite_vers_priorite(v['severite'])
                        )
                        db.session.add(nouvelle_reco)
                        db.session.commit()
                    else:
                        # Mettre à jour si la priorité a changé
                        nouvelle_priorite = severite_vers_priorite(v['severite'])
                        if existing.priorite != nouvelle_priorite:
                            existing.priorite = nouvelle_priorite
                            db.session.commit()

        except Exception as e:
            print("Erreur:", e)

    # ── Compteurs basés sur la sévérité RF ───────────────────────────────────
    nb_immediate = len([v for v in vulnerabilites if v.severite in ('CRITICAL', 'HIGH')])
    nb_rapide    = len([v for v in vulnerabilites if v.severite == 'MEDIUM'])
    nb_surveiller = len([v for v in vulnerabilites if v.severite == 'LOW'])

    return render_template('priorisation.html',
        scans           = scans,
        vulnerabilites  = vulnerabilites,
        recommandations = recommandations,
        nb_immediate    = nb_immediate,
        nb_rapide       = nb_rapide,
        nb_surveiller   = nb_surveiller,
        scan_actuel     = scan_actuel,
        type_serveur    = type_serveur,
        version_serveur = version_serveur,
        admin           = admin
    )