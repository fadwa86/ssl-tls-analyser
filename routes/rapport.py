import os
# WeasyPrint (Windows) : indiquer où trouver les DLL GTK si MSYS2 est installé,
# AVANT tout import de weasyprint. Sans effet ailleurs.
_gtk_dir = r'C:\msys64\mingw64\bin'
if os.path.isdir(_gtk_dir):
    os.environ.setdefault('WEASYPRINT_DLL_DIRECTORIES', _gtk_dir)

import hashlib
import re
from flask import Blueprint, render_template, session, redirect, url_for, request, send_file
from models.models import db, Scan, Cible, ResultatScan, Administrateur
from agent_ia.agent import analyser_resultats
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import json
import io
from datetime import datetime

rapport_bp = Blueprint('rapport', __name__)

RECOMMANDATIONS = {
    'TLS 1.0 activé': {
        'description': 'TLS 1.0 est un protocole obsolète vulnérable aux attaques BEAST et POODLE.',
        'nginx':   {'etapeCorrection': 'Modifier /etc/nginx/nginx.conf', 'solution': 'ssl_protocols TLSv1.2 TLSv1.3;'},
        'apache':  {'etapeCorrection': 'Modifier /etc/apache2/ssl.conf', 'solution': 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'},
        'iis':     {'etapeCorrection': 'Utiliser IIS Crypto Tool', 'solution': 'Désactiver TLS 1.0 via le registre Windows'},
        'inconnu': {'etapeCorrection': 'Accéder à la configuration SSL/TLS', 'solution': 'Désactiver TLS 1.0 et activer TLS 1.2 et TLS 1.3'}
    },
    'TLS 1.1 activé': {
        'description': 'TLS 1.1 est déprécié depuis mars 2021 (RFC 8996).',
        'nginx':   {'etapeCorrection': 'Modifier ssl_protocols dans nginx.conf', 'solution': 'ssl_protocols TLSv1.2 TLSv1.3;'},
        'apache':  {'etapeCorrection': 'Modifier SSLProtocol dans ssl.conf', 'solution': 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'},
        'iis':     {'etapeCorrection': 'Utiliser IIS Crypto Tool', 'solution': 'Désactiver TLS 1.1 via le registre Windows'},
        'inconnu': {'etapeCorrection': 'Accéder à la configuration SSL/TLS', 'solution': 'Désactiver TLS 1.1 et activer TLS 1.2 et TLS 1.3'}
    },
    'POODLE - SSL 3.0 activé': {
        'description': 'SSL 3.0 est vulnérable à l attaque POODLE (CVE-2014-3566).',
        'nginx':   {'etapeCorrection': 'Modifier ssl_protocols dans nginx.conf', 'solution': 'ssl_protocols TLSv1.2 TLSv1.3;'},
        'apache':  {'etapeCorrection': 'Modifier SSLProtocol dans ssl.conf', 'solution': 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1'},
        'iis':     {'etapeCorrection': 'Désactiver SSL 3.0 via le registre', 'solution': 'SSL 3.0 Enabled = 0'},
        'inconnu': {'etapeCorrection': 'Désactiver SSL 3.0', 'solution': 'Activer uniquement TLS 1.2 et TLS 1.3'}
    },
    'SSL 2.0 activé': {
        'description': 'SSL 2.0 présente de graves failles cryptographiques.',
        'nginx':   {'etapeCorrection': 'Modifier ssl_protocols dans nginx.conf', 'solution': 'ssl_protocols TLSv1.2 TLSv1.3;'},
        'apache':  {'etapeCorrection': 'Modifier SSLProtocol dans ssl.conf', 'solution': 'SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1'},
        'iis':     {'etapeCorrection': 'Désactiver SSL 2.0 via le registre', 'solution': 'SSL 2.0 Enabled = 0'},
        'inconnu': {'etapeCorrection': 'Désactiver SSL 2.0', 'solution': 'Mettre à jour OpenSSL et activer TLS 1.2+'}
    },
    'HEARTBLEED': {
        'description': 'Heartbleed (CVE-2014-0160) permet la lecture de la memoire du serveur.',
        'nginx':   {'etapeCorrection': 'Mettre à jour OpenSSL', 'solution': 'apt-get upgrade openssl && service nginx restart'},
        'apache':  {'etapeCorrection': 'Mettre à jour OpenSSL', 'solution': 'apt-get upgrade openssl && service apache2 restart'},
        'iis':     {'etapeCorrection': 'Appliquer le patch MS14-066', 'solution': 'Installer KB2992611 via Windows Update'},
        'inconnu': {'etapeCorrection': 'Mettre à jour OpenSSL', 'solution': 'Mettre à jour OpenSSL vers 1.0.1g+'}
    },
    'ROBOT Attack': {
        'description': 'ROBOT (CVE-2017-13099) permet le dechiffrement RSA.',
        'nginx':   {'etapeCorrection': 'Modifier ssl_ciphers dans nginx.conf', 'solution': 'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:!RSA;'},
        'apache':  {'etapeCorrection': 'Modifier SSLCipherSuite dans ssl.conf', 'solution': 'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:!RSA'},
        'iis':     {'etapeCorrection': 'Désactiver RSA via IIS Crypto', 'solution': 'Désactiver les cipher suites RSA'},
        'inconnu': {'etapeCorrection': 'Désactiver les cipher suites RSA', 'solution': 'Utiliser uniquement ECDHE'}
    }
}

BLEU       = HexColor('#1f6feb')
ROUGE      = HexColor('#f85149')
ORANGE     = HexColor('#d29922')
VERT       = HexColor('#3fb950')
GRIS_FONCE = HexColor('#161b22')
GRIS_MOYEN = HexColor('#30363d')
GRIS_TEXTE = HexColor('#8b949e')
BLANC      = white


def determiner_urgence(severite):
    """
    Urgence basée sur la sévérité calculée par le modèle RF.
    CRITICAL → Corriger immédiatement
    HIGH     → Corriger rapidement
    MEDIUM   → Corriger rapidement
    LOW      → Risque faible
    """
    if severite == 'CRITICAL':
        return 'Corriger immediatement', ROUGE
    elif severite == 'HIGH':
        return 'Corriger immediatement', ORANGE
    elif severite == 'MEDIUM':
        return 'Corriger rapidement', VERT
    else:
        return 'Risque faible', GRIS_TEXTE


def severite_vers_priorite(severite):
    """Cohérent avec agent.py"""
    if severite in ('CRITICAL', 'HIGH'):
        return 'HAUTE'
    elif severite == 'MEDIUM':
        return 'MOYENNE'
    else:
        return 'BASSE'


def generer_pdf(scan, cible, vulnerabilites, type_serveur, version_serveur, admin):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )
    styles   = getSampleStyleSheet()
    elements = []

    # ── Styles ────────────────────────────────────────────────────────────────
    style_titre      = ParagraphStyle('titre',      parent=styles['Title'],    fontSize=26, textColor=BLEU,              alignment=TA_CENTER, spaceAfter=10)
    style_sous_titre = ParagraphStyle('sous_titre', parent=styles['Normal'],   fontSize=13, textColor=GRIS_TEXTE,        alignment=TA_CENTER, spaceAfter=20)
    style_h1         = ParagraphStyle('h1',         parent=styles['Heading1'], fontSize=15, textColor=BLEU,              spaceAfter=10, spaceBefore=20)
    style_h2         = ParagraphStyle('h2',         parent=styles['Heading2'], fontSize=12, textColor=HexColor('#c9d1d9'), spaceAfter=8, spaceBefore=14)
    style_normal     = ParagraphStyle('normal',     parent=styles['Normal'],   fontSize=10, textColor=HexColor('#c9d1d9'), spaceAfter=6)
    style_footer     = ParagraphStyle('footer',     parent=styles['Normal'],   fontSize=8,  textColor=GRIS_TEXTE,        alignment=TA_CENTER)

    # ===== PAGE DE GARDE ======================================================
    elements.append(Spacer(1, 1.5*cm))
    elements.append(Paragraph("SSL/TLS Analyser", style_titre))
    elements.append(Paragraph("Rapport d'analyse de securite SSL/TLS", style_sous_titre))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=BLEU))
    elements.append(Spacer(1, 0.8*cm))

    data_garde = [
        ['Cible analysee',          cible.url],
        ['Date du scan',            scan.dateDebut.strftime('%d/%m/%Y a %H:%M')],
        ['Date fin du scan',        scan.dateFin.strftime('%d/%m/%Y a %H:%M') if scan.dateFin else 'N/A'],
        ['Date generation rapport', datetime.now().strftime('%d/%m/%Y a %H:%M')],
        ['Scan ID',                 f'#{scan.id}'],
        ['Realise par',             f"{admin.prenom} {admin.nom}"],
        ['Role',                    admin.role if admin.role else 'Analyste de securite'],
        ['Serveur detecte',         f"{type_serveur.upper()} — {version_serveur}"],
        ['Type recommandations',    'Personnalisees' if type_serveur != 'inconnu' else 'Generiques'],
    ]

    table_garde = Table(data_garde, colWidths=[6*cm, 11*cm])
    table_garde.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#21262d')),
        ('TEXTCOLOR',  (0, 0), (0, -1), GRIS_TEXTE),
        ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BACKGROUND', (1, 0), (1, -1), GRIS_FONCE),
        ('TEXTCOLOR',  (1, 0), (1, -1), HexColor('#c9d1d9')),
        ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN),
        ('ROWBACKGROUNDS', (1, 0), (1, -1), [GRIS_FONCE, HexColor('#21262d')]),
        ('PADDING',    (0, 0), (-1, -1), 8),
        ('FONTSIZE',   (0, 0), (-1, -1), 10),
        ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR',  (1, 5), (1, 5), BLEU),
        ('FONTNAME',   (1, 5), (1, 5), 'Helvetica-Bold'),
        ('TEXTCOLOR',  (1, 6), (1, 6), VERT),
    ]))
    elements.append(table_garde)
    elements.append(Spacer(1, 0.8*cm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.5*cm))

    # ── Niveau de risque global ───────────────────────────────────────────────
    nb_critical = len([v for v in vulnerabilites if v['severite'] == 'CRITICAL'])
    nb_high     = len([v for v in vulnerabilites if v['severite'] == 'HIGH'])
    nb_medium   = len([v for v in vulnerabilites if v['severite'] == 'MEDIUM'])
    nb_total    = len(vulnerabilites)

    if nb_critical > 0:
        niveau_risque, couleur_risque = "CRITIQUE", ROUGE
    elif nb_high > 0:
        niveau_risque, couleur_risque = "ELEVE",   ORANGE
    elif nb_medium > 0:
        niveau_risque, couleur_risque = "MOYEN",   VERT
    else:
        niveau_risque, couleur_risque = "FAIBLE",  VERT

    style_risque = ParagraphStyle('risque', parent=styles['Normal'], fontSize=18,
                                  textColor=couleur_risque, alignment=TA_CENTER, spaceAfter=8)
    elements.append(Paragraph(f"Niveau de risque global : {niveau_risque}", style_risque))
    elements.append(Spacer(1, 0.8*cm))

    # ===== 1. RÉSUMÉ ==========================================================
    elements.append(Paragraph("1. Resume", style_h1))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))

    data_resume = [
        ['Indicateur',               'Valeur'],
        ['Total vulnerabilites',     str(nb_total)],
        ['Vulnerabilites critiques', str(nb_critical)],
        ['Vulnerabilites elevees',   str(nb_high)],
        ['Vulnerabilites moyennes',  str(nb_medium)],
        ['Niveau de risque',         niveau_risque],
    ]
    table_resume = Table(data_resume, colWidths=[8*cm, 9*cm])
    table_resume.setStyle(TableStyle([
        ('BACKGROUND',     (0, 0), (-1, 0), BLEU),
        ('TEXTCOLOR',      (0, 0), (-1, 0), BLANC),
        ('FONTNAME',       (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',       (0, 0), (-1, -1), 10),
        ('BACKGROUND',     (0, 1), (-1, -1), GRIS_FONCE),
        ('TEXTCOLOR',      (0, 1), (-1, -1), HexColor('#c9d1d9')),
        ('GRID',           (0, 0), (-1, -1), 0.5, GRIS_MOYEN),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [GRIS_FONCE, HexColor('#21262d')]),
        ('PADDING',        (0, 0), (-1, -1), 8),
    ]))
    elements.append(table_resume)
    elements.append(Spacer(1, 0.8*cm))

    # ===== 2. VULNÉRABILITÉS ==================================================
    elements.append(Paragraph("2. Vulnerabilites detectees", style_h1))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))

    if vulnerabilites:
        data_vulns = [['#', 'Nom', 'CVE', 'Severite', 'CVSS', 'EPSS', 'Score IA']]
        for i, v in enumerate(vulnerabilites, 1):
            data_vulns.append([
                str(i), v['nom'], v['cve'],
                v['severite'], str(v['cvss']),
                str(v['epss']), str(v['criticite'])
            ])

        table_vulns = Table(data_vulns, colWidths=[0.8*cm, 4.5*cm, 3*cm, 2*cm, 1.5*cm, 1.5*cm, 1.7*cm])
        style_table = [
            ('BACKGROUND', (0, 0), (-1, 0), BLEU),
            ('TEXTCOLOR',  (0, 0), (-1, 0), BLANC),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), GRIS_FONCE),
            ('TEXTCOLOR',  (0, 1), (-1, -1), HexColor('#c9d1d9')),
            ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [GRIS_FONCE, HexColor('#21262d')]),
            ('PADDING',    (0, 0), (-1, -1), 6),
            ('ALIGN',      (0, 0), (-1, -1), 'CENTER'),
            ('ALIGN',      (1, 0), (1, -1), 'LEFT'),
        ]
        for i, v in enumerate(vulnerabilites, 1):
            if v['severite'] == 'CRITICAL':
                style_table.append(('TEXTCOLOR', (3, i), (3, i), ROUGE))
                style_table.append(('TEXTCOLOR', (6, i), (6, i), ROUGE))
            elif v['severite'] == 'HIGH':
                style_table.append(('TEXTCOLOR', (3, i), (3, i), ORANGE))
                style_table.append(('TEXTCOLOR', (6, i), (6, i), ORANGE))
            else:
                style_table.append(('TEXTCOLOR', (3, i), (3, i), VERT))
                style_table.append(('TEXTCOLOR', (6, i), (6, i), BLEU))

        table_vulns.setStyle(TableStyle(style_table))
        elements.append(table_vulns)
    else:
        elements.append(Paragraph("Aucune vulnerabilite detectee pour ce scan.", style_normal))

    elements.append(Spacer(1, 0.8*cm))

    # ===== 3. PRIORISATION ====================================================
    elements.append(Paragraph("3. Priorisation des vulnerabilites", style_h1))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))

    if vulnerabilites:
        vulns_triees = sorted(vulnerabilites, key=lambda x: x['criticite'], reverse=True)

        data_prio = [['Rang', 'Vulnerabilite', 'Severite', 'Score IA', 'Urgence']]
        for i, v in enumerate(vulns_triees, 1):
            # ✅ Urgence basée sur la sévérité RF, pas sur criticite >= 7
            urgence, _ = determiner_urgence(v['severite'])
            data_prio.append([
                str(i),
                v['nom'],
                v['severite'],
                str(v['criticite']),
                urgence
            ])

        table_prio = Table(data_prio, colWidths=[1.2*cm, 5.5*cm, 2.5*cm, 2*cm, 4.8*cm])
        style_prio = [
            ('BACKGROUND', (0, 0), (-1, 0), BLEU),
            ('TEXTCOLOR',  (0, 0), (-1, 0), BLANC),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), GRIS_FONCE),
            ('TEXTCOLOR',  (0, 1), (-1, -1), HexColor('#c9d1d9')),
            ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [GRIS_FONCE, HexColor('#21262d')]),
            ('PADDING',    (0, 0), (-1, -1), 6),
            ('ALIGN',      (0, 0), (-1, -1), 'CENTER'),
            ('ALIGN',      (1, 0), (1, -1), 'LEFT'),
            ('ALIGN',      (4, 0), (4, -1), 'LEFT'),
        ]
        for i, v in enumerate(vulns_triees, 1):
            # ✅ Couleur urgence cohérente avec la sévérité
            _, couleur_urgence = determiner_urgence(v['severite'])
            style_prio.append(('TEXTCOLOR', (4, i), (4, i), couleur_urgence))

        table_prio.setStyle(TableStyle(style_prio))
        elements.append(table_prio)

    elements.append(Spacer(1, 0.8*cm))

    # ===== 4. REMÉDIATION =====================================================
    elements.append(Paragraph("4. Recommandations de remediation", style_h1))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))

    if type_serveur != 'inconnu':
        elements.append(Paragraph(
            f"Recommandations personnalisees pour {type_serveur.upper()} ({version_serveur})",
            ParagraphStyle('ok', parent=styles['Normal'], fontSize=10, textColor=VERT, spaceAfter=10)
        ))
    else:
        elements.append(Paragraph(
            "Serveur non detecte — recommandations generiques",
            ParagraphStyle('warn', parent=styles['Normal'], fontSize=10, textColor=ORANGE, spaceAfter=10)
        ))

    for i, v in enumerate(vulnerabilites, 1):
        if v['nom'] in RECOMMANDATIONS:
            reco   = RECOMMANDATIONS[v['nom']]
            config = reco.get(type_serveur, reco['inconnu'])

            # ✅ Priorité dynamique depuis la sévérité RF
            priorite        = severite_vers_priorite(v['severite'])
            priorite_couleur = ROUGE if priorite == 'HAUTE' else ORANGE if priorite == 'MOYENNE' else VERT

            elements.append(Paragraph(f"4.{i} {v['nom']}", style_h2))

            data_reco = [
                ['Priorite',          priorite],
                ['Description',       reco['description']],
                ['Etape correction',  config['etapeCorrection']],
                ['Solution',          config['solution']],
            ]
            table_reco = Table(data_reco, colWidths=[4*cm, 13*cm])
            table_reco.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), HexColor('#21262d')),
                ('TEXTCOLOR',  (0, 0), (0, -1), GRIS_TEXTE),
                ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
                ('BACKGROUND', (1, 0), (1, -1), GRIS_FONCE),
                ('TEXTCOLOR',  (1, 0), (1, 0), priorite_couleur),
                ('FONTNAME',   (1, 0), (1, 0), 'Helvetica-Bold'),
                ('TEXTCOLOR',  (1, 1), (1, 1), HexColor('#c9d1d9')),
                ('TEXTCOLOR',  (1, 2), (1, 2), BLEU),
                ('TEXTCOLOR',  (1, 3), (1, 3), VERT),
                ('FONTNAME',   (1, 3), (1, 3), 'Helvetica-Bold'),
                ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN),
                ('PADDING',    (0, 0), (-1, -1), 8),
                ('VALIGN',     (0, 0), (-1, -1), 'TOP'),
                ('FONTSIZE',   (0, 0), (-1, -1), 9),
            ]))
            elements.append(table_reco)
            elements.append(Spacer(1, 0.4*cm))

    # ===== PIED DE PAGE =======================================================
    elements.append(Spacer(1, 0.8*cm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))
    elements.append(Paragraph(
        f"SSL/TLS Analyser — Rapport genere le {datetime.now().strftime('%d/%m/%Y a %H:%M')} "
        f"par {admin.prenom} {admin.nom} "
        f"({admin.role if admin.role else 'Analyste de securite'}) — Confidentiel",
        style_footer
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer


@rapport_bp.route('/rapport')
def rapport():
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

    # Scans multi-ports terminés (rapport PCI-DSS/NIST WeasyPrint).
    from models.models import ScanMultiPort, CibleMultiPort
    scans_mp = []
    for s, c in (db.session.query(ScanMultiPort, CibleMultiPort)
                 .join(CibleMultiPort, ScanMultiPort.cible_id == CibleMultiPort.id)
                 .filter(ScanMultiPort.statut == 'TERMINE')
                 .order_by(ScanMultiPort.started_at.desc()).all()):
        scans_mp.append({'id': s.id, 'cible': c.nom,
                         'date': s.started_at.strftime('%d/%m/%Y %H:%M') if s.started_at else '-'})

    return render_template('rapport.html', scans=scans, scans_mp=scans_mp, admin=admin)


@rapport_bp.route('/rapport/generer/<int:scan_id>')
def generer_rapport(scan_id):
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    admin    = Administrateur.query.get(session['admin_id'])
    scan     = Scan.query.get_or_404(scan_id)
    cible    = Cible.query.get(scan.cibleId)
    resultat = ResultatScan.query.filter_by(scanId=scan_id).first()

    vulnerabilites  = []
    type_serveur    = 'inconnu'
    version_serveur = 'Non detecte'

    if resultat and resultat.donneesSSL:
        try:
            donnees         = json.loads(resultat.donneesSSL)
            serveur_info    = donnees.get('serveur', {})
            type_serveur    = serveur_info.get('type', 'inconnu')
            version_serveur = serveur_info.get('version', 'Non detecte')
            vulnerabilites  = analyser_resultats(donnees)
        except Exception as e:
            print("Erreur:", e)

    buffer   = generer_pdf(scan, cible, vulnerabilites, type_serveur, version_serveur, admin)
    safe_url = re.sub(r'[<>:"/\\|?*]', '_', cible.url or 'cible')
    filename = f"rapport_scan_{scan_id}_{safe_url}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"

    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')


# ════════════════════════════════════════════════════════════════════════════
# Rapport PCI-DSS/NIST multi-ports (WeasyPrint). Le rapport mono-port ReportLab
# ci-dessus reste inchangé — il fonctionne même si WeasyPrint n'est pas installé.
# ════════════════════════════════════════════════════════════════════════════

def _cle_remediation(protocole, logiciel, type_serveur):
    """Priorité de remédiation : service mail → logiciel ; sinon serveur web ; sinon inconnu."""
    if protocole in ('SMTP', 'IMAP', 'POP3', 'FTP'):
        return logiciel or 'inconnu'
    return type_serveur or 'inconnu'


def _attacher_remediation(finding, protocole, logiciel, type_serveur):
    """Ajoute etape/remediation au finding via RECOMMANDATIONS (priorisation.py, source unique)."""
    from routes.priorisation import RECOMMANDATIONS
    reco = RECOMMANDATIONS.get(finding['nom'])
    if not reco:
        return
    config = reco.get(_cle_remediation(protocole, logiciel, type_serveur), reco['inconnu'])
    finding['etape'] = config['etapeCorrection']
    finding['remediation'] = config['solution']


@rapport_bp.route('/rapport/multiport/generer/<int:scan_id>')
def generer_rapport_multiport(scan_id):
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as e:
        return (f"WeasyPrint indisponible ({e}). Installer MSYS2 + pango — voir CLAUDE.md.", 500)

    from models.models import ScanMultiPort, ResultatScanMultiPort, CibleMultiPort
    from agent_ia.conformite import calculer_grade_tls, evaluer_conformite, calculer_duree_restante

    admin     = Administrateur.query.get(session['admin_id'])
    scan      = ScanMultiPort.query.get_or_404(scan_id)
    cible     = CibleMultiPort.query.get(scan.cible_id)
    cible_nom = cible.nom if cible else 'Inconnu'
    lignes    = ResultatScanMultiPort.query.filter_by(scan_id=scan_id).all()

    serveur       = {'type': 'inconnu', 'version': 'Non détecté'}
    ports_vue     = []
    ports_details = []
    all_findings  = []

    for r in lignes:
        details = json.loads(r.details_bruts) if r.details_bruts else {}
        if details.get('serveur'):
            serveur = details['serveur']
        ports_details.append(details)
        logiciel = details.get('logiciel', '')

        findings = details.get('findings', [])   # .get → anciens scans sans 'findings'
        for f in findings:
            _attacher_remediation(f, r.protocole, logiciel, serveur.get('type', 'inconnu'))
        all_findings.extend(findings)

        duree, expire = calculer_duree_restante(
            r.certificat_expiration.isoformat() if r.certificat_expiration else None)
        ports_vue.append({
            'port': r.port, 'protocole': r.protocole, 'logiciel': logiciel,
            'tls': r.tls_supported, 'tls_prefere': r.tls_preferé,
            'cert_cn': r.certificat_cn, 'cert_issuer': r.certificat_issuer,
            'cert_algo': details.get('certificat', {}).get('signature_algo'),
            'cert_duree': duree, 'cert_expire': expire,
            'ciphers': details.get('ciphers_acceptees', []),
            'findings': findings, 'score': r.score_risque_port,
        })

    grade      = calculer_grade_tls(all_findings)
    conformite = evaluer_conformite(ports_details)
    nb         = lambda s: sum(1 for f in all_findings if f.get('severite') == s)

    noms_urgents = sorted({f['nom'] for f in all_findings if f.get('severite') in ('CRITICAL', 'HIGH')})
    if noms_urgents:
        reco_principale = "Corriger en priorité : " + ", ".join(noms_urgents[:3]) + "."
    elif all_findings:
        reco_principale = "Renforcer les protocoles TLS faibles détectés."
    else:
        reco_principale = "Aucune action critique — maintenir la configuration."

    historique = []
    if cible:
        for s in (ScanMultiPort.query.filter_by(cible_id=cible.id)
                  .order_by(ScanMultiPort.started_at.desc()).limit(6).all()):
            historique.append({'id': s.id, 'score': s.score_risque_global,
                               'date': s.started_at.strftime('%d/%m/%Y %H:%M') if s.started_at else '-'})

    date_scan = scan.started_at.strftime('%d/%m/%Y %H:%M') if scan.started_at else '-'

    # SHA-256 déterministe : données canoniques du scan, PAS le HTML horodaté.
    canonical = f"{scan_id}|{cible_nom}|{date_scan}|" + json.dumps(all_findings, sort_keys=True, ensure_ascii=False)
    sha256 = hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    html = render_template('rapport_pdf.html',
        cible=cible_nom, date_scan=date_scan,
        date_generation=datetime.now().strftime('%d/%m/%Y %H:%M'),
        admin=admin, grade=grade, score_ia=scan.score_risque_global, conformite=conformite,
        observation_ia=scan.observation_ia, serveur=serveur,
        nb_critical=nb('CRITICAL'), nb_high=nb('HIGH'), nb_medium=nb('MEDIUM'), nb_total=len(all_findings),
        ports=ports_vue, historique=historique, sha256=sha256, reco_principale=reco_principale)

    pdf      = HTML(string=html).write_pdf()
    safe     = re.sub(r'[<>:"/\\|?*]', '_', cible_nom)
    filename = f"rapport_multiport_{scan_id}_{safe}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return send_file(io.BytesIO(pdf), as_attachment=True, download_name=filename, mimetype='application/pdf')