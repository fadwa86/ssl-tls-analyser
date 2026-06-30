import hashlib
import re
from xml.sax.saxutils import escape
from flask import Blueprint, render_template, session, redirect, url_for, request, send_file
from models.models import db, Scan, Cible, ResultatScan, Administrateur
from agent_ia.agent import analyser_resultats
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import json
import io
from datetime import datetime

rapport_bp = Blueprint('rapport', __name__)

# Source UNIQUE des remédiations (même dict que la page Priorisation : 6 protocoles +
# variantes mail + 17 findings cipher/DH/certificat). Évite la divergence single/multi-port.
from routes.priorisation import RECOMMANDATIONS

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
    if severite == 'INFORMATIF':
        return 'Informatif', GRIS_TEXTE
    if severite == 'CRITICAL':
        return 'Corriger immédiatement', ROUGE
    elif severite == 'HIGH':
        return 'Corriger immédiatement', ORANGE
    elif severite == 'MEDIUM':
        return 'Corriger rapidement', VERT
    else:
        return 'Risque faible', GRIS_TEXTE


def severite_vers_priorite(severite):
    """Cohérent avec agent.py"""
    if severite == 'INFORMATIF':
        return 'INFORMATIF'
    if severite in ('CRITICAL', 'HIGH'):
        return 'HAUTE'
    elif severite == 'MEDIUM':
        return 'MOYENNE'
    else:
        return 'BASSE'


def generer_pdf(scan, cible, vulnerabilites, type_serveur, version_serveur, admin, donnees=None):
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
    elements.append(Paragraph("Rapport d'analyse de sécurité SSL/TLS", style_sous_titre))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=BLEU))
    elements.append(Spacer(1, 0.8*cm))

    data_garde = [
        ['Cible analysée',          cible.url],
        ['Date du scan',            scan.dateDebut.strftime('%d/%m/%Y à %H:%M')],
        ['Date fin du scan',        scan.dateFin.strftime('%d/%m/%Y à %H:%M') if scan.dateFin else 'N/A'],
        ['Date génération rapport', datetime.now().strftime('%d/%m/%Y à %H:%M')],
        ['Scan ID',                 f'#{scan.id}'],
        ['Réalisé par',             f"{admin.prenom} {admin.nom}"],
        ['Rôle',                    admin.role if admin.role else 'Analyste de sécurité'],
        ['Serveur détecté',         f"{type_serveur.upper()} — {version_serveur}"],
        ['Type recommandations',    'Personnalisées' if type_serveur != 'inconnu' else 'Génériques'],
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
    nb_total    = len([v for v in vulnerabilites if v.get('severite') != 'INFORMATIF'])  # réels seulement

    # Grade TLS (réels) + conformité PCI-DSS v4.0 / NIST SP 800-52 (même logique que multi-port).
    from agent_ia.conformite import calculer_grade_tls, evaluer_conformite
    _reels = [v for v in vulnerabilites if v.get('severite') != 'INFORMATIF']
    grade_tls = calculer_grade_tls(_reels)
    try:
        conf = evaluer_conformite([donnees]) if donnees else {'pci_dss': False, 'nist': False}
    except Exception:
        conf = {'pci_dss': False, 'nist': False}

    if nb_critical > 0:
        niveau_risque, couleur_risque = "CRITIQUE", ROUGE
    elif nb_high > 0:
        niveau_risque, couleur_risque = "ÉLEVÉ",   ORANGE
    elif nb_medium > 0:
        niveau_risque, couleur_risque = "MOYEN",   VERT
    else:
        niveau_risque, couleur_risque = "FAIBLE",  VERT

    style_risque = ParagraphStyle('risque', parent=styles['Normal'], fontSize=18,
                                  textColor=couleur_risque, alignment=TA_CENTER, spaceAfter=8)
    elements.append(Paragraph(f"Niveau de risque global : {niveau_risque}", style_risque))
    elements.append(Spacer(1, 0.8*cm))

    # ===== 1. RÉSUMÉ ==========================================================
    elements.append(Paragraph("1. Résumé", style_h1))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))

    data_resume = [
        ['Indicateur',               'Valeur'],
        ['Total vulnérabilités',     str(nb_total)],
        ['Vulnérabilités critiques', str(nb_critical)],
        ['Vulnérabilités élevées',   str(nb_high)],
        ['Vulnérabilités moyennes',  str(nb_medium)],
        ['Niveau de risque',         niveau_risque],
        ['Grade TLS (A-F)',          grade_tls],
        ['Conformité PCI-DSS v4.0',  'CONFORME' if conf.get('pci_dss') else 'NON CONFORME'],
        ['Conformité NIST SP 800-52','CONFORME' if conf.get('nist') else 'NON CONFORME'],
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
    elements.append(Paragraph("2. Vulnérabilités détectées", style_h1))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))

    if vulnerabilites:
        data_vulns = [['#', 'Nom', 'CVE', 'Sévérité', 'CVSS', 'EPSS', 'Score IA']]
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
        elements.append(Paragraph("Aucune vulnérabilité détectée pour ce scan.", style_normal))

    elements.append(Spacer(1, 0.8*cm))

    # ===== 3. PRIORISATION ====================================================
    elements.append(Paragraph("3. Priorisation des vulnérabilités", style_h1))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))

    if vulnerabilites:
        vulns_triees = sorted(vulnerabilites, key=lambda x: x['criticite'], reverse=True)

        data_prio = [['Rang', 'Vulnérabilité', 'Sévérité', 'Score IA', 'Urgence']]
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
    elements.append(Paragraph("4. Recommandations de remédiation", style_h1))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    elements.append(Spacer(1, 0.3*cm))

    if type_serveur != 'inconnu':
        elements.append(Paragraph(
            f"Recommandations personnalisées pour {type_serveur.upper()} ({version_serveur})",
            ParagraphStyle('ok', parent=styles['Normal'], fontSize=10, textColor=VERT, spaceAfter=10)
        ))
    else:
        elements.append(Paragraph(
            "Serveur non détecté — recommandations génériques",
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
                ['Priorité',          priorite],
                ['Description',       reco['description']],
                ['Étape correction',  config['etapeCorrection']],
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
        f"SSL/TLS Analyser — Rapport généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} "
        f"par {admin.prenom} {admin.nom} "
        f"({admin.role if admin.role else 'Analyste de sécurité'}) — Confidentiel",
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

    # Scans multi-ports terminés (rapport PCI-DSS/NIST ReportLab).
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
    version_serveur = 'Non détecté'
    donnees         = {}

    if resultat and resultat.donneesSSL:
        try:
            donnees         = json.loads(resultat.donneesSSL)
            serveur_info    = donnees.get('serveur', {})
            type_serveur    = serveur_info.get('type', 'inconnu')
            version_serveur = serveur_info.get('version', 'Non détecté')
            vulnerabilites  = analyser_resultats(donnees)
        except Exception as e:
            print("Erreur:", e)

    buffer   = generer_pdf(scan, cible, vulnerabilites, type_serveur, version_serveur, admin, donnees)
    safe_url = re.sub(r'[<>:"/\\|?*]', '_', cible.url or 'cible')
    filename = f"rapport_scan_{scan_id}_{safe_url}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"

    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')


# ════════════════════════════════════════════════════════════════════════════
# Rapport PCI-DSS/NIST multi-ports (ReportLab, sans dépendance native). Même moteur
# que le rapport mono-port ci-dessus ; generer_pdf_multiport construit le PDF.
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


def _couleur_grade(grade):
    """Couleur du grade A–F (mêmes teintes que multiport_scan.html::gradeColor)."""
    return {'A': VERT, 'B': HexColor('#58a6ff'), 'C': ORANGE}.get(grade, ROUGE)


def generer_pdf_multiport(cible, date_scan, date_generation, admin, grade, score_ia,
                          conformite, observation_ia, serveur, nb_critical, nb_high,
                          nb_medium, nb_total, nb_informatif, ports, historique, sha256,
                          reco_principale):
    """Rapport PCI-DSS/NIST multi-ports en ReportLab (même format que le mono-port, sans
    dépendance native). Tout texte dynamique est échappé avant un Paragraph (évite que des
    caractères < & dans un DN de certificat ou une commande de remédiation cassent le rendu)."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=1.6*cm, leftMargin=1.6*cm,
                            topMargin=1.8*cm, bottomMargin=1.8*cm)
    styles = getSampleStyleSheet()
    e = []

    style_titre      = ParagraphStyle('mtitre', parent=styles['Title'],    fontSize=26, textColor=BLEU,              alignment=TA_CENTER, spaceAfter=10)
    style_sous_titre = ParagraphStyle('msous',  parent=styles['Normal'],   fontSize=13, textColor=GRIS_TEXTE,        alignment=TA_CENTER, spaceAfter=20)
    style_h1         = ParagraphStyle('mh1',    parent=styles['Heading1'], fontSize=15, textColor=BLEU,              spaceAfter=10, spaceBefore=18)
    style_h2         = ParagraphStyle('mh2',    parent=styles['Heading2'], fontSize=12, textColor=HexColor('#c9d1d9'), spaceAfter=6, spaceBefore=12)
    style_normal     = ParagraphStyle('mnormal',parent=styles['Normal'],   fontSize=10, textColor=HexColor('#c9d1d9'), spaceAfter=6)
    style_cell       = ParagraphStyle('mcell',  parent=styles['Normal'],   fontSize=9,  textColor=HexColor('#c9d1d9'))
    style_small      = ParagraphStyle('msmall', parent=styles['Normal'],   fontSize=8,  textColor=GRIS_TEXTE)
    style_footer     = ParagraphStyle('mfooter',parent=styles['Normal'],   fontSize=8,  textColor=GRIS_TEXTE,        alignment=TA_CENTER)

    def P(txt, style=style_cell):
        return Paragraph(escape('' if txt is None else str(txt)), style)

    # ===== PAGE DE GARDE ======================================================
    e.append(Spacer(1, 1.2*cm))
    e.append(Paragraph("SSL/TLS Analyser", style_titre))
    e.append(Paragraph("Rapport d'analyse de sécurité TLS/SSL — multi-ports", style_sous_titre))
    e.append(HRFlowable(width="100%", thickness=1.5, color=BLEU))
    e.append(Spacer(1, 0.6*cm))

    garde = [
        ['Cible scannée',   cible],
        ['Date du scan',    date_scan],
        ['Généré par',      f"{admin.prenom} {admin.nom} ({admin.role or 'Analyste de sécurité'})"],
        ['Serveur détecté', f"{(serveur.get('type') or 'inconnu').upper()} — {serveur.get('version') or 'Non détecté'}"],
    ]
    t_garde = Table([[k, P(v)] for k, v in garde], colWidths=[5*cm, 12*cm])
    t_garde.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), HexColor('#21262d')),
        ('TEXTCOLOR',  (0, 0), (0, -1), GRIS_TEXTE),
        ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
        ('BACKGROUND', (1, 0), (1, -1), GRIS_FONCE),
        ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN),
        ('PADDING',    (0, 0), (-1, -1), 8),
        ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    e.append(t_garde)
    e.append(Spacer(1, 0.6*cm))
    e.append(Paragraph("CONFIDENTIEL", ParagraphStyle('mconf', parent=styles['Normal'],
             fontSize=12, textColor=ROUGE, alignment=TA_CENTER)))
    e.append(PageBreak())

    # ===== 1. RÉSUMÉ EXÉCUTIF =================================================
    e.append(Paragraph("1. Résumé exécutif", style_h1))
    e.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    e.append(Spacer(1, 0.3*cm))

    grade_para = Paragraph(f"<b>{escape(str(grade))}</b>", ParagraphStyle('mgrade',
                 parent=styles['Normal'], fontSize=40, leading=46,
                 textColor=_couleur_grade(grade), alignment=TA_CENTER))
    pci  = 'CONFORME' if conformite.get('pci_dss') else 'NON CONFORME'
    nist = 'CONFORME' if conformite.get('nist') else 'NON CONFORME'
    infos = [
        Paragraph("Note TLS globale", style_small),
        Paragraph("Score IA de risque (Random Forest)", style_small),
        Paragraph(f"<b>{(score_ia or 0):.2f} / 10</b>", style_normal),
        Spacer(1, 0.15*cm),
        Paragraph(f"PCI-DSS v4.0 : <b>{pci}</b>", style_normal),
        Paragraph(f"NIST SP 800-52 : <b>{nist}</b>", style_normal),
    ]
    t_res = Table([[grade_para, infos]], colWidths=[4*cm, 13*cm])
    t_res.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), GRIS_FONCE),
        ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN),
        ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING',    (0, 0), (-1, -1), 8),
    ]))
    e.append(t_res)
    e.append(Spacer(1, 0.4*cm))

    counts = [['Critiques', 'Élevées', 'Moyennes', 'Total findings'],
              [str(nb_critical), str(nb_high), str(nb_medium), str(nb_total)]]
    t_counts = Table(counts, colWidths=[4.25*cm]*4)
    t_counts.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), BLEU), ('TEXTCOLOR', (0, 0), (-1, 0), BLANC),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 1), (-1, 1), GRIS_FONCE), ('TEXTCOLOR', (0, 1), (-1, 1), HexColor('#c9d1d9')),
        ('ALIGN',      (0, 0), (-1, -1), 'CENTER'),  ('GRID', (0, 0), (-1, -1), 0.5, GRIS_MOYEN),
        ('PADDING',    (0, 0), (-1, -1), 6),         ('FONTSIZE', (0, 0), (-1, -1), 10),
    ]))
    e.append(t_counts)
    e.append(Spacer(1, 0.3*cm))
    e.append(Paragraph(f"<b>Recommandation principale :</b> {escape(str(reco_principale))}", style_normal))
    if observation_ia:
        e.append(Paragraph("Observation IA (incohérence multi-ports)", style_h2))
        e.append(Paragraph(escape(str(observation_ia)), style_small))
    e.append(Spacer(1, 0.4*cm))

    # ===== 2. DÉTAIL PAR PORT =================================================
    e.append(Paragraph("2. Détail par port / service", style_h1))
    e.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    e.append(Spacer(1, 0.3*cm))
    if not ports:
        e.append(Paragraph("Aucun service TLS vulnérable détecté — configuration saine.", style_normal))
    for p in ports:
        titre = f"Port {p.get('port')} — {p.get('protocole') or ''}"
        if p.get('logiciel'):
            titre += f" ({p['logiciel']})"
        titre += f" — score IA {(p.get('score') or 0):.2f}/10"
        e.append(Paragraph(escape(titre), style_h2))

        ciphers = p.get('ciphers') or []
        if ciphers:
            cipher_txt = ', '.join(ciphers[:8]) + (f" … (+{len(ciphers) - 8})" if len(ciphers) > 8 else '')
        else:
            cipher_txt = 'N/A'
        cert = [
            ['Certificat (CN)',          P(p.get('cert_cn') or 'N/A')],
            ['Émetteur',                 P(p.get('cert_issuer') or 'N/A')],
            ['Algorithme de signature',  P(p.get('cert_algo') or 'N/A')],
            ['Validité restante',        P(p.get('cert_duree') or 'N/A')],
            ['Versions TLS',             P(f"{p.get('tls') or 'N/A'} (préférée : {p.get('tls_prefere') or 'N/A'})")],
            ['Suites de chiffrement',    P(cipher_txt)],
        ]
        t_cert = Table(cert, colWidths=[4.5*cm, 12.5*cm])
        t_cert.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#21262d')), ('TEXTCOLOR', (0, 0), (0, -1), GRIS_TEXTE),
            ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BACKGROUND', (1, 0), (1, -1), GRIS_FONCE),
            ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN), ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN',     (0, 0), (-1, -1), 'TOP'), ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))
        e.append(t_cert)

        findings = p.get('findings') or []
        if findings:
            data = [['Vulnérabilité', 'CVE', 'Sévérité', 'CVSS', 'EPSS', 'Score IA']]
            sev_rows, span_rows = {}, []
            for v in findings:
                data.append([P(v.get('nom')), P(v.get('cve') or '-'), v.get('severite') or '-',
                             str(v.get('cvss', '-')), f"{(v.get('epss') or 0):.2f}", str(v.get('criticite', '-'))])
                sev_rows[len(data) - 1] = v.get('severite')
                if v.get('remediation'):
                    remed = (f"<b>Remédiation</b> — {escape(str(v.get('etape') or ''))}<br/>"
                             f"{escape(str(v['remediation']))}")
                    data.append([Paragraph(remed, style_small), '', '', '', '', ''])
                    span_rows.append(len(data) - 1)
            t_find = Table(data, colWidths=[4.6*cm, 2.6*cm, 2.2*cm, 1.6*cm, 1.6*cm, 1.8*cm])
            ts = [
                ('BACKGROUND', (0, 0), (-1, 0), BLEU), ('TEXTCOLOR', (0, 0), (-1, 0), BLANC),
                ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 1), (-1, -1), GRIS_FONCE), ('TEXTCOLOR', (0, 1), (-1, -1), HexColor('#c9d1d9')),
                ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN), ('PADDING', (0, 0), (-1, -1), 5),
                ('FONTSIZE',   (0, 0), (-1, -1), 8), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN',      (2, 1), (-1, -1), 'CENTER'),
            ]
            for r in span_rows:
                ts.append(('SPAN', (0, r), (-1, r)))
                ts.append(('BACKGROUND', (0, r), (-1, r), HexColor('#21262d')))
            for r, sev in sev_rows.items():
                col = ROUGE if sev in ('CRITICAL', 'HIGH') else ORANGE if sev == 'MEDIUM' else VERT
                ts.append(('TEXTCOLOR', (2, r), (2, r), col))
            t_find.setStyle(TableStyle(ts))
            e.append(t_find)
        else:
            e.append(Paragraph("Aucune vulnérabilité détectée sur ce port.", style_small))
        e.append(Spacer(1, 0.4*cm))

    # ===== 3. HISTORIQUE & INTÉGRITÉ =========================================
    e.append(Paragraph("3. Historique &amp; intégrité", style_h1))
    e.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    e.append(Spacer(1, 0.3*cm))
    if historique:
        hist = [['Scan', 'Date', 'Score IA global']]
        for h in historique:
            hist.append([f"#{h.get('id')}", h.get('date') or '-', f"{(h.get('score') or 0):.2f}"])
        t_hist = Table(hist, colWidths=[3*cm, 7*cm, 7*cm])
        t_hist.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BLEU), ('TEXTCOLOR', (0, 0), (-1, 0), BLANC),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (-1, -1), GRIS_FONCE), ('TEXTCOLOR', (0, 1), (-1, -1), HexColor('#c9d1d9')),
            ('GRID',       (0, 0), (-1, -1), 0.5, GRIS_MOYEN), ('PADDING', (0, 0), (-1, -1), 6),
            ('FONTSIZE',   (0, 0), (-1, -1), 9),
        ]))
        e.append(t_hist)
    else:
        e.append(Paragraph("Aucun scan antérieur sur cette cible.", style_small))

    e.append(Spacer(1, 0.6*cm))
    e.append(HRFlowable(width="100%", thickness=0.5, color=GRIS_MOYEN))
    e.append(Spacer(1, 0.2*cm))
    e.append(Paragraph(
        f"SSL/TLS Analyser — Rapport généré le {date_generation} par "
        f"{admin.prenom} {admin.nom} — Confidentiel", style_footer))
    e.append(Paragraph(f"Empreinte d'intégrité SHA-256 : {sha256}",
             ParagraphStyle('msha', parent=style_footer, fontSize=7)))

    doc.build(e)
    buffer.seek(0)
    return buffer


@rapport_bp.route('/rapport/multiport/generer/<int:scan_id>')
def generer_rapport_multiport(scan_id):
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

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
        # Le rapport ne contient QUE les ports TLS ouverts (on ignore non-TLS/échec).
        if (details.get('statut') or 'SUCCES') != 'SUCCES':
            continue
        ports_details.append(details)            # conformité : tous les ports TLS
        logiciel = details.get('logiciel', '')

        findings = details.get('findings', [])   # .get → anciens scans sans 'findings'
        if not findings:
            continue                             # « ports avec vuln » : pas les ports propres
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

    buffer = generer_pdf_multiport(
        cible=cible_nom, date_scan=date_scan,
        date_generation=datetime.now().strftime('%d/%m/%Y %H:%M'),
        admin=admin, grade=grade, score_ia=scan.score_risque_global, conformite=conformite,
        observation_ia=scan.observation_ia, serveur=serveur,
        nb_critical=nb('CRITICAL'), nb_high=nb('HIGH'), nb_medium=nb('MEDIUM'),
        nb_total=sum(1 for f in all_findings if f.get('severite') != 'INFORMATIF'),
        nb_informatif=nb('INFORMATIF'),
        ports=ports_vue, historique=historique, sha256=sha256, reco_principale=reco_principale)

    safe     = re.sub(r'[<>:"/\\|?*]', '_', cible_nom)
    filename = f"rapport_multiport_{scan_id}_{safe}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')