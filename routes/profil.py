from flask import Blueprint, render_template, session, redirect, url_for, request
from models.models import db, Administrateur, Scan, ResultatScan
import json

profil_bp = Blueprint('profil', __name__)

@profil_bp.route('/profil')
def profil():
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    admin = Administrateur.query.get(session['admin_id'])

    nb_scans = Scan.query.filter_by(adminId=session['admin_id']).count()
    nb_vulns_total = 0
    resultats = ResultatScan.query.join(Scan, ResultatScan.scanId == Scan.id).filter(Scan.adminId == session['admin_id']).all()
    for r in resultats:
        if r.donneesSSL:
            try:
                donnees = json.loads(r.donneesSSL)
                protocoles = donnees.get('protocoles', {})
                if protocoles.get('ssl2'): nb_vulns_total += 1
                if protocoles.get('ssl3'): nb_vulns_total += 1
                if protocoles.get('tls10'): nb_vulns_total += 1
                if protocoles.get('tls11'): nb_vulns_total += 1
                if donnees.get('heartbleed'): nb_vulns_total += 1
                if donnees.get('robot'): nb_vulns_total += 1
            except: pass

    return render_template('profil.html',
        admin=admin,
        nb_scans=nb_scans,
        nb_vulns_total=nb_vulns_total
    )


@profil_bp.route('/profil/modifier', methods=['POST'])
def modifier_profil():
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    admin = Administrateur.query.get(session['admin_id'])
    admin.nom = request.form.get('nom')
    admin.prenom = request.form.get('prenom')
    admin.email = request.form.get('email')
    db.session.commit()
    return redirect(url_for('profil.profil'))


@profil_bp.route('/profil/mot-de-passe', methods=['POST'])
def modifier_password():
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    from flask import current_app
    from flask_bcrypt import Bcrypt
    bcrypt = Bcrypt(current_app)

    admin = Administrateur.query.get(session['admin_id'])
    ancien_mdp = request.form.get('ancien_mdp')
    nouveau_mdp = request.form.get('nouveau_mdp')
    confirmer_mdp = request.form.get('confirmer_mdp')

    nb_scans = Scan.query.filter_by(adminId=session['admin_id']).count()
    nb_vulns_total = 0
    resultats = ResultatScan.query.join(
        Scan, ResultatScan.scanId == Scan.id
    ).filter(Scan.adminId == session['admin_id']).all()
    for r in resultats:
        if r.donneesSSL:
            try:
                donnees = json.loads(r.donneesSSL)
                protocoles = donnees.get('protocoles', {})
                if protocoles.get('ssl2'): nb_vulns_total += 1
                if protocoles.get('ssl3'): nb_vulns_total += 1
                if protocoles.get('tls10'): nb_vulns_total += 1
                if protocoles.get('tls11'): nb_vulns_total += 1
                if donnees.get('heartbleed'): nb_vulns_total += 1
                if donnees.get('robot'): nb_vulns_total += 1
            except: pass

    if not bcrypt.check_password_hash(admin.password, ancien_mdp):
        return render_template('profil.html',
            admin=admin,
            nb_scans=nb_scans,
            nb_vulns_total=nb_vulns_total,
            erreur_mdp="Ancien mot de passe incorrect !")

    if nouveau_mdp != confirmer_mdp:
        return render_template('profil.html',
            admin=admin,
            nb_scans=nb_scans,
            nb_vulns_total=nb_vulns_total,
            erreur_mdp="Les mots de passe ne correspondent pas !")

    if len(nouveau_mdp) < 6:
        return render_template('profil.html',
            admin=admin,
            nb_scans=nb_scans,
            nb_vulns_total=nb_vulns_total,
            erreur_mdp="Le mot de passe doit contenir au moins 6 caractères !")

    admin.password = bcrypt.generate_password_hash(nouveau_mdp).decode('utf-8')
    db.session.commit()
    return render_template('profil.html',
        admin=admin,
        nb_scans=nb_scans,
        nb_vulns_total=nb_vulns_total,
        succes_mdp="Mot de passe changé avec succès !")



@profil_bp.route('/profil/supprimer', methods=['POST'])
def supprimer_compte():
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))

    admin = Administrateur.query.get(session['admin_id'])
    db.session.delete(admin)
    db.session.commit()
    session.clear()
    return redirect(url_for('auth.login'))