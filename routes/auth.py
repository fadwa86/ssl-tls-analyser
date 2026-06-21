from flask import Blueprint, render_template, request, redirect, url_for, session, current_app
from models.models import Administrateur, db
from flask_bcrypt import Bcrypt


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login']
        password = request.form['password']
        role = request.form.get('role')

        admin = Administrateur.query.filter_by(
            login=login_input,
            role=role
        ).first()

        bcrypt = Bcrypt(current_app)

        if not admin:
            return render_template('login.html', error=True, restantes=None)

        # Vérifier si bloqué
        if admin.bloque:
            return render_template('login.html',
                bloque="Compte bloqué après 3 tentatives échouées. Contactez l'administrateur.")

        if bcrypt.check_password_hash(admin.password, password):
            # Connexion réussie → réinitialiser
            admin.nb_tentatives = 0
            admin.bloque = False
            db.session.commit()
            session['admin_id'] = admin.id
            return redirect(url_for('auth.dashboard'))

        else:
            # Échec → incrémenter tentatives
            admin.nb_tentatives += 1

            if admin.nb_tentatives >= 3:
                admin.bloque = True
                db.session.commit()
                return render_template('login.html',
                    bloque="Compte bloqué après 3 tentatives échouées. Contactez l'administrateur.")
            else:
                restantes = 3 - admin.nb_tentatives
                db.session.commit()
                return render_template('login.html',
                    error=True,
                    restantes=restantes)

    return render_template('login.html')


@auth.route('/debloquer/<int:admin_id>')
def debloquer(admin_id):
    """Route pour débloquer un compte via URL directe"""
    admin = Administrateur.query.get_or_404(admin_id)
    admin.bloque = False
    admin.nb_tentatives = 0
    db.session.commit()
    return render_template('login.html',
        succes_inscription="Compte débloqué avec succès ! Vous pouvez vous connecter.")


@auth.route('/inscription', methods=['POST'])
def inscription():
    bcrypt = Bcrypt(current_app)
    nom = request.form.get('nom')
    prenom = request.form.get('prenom')
    login_input = request.form.get('login_inscription')
    password = request.form.get('password_inscription')
    email = request.form.get('email')

    existing = Administrateur.query.filter_by(login=login_input).first()
    if existing:
        return render_template('login.html',
            erreur_inscription="Ce login existe déjà !")

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    nouvel_utilisateur = Administrateur(
        nom=nom,
        prenom=prenom,
        login=login_input,
        password=hashed,
        email=email,
        role='analyste'  # ← par défaut analyste, l'admin attribue le rôle
    )
    db.session.add(nouvel_utilisateur)
    db.session.commit()
    return render_template('login.html',
        succes_inscription="Compte créé avec succès ! Connectez-vous.")


@auth.route('/dashboard')
def dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('auth.login'))
    admin = Administrateur.query.get(session['admin_id'])
    return render_template('dashboard.html', admin=admin)


@auth.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))