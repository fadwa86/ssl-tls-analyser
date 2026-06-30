import sys
# Console Windows en cp1252 par défaut : un print() contenant '→', '✓', etc. fait
# planter le thread de scan (UnicodeEncodeError). On force la sortie en UTF-8.
for _flux in (sys.stdout, sys.stderr):
    try:
        _flux.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from flask import Flask, redirect
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

from models.models import db
db.init_app(app)

from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

# Protection CSRF sur toutes les requêtes POST (formulaires + fetch JSON). Les
# formulaires portent {{ csrf_token() }} ; les appels fetch envoient l'en-tête
# X-CSRFToken. Les flux SSE (GET) ne sont pas concernés.
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

with app.app_context():
    db.create_all()
    print("Tables créées avec succès !")
    
    from models.models import Administrateur
    if not Administrateur.query.filter_by(role='Administrateur').first():
        bcrypt = Bcrypt(app)
        admin = Administrateur(
            nom='Touibi', prenom='Fadwa',
            login='fadwa',
            password=bcrypt.generate_password_hash('fadwa123456').decode('utf-8'),
            email='fadwa.touibi@gmail.com',
            role='Administrateur'
        )
        db.session.add(admin)
        db.session.commit()
        print("✓ Admin initial créé automatiquement")

from routes.auth import auth
from routes.scan import scan_bp
from routes.historique import historique_bp
from routes.priorisation import prio_bp
from routes.rapport import rapport_bp
from routes.profil import profil_bp
from routes.multiport_scan import multiport_bp
from routes.comparison_bp import comparison_bp

app.register_blueprint(auth)
app.register_blueprint(scan_bp)
app.register_blueprint(historique_bp)
app.register_blueprint(prio_bp)
app.register_blueprint(rapport_bp)
app.register_blueprint(profil_bp)
app.register_blueprint(multiport_bp, url_prefix='/multiport')
app.register_blueprint(comparison_bp, url_prefix='/comparison')

@app.route('/')
def index():
    return redirect('/login')

if __name__ == '__main__':
    # Serveur WSGI Cheroot (celui de CherryPy) en HTTP. On garde Cheroot plutôt que le
    # serveur de dev Werkzeug pour conserver le modèle threadé (chaque flux SSE garde un
    # thread). En HTTP il n'y a pas de handshake TLS : plus de certificat auto-signé ni de
    # risque de blocage du handshake. Pas de rechargement auto : relancer après modification.
    from cheroot.wsgi import Server as ServeurWSGI

    serveur = ServeurWSGI(('127.0.0.1', 5000), app, numthreads=16)
    print('HTTP : http://127.0.0.1:5000  (Cheroot, Ctrl+C pour arrêter)')
    try:
        serveur.start()
    except KeyboardInterrupt:
        serveur.stop()