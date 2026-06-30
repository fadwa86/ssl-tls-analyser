import os


class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/vulnerability_scanner'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Clé de signature des sessions/CSRF : surchargeable par variable d'environnement
    # (à définir en prod). Repli sur la clé de dev si non définie.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'tls_analyser_secret_key'

    # Durcissement des cookies de session : l'app est servie en HTTP (en local).
    SESSION_COOKIE_SECURE = False      # HTTP : le cookie Secure ne serait jamais renvoyé
    SESSION_COOKIE_HTTPONLY = True     # inaccessible au JavaScript (atténuation XSS)
    SESSION_COOKIE_SAMESITE = 'Lax'    # bloque l'envoi du cookie sur un POST cross-site
    PREFERRED_URL_SCHEME = 'http'      # url_for(_external=True) génère du http