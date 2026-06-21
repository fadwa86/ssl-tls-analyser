class Config:
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/vulnerability_scanner'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'tls_analyser_secret_key'