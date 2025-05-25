import os

SECRET_KEY = os.environ.get('SECRET_KEY') or 'sua-chave-secreta-aqui'
SQLALCHEMY_DATABASE_URI = 'sqlite:///defesa_civil.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
