from app import app, db, Usuario, Funcionario, Alerta
from werkzeug.security import generate_password_hash
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

def initialize_database():
    with app.app_context():
        db.drop_all()
        db.create_all()
        
        if not Usuario.query.filter_by(email=os.getenv("USUARIO_EMAIL")).first():
            usuario = Usuario(
                nome="João Silva",
                email=os.getenv("USUARIO_EMAIL"),
                telefone="11999999999",
                endereco="12603000",
                senha=generate_password_hash(os.getenv("USUARIO_SENHA"))
            )
            db.session.add(usuario)
        
        admin = Funcionario.query.filter_by(email=os.getenv("ADMIN_EMAIL")).first()
        if not admin:
            admin = Funcionario(
                nome='Administrador',
                email=os.getenv("ADMIN_EMAIL"),
                senha=generate_password_hash(os.getenv("ADMIN_SENHA")),
                is_admin=True
            )
            db.session.add(admin)
            db.session.flush()
            
        db.session.commit()
        print("✅ Banco de dados inicializado com sucesso!")

if __name__ == '__main__':
    initialize_database()
