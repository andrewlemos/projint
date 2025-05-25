from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from twilio.rest import Client
from zoneinfo import ZoneInfo
import os
import requests
import threading
import time
import re
import signal
import sys
import atexit
import socket



load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///defesa_civil.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_funcionario'

# Configuração específica para GitHub Codespaces
if 'CODESPACES' in os.environ:
    codespace_name = os.environ.get('CODESPACE_NAME', '')
    app.config['SERVER_NAME'] = f"{codespace_name}-5001.app.github.dev"
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
else:
    app.config['SERVER_NAME'] = None

# Configurações da API REDEMET
load_dotenv()
REDEMET_API_KEY = os.getenv("REDEMET_API_KEY")
LOCALIDADE = os.getenv("LOCALIDADE")
API_URL = os.getenv("API_URL")

# Variável global para armazenar os dados meteorológicos
dados_meteorologicos = {
    'localidade': 'N/A',
    'nome_aerodromo': 'N/A',
    'cidade': 'N/A',
    'data_hora': 'N/A',
    'temperatura': 'N/A',
    'umidade': 'N/A',
    'visibilidade': 'N/A',
    'teto': 'N/A',
    'ceu': 'N/A',
    'condicao_tempo': 'N/A',
    'vento': 'N/A',
    'imagem_tempo': None,
    'atualizacao': 'Nunca'
}

# Variáveis para controle de threads
atualizacao_thread = None
encerrar_thread = threading.Event()

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    telefone = db.Column(db.String(20), unique=True, nullable=False)
    endereco = db.Column(db.String(200), nullable=False)
    senha = db.Column(db.String(200), nullable=False)

class Funcionario(db.Model, UserMixin):
    __tablename__ = 'funcionario'
    
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relacionamento simplificado sem back_populates
    alertas = db.relationship('Alerta', backref='funcionario_rel', lazy=True)

class Alerta(db.Model):
    __tablename__ = 'alertas'
    
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(300), nullable=False)
    cep_afetado = db.Column(db.String(20), nullable=False)
    data_criacao = db.Column(db.DateTime, default=datetime.utcnow)
    funcionario_id = db.Column(db.Integer, db.ForeignKey('funcionario.id'))

@login_manager.user_loader
def load_user(funcionario_id):
    return Funcionario.query.get(int(funcionario_id))    

def converter_para_utc3(dt_string):
    """Converte uma string de data/hora UTC para UTC-3 (Horário de Brasília)"""
    if dt_string == 'N/A':
        return 'N/A'
    
    formatos = [
        '%Y-%m-%d %H:%M:%S',    # Formato da API REDEMET
        '%d/%m/%Y %H:%M UTC',   # Formato de atualização
        '%Y-%m-%dT%H:%M:%SZ',   # Formato ISO em Z
        '%Y%m%d%H%M%S'          # Formato de METAR
    ]
    
    for fmt in formatos:
        try:
            dt = datetime.strptime(dt_string, fmt)
            dt_local = dt.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=-3)))
            return dt_local.strftime('%d/%m/%Y %H:%M')
        except ValueError:
            continue
    
    return dt_string  # Retorna original se nenhum formato funcionar

def obter_dados_tempo_presente():
    """Obtém dados meteorológicos em tempo real da API REDEMET"""
    try:
        params = {
            'api_key': REDEMET_API_KEY,
            'localidade': LOCALIDADE,
            'metar': 'sim'
        }

        response = requests.get(API_URL, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get('status') and data.get('data'):
            dados_api = data['data']
            agora_utc = datetime.now(timezone.utc)
            agora_local = converter_para_utc3(agora_utc.strftime('%Y-%m-%d %H:%M:%S'))

            # Extrai data do METAR se não estiver no campo 'data'
            data_hora_api = dados_api.get('data', 'N/A')
            if data_hora_api == 'N/A' and 'metar' in dados_api:
                metar = dados_api['metar']
                # Procura por padrão DDhhmmZ no METAR
                match = re.search(r'(\d{2})(\d{2})(\d{2})Z', metar)
                if match:
                    day, hour, minute = match.groups()
                    data_hora_api = f"{datetime.now(timezone.utc).year}-{datetime.now(timezone.utc).month}-{day} {hour}:{minute}:00"

            dados_meteorologicos.update({
                'localidade': dados_api.get('localidade', 'N/A'),
                'nome_aerodromo': dados_api.get('nome', 'N/A'),
                'cidade': dados_api.get('cidade', 'N/A'),
                'lon': dados_api.get('lon', 'N/A'),
                'lat': dados_api.get('lat', 'N/A'),
                'localizacao': dados_api.get('localizacao', 'N/A'),
                'data_hora': converter_para_utc3(data_hora_api),
                'temperatura': dados_api.get('temperatura', 'N/A'),
                'umidade': dados_api.get('ur', 'N/A'),
                'visibilidade': dados_api.get('visibilidade', 'N/A'),
                'teto': dados_api.get('teto', 'N/A'),
                'ceu': dados_api.get('ceu', 'N/A'),
                'condicao_tempo': dados_api.get('condicoes_tempo', 'N/A'),
                'vento': dados_api.get('vento', 'N/A'),
                'imagem_tempo': dados_api.get('tempoImagem', None),
                'metar': dados_api.get('metar', 'N/A'),
                'atualizacao': agora_local
            })

            print("Dados meteorológicos atualizados com sucesso!")
            return dados_meteorologicos

    except Exception as e:
        print(f"Erro ao obter dados meteorológicos: {e}")

    return dados_meteorologicos

def agendador_atualizacao():
    """Agenda atualizações para 5 minutos após a hora cheia"""
    while not encerrar_thread.is_set():
        try:
            agora = datetime.now(timezone.utc)
            prox_atualizacao = (agora.replace(minute=5, second=0, microsecond=0) + timedelta(hours=1))
            espera = (prox_atualizacao - agora).total_seconds()

            # Espera com verificação periódica do evento de encerramento
            while espera > 0 and not encerrar_thread.is_set():
                time.sleep(min(1, espera))
                espera = (prox_atualizacao - datetime.now(timezone.utc)).total_seconds()
                
            if not encerrar_thread.is_set():
                obter_dados_tempo_presente()
                print(f"Dados meteorológicos atualizados em: {datetime.now(timezone.utc)}")
        except Exception as e:
            print(f"Erro no agendador de atualização: {e}")

def initialize_database():
    with app.app_context():
        # Forçar recriação do banco
        db.drop_all()
        db.create_all()
        
        # Criar admin se não existir
        admin_email = os.getenv('ADMIN_EMAIL')
        admin_senha = os.getenv('ADMIN_SENHA')

        if not Funcionario.query.filter_by(email=admin_email).first():
            admin = Funcionario(
                nome='Administrador',
                email=admin_email,
                senha=generate_password_hash(admin_senha),
                is_admin=True
            )
            db.session.add(admin)
            
                     
            db.session.commit()
            print("✅ Banco de dados inicializado com sucesso!")

def convert_utc_to_local(utc_time_str):
    """Converte datetime UTC para horário local (UTC-3)"""
    try:
        if not utc_time_str or utc_time_str.lower() == 'horário desconhecido':
            return "horário desconhecido"
            
        # Formatos possíveis que a API pode retornar
        formatos = [
            '%Y-%m-%d %H:%M:%S',  # Formato padrão da API
            '%Y%m%d%H%M%S',       # Formato de Metar
            '%Y-%m-%dT%H:%M:%SZ'  # Formato ISO em Z
        ]
        
        for fmt in formatos:
            try:
                utc_time = datetime.strptime(utc_time_str, fmt).replace(tzinfo=timezone.utc)
                local_time = utc_time.astimezone(timezone(timedelta(hours=-3)))  # UTC-3 (Brasília)
                return local_time.strftime('%d/%m/%Y %H:%M')
            except ValueError:
                continue
                
        return utc_time_str  # Retorna original se não conseguir converter
    except Exception as e:
        print(f"Erro ao converter horário: {e}")
        return utc_time_str

def kt_to_kmh(kt_value):
    """Converte velocidade de nós (kt) para km/h"""
    try:
        if kt_value is None:
            return None
        return round(float(kt_value) * 1.852)
    except (ValueError, TypeError) as e:
        print(f"Erro ao converter nós para km/h: {e}")
        return None            

def get_weather_warnings():
    """Obtém Avisos de Aeródromo da API REDEMET no formato correto"""
    alertas_formatados = []
    try:
        # Formatar datas para o período atual (últimas 24 horas)
        agora = datetime.now(timezone(timedelta(hours=-3)))

        data_ini = (agora).strftime("%Y%m%d%H")
        data_fim = (agora + timedelta(hours=3)).strftime("%Y%m%d%H")
        
        url = f"https://api-redemet.decea.mil.br/mensagens/aviso/{LOCALIDADE}"
        params = {
            'api_key': REDEMET_API_KEY,
            'data_ini': data_ini,
            'data_fim': data_fim,
            'page_tam': 150  # Número máximo de resultados
        }

        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        
        print(f"DEBUG - Resposta da API: {data}")  # Para análise
        
        if data.get('status') and isinstance(data.get('data'), dict):
            if 'data' in data['data'] and isinstance(data['data']['data'], list):
                for aviso in data['data']['data']:
                    alerta = process_aviso(aviso)
                    if alerta:
                        alertas_formatados.append(alerta)
            else:
                print("Nenhum aviso ativo encontrado")
        else:
            print("Resposta da API inválida ou sem status")
            
    except requests.exceptions.RequestException as e:
        print(f"Erro ao acessar a API: {e}")
    
    return alertas_formatados

def process_aviso(aviso):
    """Processa um aviso individual conforme a estrutura real da API"""
    try:
        if not isinstance(aviso, dict):
            print(f"Aviso não é um dicionário: {type(aviso)}")
            return None

        mens = aviso.get('mens', '')
        inicio = aviso.get('validade_inicial', '')
        fim = aviso.get('validade_final', '')
        
        # Código ICAO do aeródromo
        aerodromo = mens.split('/')[0] if '/' in mens else LOCALIDADE
        
        # Condições meteorológicas
        has_ts = " TS " in mens or "TROVOADA" in mens.upper()
        has_wspd = "WSPD" in mens
        
        # Detalhes do vento
        vento_info = {}
        if has_wspd:
            vento_match = re.search(r'WSPD\s*(\d+)KT(?:\s*MAX\s*(\d+))?', mens)
            if vento_match:
                vento_info = {
                    'base_kt': vento_match.group(1),
                    'max_kt': vento_match.group(2),
                    'base_kmh': kt_to_kmh(vento_match.group(1)),
                    'max_kmh': kt_to_kmh(vento_match.group(2)) if vento_match.group(2) else None
                }
        
        # Construir mensagem
        mensagem = f"Alerta para {LOCALIDADE}: "
        conditions = []
        
        if has_ts:
            conditions.append("trovoadas")
        if has_wspd and vento_info.get('base_kt'):
            conditions.append(f"ventos de {vento_info['base_kt']}kt")
            if vento_info.get('max_kt'):
                conditions[-1] += f" a {vento_info['max_kt']}kt"
        
        mensagem += " e ".join(conditions) if conditions else "condições adversas"
        
        # Converter horários para Local
        inicio_local = convert_utc_to_local(inicio) if inicio else "horário desconhecido"
        fim_local = convert_utc_to_local(fim) if fim else "horário desconhecido"
        
        return {
            'aerodromo': aerodromo,
            'mensagem': mensagem,
            'mensagem_original': mens,
            'validade_inicio': inicio_local,
            'validade_fim': fim_local,
            'has_ts': has_ts,
            'has_wspd': has_wspd,
            'vento': vento_info,
            'timestamp': datetime.now(timezone(timedelta(hours=-3))).strftime("%d/%m/%Y %H:%M")
        }
        
    except Exception as e:
        print(f"Erro ao processar aviso: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def encerrar_recursos():
    """Função para encerrar todos os recursos antes de sair"""
    print("\nEncerrando recursos...")
    encerrar_thread.set()
    
    if atualizacao_thread and atualizacao_thread.is_alive():
        print("Aguardando finalização do thread de atualização...")
        atualizacao_thread.join(timeout=5)
        if atualizacao_thread.is_alive():
            print("Thread de atualização não finalizou a tempo")
        else:
            print("Thread de atualização finalizado com sucesso")

def is_port_in_use(port):
    """Verifica se a porta está em uso"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def handle_exit(signum=None, frame=None):
    """Função para lidar com a saída do programa"""
    encerrar_recursos()
    sys.exit(0)

# Função para enviar SMS via Twilio
def enviar_sms(destinatario, mensagem):
    """Envia SMS usando a API Twilio"""
    try:
        account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        twilio_number = os.getenv("TWILIO_PHONE_NUMBER")
        
        if not all([account_sid, auth_token, twilio_number]):
            print("Variáveis de ambiente do Twilio não configuradas corretamente")
            return False
            
        client = Client(account_sid, auth_token)
        
        # Adiciona código do país se necessário
        if not destinatario.startswith('+'):
            destinatario = '+55' + destinatario  # Assume Brasil como padrão
            
        message = client.messages.create(
            body=mensagem,
            from_=twilio_number,
            to=destinatario
        )
        
        print(f"SMS enviado para {destinatario}: {message.sid}")
        return True
        
    except Exception as e:
        print(f"Erro ao enviar SMS: {e}")
        return False

# Rotas principais
@app.route('/')
def index():
    """Rota raiz que redireciona para a página inicial apropriada"""
    if 'funcionario_id' in session:
        return redirect(url_for('dashboard_funcionario'))
    elif 'usuario_id' in session:
        return redirect(url_for('dashboard_usuario'))
    return render_template('index.html')

@app.route('/cadastro_usuario', methods=['GET', 'POST'])
def cadastro_usuario():
    if request.method == 'POST':
        try:
            # Coleta e limpa os dados
            nome = request.form['nome']
            email = request.form['email']
            
            # Remove todos os não-dígitos do telefone e CEP
            telefone = re.sub(r'\D', '', request.form['telefone'])
            endereco = re.sub(r'\D', '', request.form['endereco'])
            
            senha = request.form['senha']

            # Validações
            if not email:
                flash('E-mail é obrigatório', 'danger')
                return redirect(url_for('cadastro_usuario'))

            if len(telefone) < 10 or len(telefone) > 11:
                flash('Telefone inválido', 'danger')
                return redirect(url_for('cadastro_usuario'))

            if len(endereco) != 8:
                flash('CEP deve conter 8 dígitos', 'danger')
                return redirect(url_for('cadastro_usuario'))

            # Cria usuário
            novo_usuario = Usuario(
                nome=nome,
                email=email,
                telefone=telefone,
                endereco=endereco,
                senha=generate_password_hash(senha)
            )

            db.session.add(novo_usuario)
            db.session.commit()
            flash('Cadastro realizado com sucesso!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar: {str(e)}', 'danger')
            return redirect(url_for('cadastro_usuario'))

    return render_template('cadastro_usuario.html')

@app.route('/login_funcionario', methods=['GET', 'POST'])
def login_funcionario():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')

        funcionario = Funcionario.query.filter_by(email=email).first()

        if funcionario and check_password_hash(funcionario.senha, senha):
            login_user(funcionario)
            session['funcionario_id'] = funcionario.id
            session['funcionario_nome'] = funcionario.nome
            session['funcionario_email'] = funcionario.email
            
            if 'CODESPACES' in os.environ:
                return redirect(url_for('dashboard_funcionario', _external=True).replace(':5001', ''))
            return redirect(url_for('dashboard_funcionario'))

        flash('Credenciais inválidas!', 'danger')

    return render_template('login_funcionario.html')



@app.route('/dashboard_funcionario')
def dashboard_funcionario():
    if 'funcionario_id' not in session:
        return redirect(url_for('login_funcionario'))

    # Obter dados básicos
    alertas_cadastrados = Alerta.query.order_by(Alerta.data_criacao.desc()).limit(5).all()
    dados_tempo = obter_dados_tempo_presente()
    alertas_meteo = get_weather_warnings() or []
    
    # Verifica se há alertas para tocar o som
    tem_alertas = bool(alertas_meteo)
    
    return render_template('dashboard_funcionario.html',
                         alertas=alertas_cadastrados,
                         alertas_meteo=alertas_meteo,
                         dados_tempo=dados_tempo,
                         LOCALIDADE=LOCALIDADE,
                         tem_alertas=tem_alertas,
                         nome=session.get('funcionario_nome', 'Funcionário'))

@app.route('/dashboard_usuario')
def dashboard_usuario():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    # Buscar usuário logado
    usuario = Usuario.query.get(session['usuario_id'])
    if not usuario:
        return redirect(url_for('login'))

    # Filtrar alertas pelo CEP (que está no campo endereco do usuario)
    alertas_cadastrados = Alerta.query.filter_by(cep_afetado=usuario.endereco).order_by(Alerta.data_criacao.desc()).limit(5).all()

    dados_tempo = obter_dados_tempo_presente()
    alertas_meteo = get_weather_warnings() or []

    return render_template('dashboard_usuario.html',
                           alertas=alertas_cadastrados,
                           alertas_meteo=alertas_meteo,
                           dados_tempo=dados_tempo,
                           LOCALIDADE=LOCALIDADE,
                           nome=session.get('usuario_nome', 'Usuário'))

@app.template_filter('format_datetime')
def format_datetime_filter(value):
    if value is None:
        return ""
    try:
        # Formata para 'dd/mm/aaaa HH:MM' (UTC-3)
        return (value - timedelta(hours=3)).strftime('%d/%m/%Y %H:%M')
    except:
        return str(value)

@app.route('/novo_alerta', methods=['POST'])
def novo_alerta():
    if 'funcionario_id' not in session:
        return redirect(url_for('login_funcionario'))

    # Validação dos dados do formulário
    if not request.form.get('descricao') or not request.form.get('cep'):
        flash('Descrição e CEP são obrigatórios!', 'danger')
        return redirect(url_for('dashboard_funcionario'))

    try:
        descricao = request.form['descricao']
        cep = request.form['cep']
        
        # Limpa e valida o CEP
        cep_limpo = re.sub(r'\D', '', cep)
        if len(cep_limpo) != 8:
            flash('CEP inválido. Deve conter 8 dígitos.', 'danger')
            return redirect(url_for('dashboard_funcionario'))

        # Cria o alerta com data/hora UTC
        novo_alerta = Alerta(
            descricao=descricao,
            cep_afetado=cep_limpo,
            funcionario_id=session['funcionario_id']
        )

        db.session.add(novo_alerta)
        db.session.commit()
        
        # Notifica usuários afetados
        usuarios_afetados = Usuario.query.filter(
            Usuario.endereco.like(f"{cep_limpo[:5]}%")
        ).all()
        
        notificacoes_enviadas = 0
        if usuarios_afetados:
            for usuario in usuarios_afetados:
                mensagem = (
                    f"ALERTA DEFESA CIVIL: {descricao}\n"
                    f"CEP afetado: {cep_limpo[:5]}-{cep_limpo[5:]}\n"
                    f"Data: {datetime.now(ZoneInfo('America/Sao_Paulo')).strftime('%d/%m/%Y %H:%M')}"
                )
                if enviar_sms(usuario.telefone, mensagem):
                    notificacoes_enviadas += 1
                else:
                    print(f"Falha ao enviar SMS para {usuario.telefone}")
                    # Pode adicionar um log mais robusto aqui

        # Feedback para o usuário
        if notificacoes_enviadas > 0:
            flash(f'Alerta criado! Notificações enviadas para {notificacoes_enviadas} usuário(s).', 'success')
        else:
            flash('Alerta criado, mas nenhum usuário foi notificado na área afetada.', 'info')
            
    except Exception as e:
        db.session.rollback()
        print(f"Erro detalhado: {str(e)}")  # Log para debug
        flash('Erro ao processar o alerta. Por favor, tente novamente.', 'danger')
    
    return redirect(url_for('dashboard_funcionario'))

@app.route('/cadastro_funcionarios', methods=['GET', 'POST'])
def cadastro_funcionarios():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = generate_password_hash(request.form['senha'])
        
        novo_funcionario = Funcionario(
            nome=nome, email=email, senha=senha
        )
        db.session.add(novo_funcionario)
        db.session.commit()
        return redirect('/login_funcionario')
    return render_template('cadastro_funcionarios.html')

@app.route('/logout')
def logout():
    session.clear()
    response = redirect(url_for('index'))
    response.delete_cookie(app.config['SESSION_COOKIE_NAME'])
    
    if 'CODESPACES' in os.environ:
        response.headers['Location'] = response.headers['Location'].replace(':5001', '')
    
    flash('Logout realizado com sucesso', 'success')
    return response

@app.route('/ver_alertas/<int:funcionario_id>')
@login_required
def ver_alertas_funcionario(funcionario_id):
    # código para buscar e exibir alertas do funcionário
    return render_template('alertas_funcionario.html', funcionario_id=funcionario_id)


@app.route('/excluir_funcionario/<int:funcionario_id>', methods=['POST'])
def excluir_funcionario(funcionario_id):
    if 'funcionario_id' not in session or session.get('funcionario_email') != 'admin@defesacivil.com':
        return redirect(url_for('index'))

    funcionario = Funcionario.query.get_or_404(funcionario_id)
    db.session.delete(funcionario)
    db.session.commit()
    flash('Funcionário excluído com sucesso!', 'success')
    return redirect(url_for('painel_admin'))


@app.route('/painel_admin')
@login_required
def painel_admin():
    # Verifica se o usuário é admin
    if not current_user.is_admin:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('dashboard_funcionario'))

    funcionarios = Funcionario.query.all()
    alertas_por_funcionario = {
        func: Alerta.query.filter_by(funcionario_id=func.id)
                         .order_by(Alerta.data_criacao.desc())
                         .all()
        for func in funcionarios
    }
    
    return render_template('painel_admin.html',
                         funcionarios=funcionarios,
                         alertas_por_funcionario=alertas_por_funcionario)

@app.route('/termo-consentimento')
def termo_consentimento():
    return render_template('termo_consentimento.html')

@app.route('/contatos')
def contatos():
    return render_template('contatos.html')

# LOGIN 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')

        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and check_password_hash(usuario.senha, senha):
            session['usuario_id'] = usuario.id
            session['usuario_nome'] = usuario.nome
            
            if 'CODESPACES' in os.environ:
                return redirect(url_for('dashboard_usuario', _external=True).replace(':5001', ''))
            return redirect(url_for('dashboard_usuario'))

        flash('Credenciais inválidas!', 'danger')

    return render_template('login.html')    


# DASHBOARD
@app.route('/dashboard')
def dashboard():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', usuario=session['usuario_id'])


# Configurações adicionais para iframes
@app.after_request
def add_security_headers(response):
    # Permite iframes do mesmo domínio e da REDEMET
    response.headers['X-Frame-Options'] = 'ALLOW-FROM https://www.redemet.aer.mil.br/'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'self' https://www.redemet.aer.mil.br"
    return response

if __name__ == '__main__':
    # Registrar handlers para sinais de encerramento
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    atexit.register(encerrar_recursos)
    
    initialize_database()
    
    # Iniciar thread de atualização
    encerrar_thread.clear()
    atualizacao_thread = threading.Thread(target=agendador_atualizacao)
    atualizacao_thread.daemon = True  # Garante que o thread será encerrado com o programa
    atualizacao_thread.start()
    
    obter_dados_tempo_presente()
    
    try:
        port = int(os.environ.get('PORT', 5001))
        
        # Verificar se a porta está disponível
        if is_port_in_use(port):
            print(f"A porta {port} já está em uso. Tentando encontrar porta alternativa...")
            for p in range(port+1, port+10):
                if not is_port_in_use(p):
                    port = p
                    print(f"Usando porta alternativa: {port}")
                    break
        
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
        
        # Se estiver no GitHub Codespaces, imprimir a URL de acesso
        if 'CODESPACES' in os.environ:
            print(f"\nAplicação disponível em: https://{app.config['SERVER_NAME']}")
    except Exception as e:
        print(f"Erro ao iniciar servidor: {e}")
        handle_exit()