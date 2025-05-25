# 🌩️ Alerta Defesa: Sistema de Monitoramento e Alerta de Risco

Desenvolvido com foco na **Defesa Civil**, este sistema oferece **monitoramento em tempo real** de condições meteorológicas e envio de **alertas via SMS** para a população em áreas de risco. A aplicação consome dados da API REDEMET (Decea) e permite o gerenciamento de usuários e funcionários, com funcionalidades específicas para cada perfil.

---

## 🚀 Funcionalidades

### 🌦️ Monitoramento Meteorológico em Tempo Real
- Temperatura, umidade, visibilidade
- Condições do tempo: céu, vento, teto
- Alertas meteorológicos automáticos

### 🚨 Sistema de Alertas
- Cadastro manual de alertas por funcionários
- Notificação via **SMS** para usuários afetados
- Histórico de alertas

### 🔐 Autenticação e Autorização
- Dois perfis: **usuário civil** e **funcionário**
- Painéis de controle personalizados
- Proteção de rotas sensíveis

### 🔗 Integração com APIs
- **REDEMET** (dados meteorológicos)
- **Twilio** (envio de mensagens SMS)

---

## 🛠️ Tecnologias Utilizadas

### Backend
- Python 3.8+
- Flask
- Flask-SQLAlchemy
- Requests
- Twilio

### Frontend
- HTML5 + CSS3
- Bootstrap (interface responsiva)
- Jinja2 (templates)

### Banco de Dados
- SQLite (ideal para desenvolvimento)

---

## ⚙️ Configuração do Ambiente

### Pré-requisitos
- Python 3.8 ou superior
- pip (gerenciador de pacotes)
- Conta no [Twilio](https://www.twilio.com/)
- Chave de API da [REDEMET](https://api-redemet.decea.mil.br/)

### Instalação

```bash
# Clone o repositório
git clone https://github.com/andrewlemos/PI.git
cd PI

# Crie e ative um ambiente virtual (recomendado)
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Instale as dependências
pip install -r requirements.txt
```

### Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto com o seguinte conteúdo:

```env
SECRET_KEY=sua_chave_secreta
REDEMET_API_KEY=sua_api_key
LOCALIDADE=SBBR
API_URL=https://api-redemet.decea.mil.br/mensagens/aviso/
TWILIO_ACCOUNT_SID=seu_account_sid
TWILIO_AUTH_TOKEN=seu_auth_token
TWILIO_PHONE_NUMBER=+1234567890
```

### Inicialização do Banco de Dados

```bash
python -c "from app import initialize_database; initialize_database()"
```

---

## ▶️ Executando a Aplicação

```bash
python app.py
```

- Acesse localmente: [http://localhost:5001](http://localhost:5001)  
- Em Codespaces: `https://[CODESPACE_NAME]-5001.app.github.dev`

---

## 📁 Estrutura do Projeto

```
defesa-civil-app/
├── app.py
├── requirements.txt
├── .env
├── instance/
│   └── defesa_civil.db
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── cadastro_usuario.html
│   ├── login_funcionario.html
│   ├── dashboard_funcionario.html
│   └── dashboard_usuario.html
└── README.md
```

---

## 🧩 Modelos do Banco de Dados

- **Usuario**: nome, email, telefone, endereço (CEP), senha (hash)
- **Funcionario**: nome, email, senha (hash)
- **Alerta**: descrição, CEP afetado, data de criação, criado_por (FK para Funcionario)

---

## 🔁 Rotas Principais

| Rota                      | Descrição                                  |
|---------------------------|--------------------------------------------|
| `/`                       | Página inicial (redireciona conforme perfil) |
| `/login`                  | Login para usuários comuns                  |
| `/login_funcionario`      | Login para funcionários                     |
| `/cadastro_usuario`       | Cadastro de novos usuários                  |
| `/dashboard_funcionario`  | Painel de controle para funcionários        |
| `/dashboard_usuario`      | Painel de informações para usuários         |
| `/novo_alerta`            | Criação de novos alertas                    |
| `/logout`                 | Logout da sessão                           |

---

## 📜 Licença

Este projeto está **sob consulta do desenvolvedor**.  
Para obter uma licença de uso, entre em contato com **Andrew Lemos**.

---

## 📬 Contato

Caso tenha dúvidas, sugestões ou queira colaborar com o projeto, entre em contato com o desenvolvedor:

**Andrew Lemos**  
[LinkedIn](https://www.linkedin.com/in/andrewlemos) | [GitHub](https://github.com/andrewlemos)

---
