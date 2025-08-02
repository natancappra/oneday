import os
import uuid
from datetime import datetime, timedelta, date, timezone
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_migrate import Migrate
from flask import Flask, render_template, redirect, url_for, request, abort, flash, jsonify, has_request_context, send_file
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer as Serializer
from wtforms import PasswordField
from itertools import combinations
import json
import io
import random
import math
import config
import pandas as pd
from extensions import db
from models import User, Time, Jogador, Game, Configuracao, Grupo, Classificacao
import dropbox
from PIL import Image
import traceback
from wtforms import PasswordField

# --- Constantes do Campeonato ---

# --- CONFIGURAÇÕES MANUAIS DE TEMPO (COLE AS 3 LINHAS AQUI) ---
INTERVALO_JOGOS_FUTEBOL_MINUTOS = 17
HORA_INICIO_JOGOS = 8  # <<-- Mude a HORA de início aqui (formato 24h)
MINUTO_INICIO_JOGOS = 30 # <<-- Mude o MINUTO de início aqui
# ----------------------------------------------------------------

REGIAO_OPCOES = [
    "Região 1 | Moving - Regional Natan Cappra", "Região 2 | I Am - Regional Daniel Martins",
    "Região 3 | Chamados - Regional Roberta Pedroso", "Região 4 | Together - Regional Maycon Lilo",
    "Região 5 | Reaviva - Regional Sônia Ribeiro", "Região 6 | Bethel - Regional Matheus Felipe",
    "Região 7 | Tô Ligado - Regional Regis Nogara", "Região 8 | Forgiven - Regional Jeferson Martins",
]
LINK_PAGAMENTO_PADRAO = "https://eventodaigreja.com.br/ILRJ81"

# --- Criação e Configuração do App ---
app = Flask(__name__)
app.config.from_object(config)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['SECRET_KEY'] = 'vkexidzlrxtpyarh'

# --- Inicialização das Extensões ---
mail = Mail(app)
db.init_app(app)
migrate = Migrate(app, db, render_as_batch=True)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
admin = Admin(app, name='Painel Admin', template_mode='bootstrap4')


# --- Configuração do Flask-Admin ---
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

class UserModelView(AdminModelView):
    # Colunas a não serem exibidas na lista de usuários
    column_exclude_list = ['password_hash']
    # Colunas a serem excluídas dos formulários (o hash da senha e a lista de times)
    form_excluded_columns = ['password_hash', 'times']

    # Campo extra para o formulário que não existe diretamente no modelo
    # Isso diz ao Flask-Admin: "Crie um campo de senha chamado 'password'"
    form_extra_fields = {
        'password': PasswordField('Nova Senha (deixe em branco para não alterar)')
    }

    # Regras para o formulário de CRIAÇÃO (exige a nova senha)
    form_create_rules = ('username', 'email', 'is_admin', 'password')

    # Regras para o formulário de EDIÇÃO (também permite alterar a senha)
    form_edit_rules = ('username', 'email', 'is_admin', 'password')

    # Função que é chamada ao salvar o formulário
    def on_model_change(self, form, model, is_created):
        # Se o campo de senha foi preenchido, atualiza o hash da senha
        if form.password.data:
            model.set_password(form.password.data)

admin.add_view(UserModelView(User, db.session))
admin.add_view(AdminModelView(Time, db.session))
admin.add_view(AdminModelView(Jogador, db.session))
admin.add_view(AdminModelView(Game, db.session))


# --- Funções de Apoio (Helpers) ---
@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        try: return json.loads(value)
        except (json.JSONDecodeError, TypeError): return None
    return None

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def log_auditoria(acao):
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    if has_request_context() and current_user.is_authenticated:
        print(f"AUDITORIA: {'Admin' if current_user.is_admin else 'Usuário'} '{current_user.username}' realizou a ação: {acao} em {timestamp}")
    else:
        print(f"AUDITORIA: [SISTEMA] Ação automática: {acao} em {timestamp}")

@app.route('/request_reset', methods=['GET', 'POST'])
def request_reset():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = get_reset_token(user)
            msg = Message('Redefinição de Senha - Campeonato Oneday',
                          sender=('Campeonato Oneday', app.config['MAIL_USERNAME']),
                          recipients=[user.email])

            msg.body = f'''Para redefinir sua senha, visite o seguinte link:
{url_for('reset_token', token=token, _external=True)}

Este link é válido por 30 minutos.

Se você não fez esta solicitação, simplesmente ignore este e-mail e nenhuma mudança será feita.
'''
            mail.send(msg)

        # Mostra a mesma mensagem para e-mails existentes ou não, por segurança
        flash('Se este e-mail estiver cadastrado, um link para redefinição de senha foi enviado.', 'info')
        return redirect(url_for('login'))

    return render_template('request_reset.html')

@app.route('/reset_token/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    user = verify_reset_token(token)
    if user is None:
        flash('O link para redefinição de senha é inválido ou expirou.', 'warning')
        return redirect(url_for('request_reset'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('As senhas não coincidem.', 'danger')
            return redirect(url_for('reset_token', token=token))

        user.set_password(password)
        db.session.commit()
        flash('Sua senha foi atualizada! Você já pode fazer login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html')

# --- Funções Auxiliares ---

def limpar_estrutura_torneio():
    """Helper que apaga jogos, grupos e classificações, mas mantém os times."""
    try:
        # Apaga em uma ordem que respeita as dependências do banco
        Game.query.delete()
        Classificacao.query.delete()
        Grupo.query.delete()
        # Desassocia todos os times de seus grupos antigos
        for time in Time.query.all():
            time.grupo_id = None
        db.session.commit()
        log_auditoria("Estrutura do torneio (jogos, grupos, classificação) foi zerada.")
        return True
    except Exception as e:
        db.session.rollback()
        log_auditoria(f"Falha ao zerar estrutura do torneio: {e}")
        return False


@app.route('/admin/limpar_torneio', methods=['POST'])
@login_required
def limpar_torneio_route():
    if not current_user.is_admin:
        abort(403)

    if limpar_estrutura_torneio():
        flash("O chaveamento (jogos, grupos e classificação) foi zerado com sucesso! Os times foram mantidos.",
              "success")
    else:
        flash("Ocorreu um erro ao tentar zerar o torneio.", "danger")

    return redirect(url_for('admin_master'))

def get_public_id_from_url(url):
    """Extrai o public_id de uma URL do Cloudinary para permitir a exclusão."""
    if not url:
        return None
    try:
        # Pega a parte depois da última "/"
        public_id_com_extensao = url.split('/')[-1]
        # Remove a extensão do arquivo (ex: .jpg, .png)
        public_id = os.path.splitext(public_id_com_extensao)[0]
        return public_id
    except Exception:
        return None

def log_auditoria(acao):
    """
    Registra uma ação de auditoria no console.
    Agora é seguro para ser chamado de scripts fora de um request.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    # Verifica se estamos em um contexto de request (alguém usando o site)
    # e se o usuário está logado.
    if has_request_context() and current_user.is_authenticated:
        if current_user.is_admin:
            print(f"AUDITORIA: Admin '{current_user.username}' realizou a ação: {acao} em {timestamp}")
        else:
            print(f"AUDITORIA: Usuário '{current_user.username}' realizou a ação: {acao} em {timestamp}")
    else:
        # Se não houver contexto de request (rodando via script), registra como ação do sistema.
        print(f"AUDITORIA: [SISTEMA] Ação automática: {acao} em {timestamp}")


def get_dbx_client():
    """
    Inicializa e retorna o cliente do Dropbox usando o Refresh Token.
    Este método garante que o acesso seja sempre válido e se renove
    automaticamente.
    """
    dbx = dropbox.Dropbox(
        app_key=app.config['DROPBOX_APP_KEY'],
        app_secret=app.config['DROPBOX_APP_SECRET'],
        oauth2_refresh_token=app.config['DROPBOX_REFRESH_TOKEN']
    )
    return dbx

def upload_and_get_shared_link(file_stream):
    """
    Otimiza uma imagem, faz o upload para o Dropbox e retorna um link direto para visualização.
    VERSÃO CORRIGIDA: Garante que o stream da imagem seja lido desde o início.
    """
    try:
        # --- LINHA DE CORREÇÃO ADICIONADA AQUI ---
        file_stream.seek(0)
        # -----------------------------------------

        # Otimização da imagem com Pillow
        img = Image.open(file_stream)

        # Se a imagem tiver um modo com canal alfa (transparência), como RGBA ou PA,
        # converte para RGB antes de salvar como JPEG.
        if img.mode in ('RGBA', 'PA'):
            img = img.convert("RGB")

        img.thumbnail((800, 800))  # Redimensiona a imagem para no máximo 800x800 pixels
        in_mem_file = io.BytesIO()
        # Salva em formato JPEG com 80% de qualidade para reduzir o tamanho
        img.save(in_mem_file, format='JPEG', quality=80)
        in_mem_file.seek(0)

        dbx = get_dbx_client()
        # Cria um nome de arquivo único para evitar conflitos
        file_path = f"/{uuid.uuid4().hex}.jpg"

        # Faz o upload do arquivo
        dbx.files_upload(in_mem_file.read(), file_path, mode=dropbox.files.WriteMode('overwrite'))

        # Cria um link compartilhável público
        settings = dropbox.sharing.SharedLinkSettings(requested_visibility=dropbox.sharing.RequestedVisibility.public)
        link_metadata = dbx.sharing_create_shared_link_with_settings(file_path, settings)

        # Converte o link padrão do Dropbox para um link de download/visualização direta
        direct_link = link_metadata.url.replace('www.dropbox.com', 'dl.dropboxusercontent.com').replace('?dl=0', '')

        # Retorna apenas o link direto, que será salvo no banco
        return direct_link
    except Exception as e:
        print(f"Erro no upload para o Dropbox: {e}")
        return None


def get_path_from_dropbox_url(url):
    """
    Extrai o caminho do arquivo (ex: /arquivo.jpg) de uma URL do Dropbox
    para permitir a exclusão. VERSÃO CORRIGIDA E MAIS SEGURA.
    """
    if not url or 'dropboxusercontent' not in url:
        return None
    try:
        # Extrai a parte final da URL, que é o nome do arquivo
        filename = url.split('/')[-1].split('?')[0]

        # VERIFICAÇÃO ADICIONAL: Garante que o nome do arquivo não está vazio
        if not filename:
            return None

        # Monta o caminho que o Dropbox espera para a exclusão
        return f"/{filename}"
    except Exception:
        return None


def delete_from_dropbox(file_path):
    """Deleta um arquivo do Dropbox usando seu caminho."""
    if not file_path:
        return
    try:
        dbx = get_dbx_client()
        dbx.files_delete_v2(file_path)
        print(f"Arquivo {file_path} deletado do Dropbox.")
    except Exception as e:
        # Ignora erros de "arquivo não encontrado" que podem acontecer
        if isinstance(e, dropbox.exceptions.ApiError) and 'path/not_found' in str(e.error):
            print(f"Arquivo {file_path} não encontrado no Dropbox, talvez já tenha sido deletado.")
        else:
            print(f"Erro ao deletar arquivo do Dropbox ({file_path}): {e}")


def allowed_file(filename):
    """Verifica se o formato do arquivo é permitido."""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'pdf'}

def get_next_power_of_2(n):
    """Retorna a próxima potência de 2 maior ou igual a n."""
    if n == 0:
        return 0
    return 2 ** (n - 1).bit_length()


def get_num_rounds(num_teams):
    """Calcula o número de rodadas para um torneio de eliminação simples."""
    if num_teams <= 1:
        return 0
    return (num_teams - 1).bit_length()

#função de reset de token
def get_reset_token(user, expires_sec=1800):
    s = Serializer(app.config['SECRET_KEY'])
    return s.dumps({'user_id': user.id})

def verify_reset_token(token):
    s = Serializer(app.config['SECRET_KEY'])
    try:
        # O token expira em 30 minutos (1800 segundos)
        user_id = s.loads(token, max_age=1800)['user_id']
    except:
        return None
    return User.query.get(user_id)

# Função para registrar ações administrativas (Auditoria simples no console)
def log_admin_action(action_description):
    if current_user.is_authenticated and current_user.is_admin:
        print(
            f"AUDITORIA: Admin '{current_user.username}' realizou a ação: {action_description} em {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print(
            f"AUDITORIA: Usuário não admin tentou realizar ação: {action_description} em {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user:
            if user.check_password(password):
                login_user(user)
                log_admin_action(f"Login bem-sucedido: '{username}'")
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('index'))
            else:
                log_admin_action(f"Login falhou (senha incorreta) para username: '{username}'")
                flash('Senha incorreta. Por favor, tente novamente.', 'danger')
        else:
            log_admin_action(f"Login falhou (usuário não encontrado) para username: '{username}'")
            flash('Nome de usuário não encontrado. Por favor, verifique seu nome de usuário.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_admin_action(f"Logout: '{current_user.username}'")
    logout_user()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')

        # --- NOVA LÓGICA DE VERIFICAÇÃO ---

        # 1. Verifica se o nome de usuário já existe
        user_existente = User.query.filter_by(username=username).first()
        if user_existente:
            flash('Este nome de usuário já está em uso. Por favor, escolha outro.', 'danger')
            return redirect(url_for('signup'))

        # 2. Verifica se o e-mail já existe
        email_existente = User.query.filter_by(email=email).first()
        if email_existente:
            flash('Este endereço de e-mail já foi cadastrado. Tente fazer o login ou recuperar sua senha.', 'danger')
            return redirect(url_for('signup'))

        # 3. Se tudo estiver ok, cria o novo usuário
        novo_usuario = User(username=username, email=email, is_admin=False)
        novo_usuario.set_password(password)
        db.session.add(novo_usuario)
        db.session.commit()

        log_auditoria(f"Novo usuário cadastrado: '{username}'")
        flash('Conta criada com sucesso! Agora você pode fazer o login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html', title='Cadastre-se')


# --- Rotas principais ---

@app.route('/')
@login_required
def index():
    if current_user.is_admin:
        # Se for admin, redireciona para o painel master
        return redirect(url_for('admin_master'))

    # Se for usuário comum, busca os times liderados por ele
    times_liderados = Time.query.filter_by(lider_id=current_user.id).all()

    # Usa o template 'lista_times.html', mas agora enviando os times que encontrou
    return render_template('lista_times.html', times=times_liderados)


@app.route('/times')
@login_required
def lista_times():
    if not current_user.is_admin:
        abort(403)
    times = Time.query.all()
    return render_template('lista_times.html', times=times, perfil='admin', now=datetime.now(timezone.utc))

@app.route('/cadastro_igreja', methods=['GET', 'POST'])
@login_required
def cadastro_igreja():
    # --- ADICIONE ESTA LINHA AQUI ---
    form_data = {} # Inicializa form_data como um dicionário vazio por padrão

    if request.method == 'POST':
        nome_igreja = request.form.get('nome_igreja')
        distrito = request.form.get('distrito')
        regiao = request.form.get('regiao')
        nome_base = request.form.get('nome_base')
        modalidade = request.form.get('modalidade')
        pagou = True if request.form.get('pagou') == 'on' else False
        diretor_jovem = request.form.get('diretor_jovem')

        # Converte para dict para manter os dados no formulário em caso de erro.
        # Agora, esta linha irá ATUALIZAR a variável form_data já inicializada.
        form_data = request.form.to_dict() # <--- MANTENHA ESTA LINHA

        ## MUDANÇA 1: Lógica de Upload para o Comprovante ##
        comprovante_url = None
        comprovante_file = request.files.get('comprovante_pagamento')
        if comprovante_file and allowed_file(comprovante_file.filename):
            try:
                # Lógica de Upload para o Dropbox
                # (Assumindo que 'upload_and_get_shared_link' está definida em algum lugar)
                comprovante_url = upload_and_get_shared_link(comprovante_file)
                if not comprovante_url:
                    flash('Erro: A URL do comprovante não foi gerada.', 'danger')
                    return render_template('cadastro_igreja.html', regiao_opcoes=REGIAO_OPCOES, LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO, form_data=form_data), 400
            except Exception as e:
                print("--- ERRO DETALHADO NO UPLOAD DO COMPROVANTE ---")
                traceback.print_exc()
                print("---------------------------------------------")
                flash(f'Erro interno ao processar comprovante. Verifique o terminal.', 'danger')
                return render_template('cadastro_igreja.html', regiao_opcoes=REGIAO_OPCOES,
                                           LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO, form_data=form_data), 400
        elif comprovante_file and comprovante_file.filename != '':
            flash('Formato de comprovante inválido. Use PNG, JPG, JPEG, GIF ou PDF.', 'danger')
            return render_template('cadastro_igreja.html', regiao_opcoes=REGIAO_OPCOES, LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO, form_data=form_data), 400

        if not nome_igreja or not modalidade:
            flash('Nome da igreja e modalidade são campos obrigatórios.', 'danger')
            return render_template('cadastro_igreja.html', regiao_opcoes=REGIAO_OPCOES, LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO, form_data=form_data), 400


        imagem_url = None
        imagem_file = request.files.get('imagem')
        if imagem_file and allowed_file(imagem_file.filename):
            try:
                # Lógica de Upload para o Dropbox
                # (Assumindo que 'upload_and_get_shared_link' está definida em algum lugar)
                imagem_url = upload_and_get_shared_link(imagem_file)
                if not imagem_url:
                    flash('Erro: A URL da imagem não foi gerada.', 'danger')
                    return render_template('cadastro_igreja.html', regiao_opcoes=REGIAO_OPCOES, LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO, form_data=form_data), 400
            except Exception as e:
                print("--- ERRO DETALHADO NO UPLOAD DA IMAGEM DO TIME ---")
                traceback.print_exc()
                print("--------------------------------------------------")
                flash(f'Erro interno ao processar imagem do time. Verifique o terminal.', 'danger')
                return render_template('cadastro_igreja.html', regiao_opcoes=REGIAO_OPCOES,
                                           LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO, form_data=form_data), 400
        elif imagem_file and imagem_file.filename != '':
            flash('Formato de imagem inválido. Use PNG, JPG, JPEG ou GIF.', 'danger')
            return render_template('cadastro_igreja.html', regiao_opcoes=REGIAO_OPCOES, LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO, form_data=form_data), 400

        novo_time = Time(
            nome_igreja=nome_igreja,
            distrito=distrito,
            regiao=regiao,
            nome_base=nome_base,
            modalidade=modalidade,
            token=str(uuid.uuid4()),
            lider_id=current_user.id,
            imagem=imagem_url,
            link_pagamento=LINK_PAGAMENTO_PADRAO,
            pagou=pagou,
            comprovante_pagamento=comprovante_url,
            diretor_jovem=diretor_jovem,
            limite_nao_adv_fut_masc=request.form.get('limite_nao_adv_fut_masc', type=int, default=1),
            limite_nao_adv_fut_fem=request.form.get('limite_nao_adv_fut_fem', type=int, default=2),
            limite_nao_adv_volei_misto=request.form.get('limite_nao_adv_volei_misto', type=int, default=1),
        )
        db.session.add(novo_time)
        db.session.commit()
        log_admin_action(f"Cadastrou novo time: '{nome_igreja}'")
        flash('Time cadastrado com sucesso! Você pode prosseguir para o pagamento.', 'success')

        # Este return render_template já está correto após a última alteração para incluir form_data
        return render_template('cadastro_igreja.html',
                               regiao_opcoes=REGIAO_OPCOES,
                               LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO,
                               form_data=form_data, # ESTE form_data é o que foi preenchido no POST
                               time=novo_time), 200

    # Se o método não for POST (primeira carga da página), renderiza o formulário vazio
    # A variável form_data já foi inicializada no início da função como {}
    return render_template('cadastro_igreja.html',
                           regiao_opcoes=REGIAO_OPCOES,
                           LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO,
                           form_data=form_data, # ESTE form_data é o dicionário vazio inicializado
                           time=None)

@app.route('/cadastro_jogador/<token>', methods=['GET', 'POST'])
@login_required
def cadastro_jogador(token):
    time = Time.query.filter_by(token=token).first_or_404()
    if time.lider_id != current_user.id and not current_user.is_admin:
        abort(403)
    if time.cadastros_encerrados and not current_user.is_admin:
        flash('O cadastro de jogadores para este time foi encerrado.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    # Inicializa form_data e variáveis de frontend ANTES do bloco POST
    # Isso garante que elas sempre existam para o return final
    form_data = {}
    limite_nao_adventistas_para_frontend = 0
    count_nao_adventistas_para_frontend = 0  # Será atualizado abaixo

    # Define os defaults para os limites (caso config não exista ou atributos sejam None)
    limite_fut_masc_default = 1
    limite_fut_fem_default = 2
    limite_volei_misto_default = 1

    # Lógica para contar jogadores com mais de 35 anos (apenas para Futebol Masculino)
    count_acima_idade = 0
    MAX_EXCECOES = 2  # O limite definido
    if time.modalidade == 'Futebol Masculino':
        data_campeonato = date(2025, 8, 2)
        jogadores_acima_idade = [
            p for p in time.jogadores if p.data_nascimento and
                                         (((data_campeonato - p.data_nascimento).days / 365.25) > 35)
        ]
        count_acima_idade = len(jogadores_acima_idade)

    if request.method == 'POST':
        form_data = request.form.to_dict()  # Atualiza form_data com os dados do POST
        nome_completo = form_data.get('nome_completo')
        telefone = form_data.get('telefone')
        cpf = form_data.get('cpf')
        rg = form_data.get('rg')
        data_nascimento_str = form_data.get('data_nascimento')
        is_adventista = 'is_adventista' in form_data
        is_capitao = 'is_capitao' in form_data
        foto_file = request.files.get('foto')
        foto_identidade_file = request.files.get('foto_identidade')

        # --- Suas validações existentes ---
        if not nome_completo or not telefone:
            flash('O nome completo e o telefone do jogador são obrigatórios.', 'danger')
            # Retorna aqui com status 400
            return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        if not data_nascimento_str:
            flash('A data de nascimento é obrigatória.', 'danger')
            # Retorna aqui com status 400
            return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        try:
            data_nascimento = datetime.strptime(data_nascimento_str, '%Y-%m-%d').date()
            data_campeonato = date(2025, 8, 2)
            idade = (data_campeonato - data_nascimento).days / 365.25

            if time.modalidade == 'Futebol Masculino':
                IDADE_MINIMA, IDADE_MAXIMA_PADRAO, MAX_EXCECOES = 15, 35, 2
                if idade < IDADE_MINIMA:
                    flash(f'Erro: O jogador precisa ter no mínimo {IDADE_MINIMA} anos.', 'danger')
                    return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                           limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                           count_nao_adventistas=count_nao_adventistas_para_frontend), 400
                elif idade > IDADE_MAXIMA_PADRAO:
                    jogadores_acima_idade = [p for p in time.jogadores if p.data_nascimento and (
                            (data_campeonato - p.data_nascimento).days / 365.25) > IDADE_MAXIMA_PADRAO]
                    if len(jogadores_acima_idade) >= MAX_EXCECOES:
                        flash(
                            f'Erro: O time já atingiu o limite de {MAX_EXCECOES} jogadores com mais de {IDADE_MAXIMA_PADRAO} anos.',
                            'danger')
                        return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                               limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                               count_nao_adventistas=count_nao_adventistas_para_frontend), 400
            elif time.modalidade in ['Futebol Feminino', 'Vôlei Misto']:
                if idade < 15:
                    flash(f'Erro: Para a modalidade "{time.modalidade}", o jogador deve ter no mínimo 15 anos.',
                          'danger')
                    return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                           limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                           count_nao_adventistas=count_nao_adventistas_para_frontend), 400
        except ValueError:
            flash('Formato de data de nascimento inválido.', 'danger')
            return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        if cpf and cpf.strip() and Jogador.query.filter_by(cpf=cpf.strip()).first():
            flash(f'Erro: Já existe um jogador cadastrado com o CPF {cpf}.', 'danger')
            return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400
        if rg and rg.strip() and Jogador.query.filter_by(rg=rg.strip()).first():
            flash(f'Erro: Já existe um jogador cadastrado com o RG {rg}.', 'danger')
            return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400
        if is_capitao and Jogador.query.filter_by(time_id=time.id, is_capitao=True).first():
            flash('O time já possui um capitão.', 'danger')
            return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        # --- VALIDAÇÃO: LIMITE DE JOGADORES NÃO ADVENTISTAS ---
        if not is_adventista:
            config = Configuracao.query.first()
            limite_atual = 0
            config_nao_definida = False

            if config:
                if time.modalidade == 'Futebol Masculino':
                    limite_atual = getattr(config, 'limite_nao_adv_fut_masc', limite_fut_masc_default)
                elif time.modalidade == 'Futebol Feminino':
                    limite_atual = getattr(config, 'limite_nao_adv_fut_fem', limite_fut_fem_default)
                elif time.modalidade == 'Vôlei Misto':
                    limite_atual = getattr(config, 'limite_nao_adv_volei_misto', limite_volei_misto_default)
                else:
                    limite_atual = 0
            else:
                config_nao_definida = True
                if time.modalidade == 'Futebol Masculino':
                    limite_atual = limite_fut_masc_default
                elif time.modalidade == 'Futebol Feminino':
                    limite_atual = limite_fut_fem_default
                elif time.modalidade == 'Vôlei Misto':
                    limite_atual = limite_volei_misto_default
                else:
                    limite_atual = 0

            jogadores_nao_adv_existentes = Jogador.query.filter_by(time_id=time.id, is_adventista=False).count()

            if jogadores_nao_adv_existentes >= limite_atual:
                flash(
                    f"Você já cadastrou o limite de {limite_atual} jogador(es) não adventista(s) no time de {time.modalidade}, conforme o boletim informativo. Portanto, não poderá cadastrar esse jogador.",
                    'danger')
                # Retorna aqui com status 400
                return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                       limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                       count_nao_adventistas=count_nao_adventistas_para_frontend), 400

            if config_nao_definida:
                flash(
                    'Aviso: As configurações de limite de jogadores não adventistas não foram definidas pelo administrador. Limites padrão aplicados.',
                    'warning')

        # --- FIM DAS VALIDAÇÕES ---

        # Se todas as validações passarem, processa o upload e salva o jogador
        foto_url, foto_identidade_url = None, None
        try:
            if foto_file and allowed_file(foto_file.filename):
                foto_url = upload_and_get_shared_link(foto_file)
            if foto_identidade_file and allowed_file(foto_identidade_file.filename):
                foto_identidade_url = upload_and_get_shared_link(foto_identidade_file)
        except Exception as e:
            flash(f'Erro ao enviar imagens para o Dropbox: {e}', 'danger')
            # Retorna aqui com status 400
            return render_template('cadastro_jogador.html', time=time, perfil='lider', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        novo_jogador = Jogador(
            nome_completo=nome_completo, telefone=telefone, cpf=cpf, rg=rg,
            data_nascimento=data_nascimento, is_adventista=is_adventista, is_capitao=is_capitao,
            foto=foto_url, foto_identidade=foto_identidade_url, time_id=time.id
        )
        db.session.add(novo_jogador)
        db.session.commit()
        flash('Jogador cadastrado com sucesso!', 'success')

        return redirect(url_for('ver_time', time_id=time.id))

    # --- Este bloco é executado APENAS se request.method == 'GET' ---
    # Calcula as variáveis de frontend para a carga inicial da página (GET)
    config_current = Configuracao.query.first()

    # Atualiza count_nao_adventistas_para_frontend para o GET inicial
    count_nao_adventistas_para_frontend = Jogador.query.filter_by(time_id=time.id, is_adventista=False).count()

    if config_current:
        if time.modalidade == 'Futebol Masculino':
            limite_nao_adventistas_para_frontend = getattr(config_current, 'limite_nao_adv_fut_masc',
                                                           limite_fut_masc_default)
        elif time.modalidade == 'Futebol Feminino':
            limite_nao_adventistas_para_frontend = getattr(config_current, 'limite_nao_adv_fut_fem',
                                                           limite_fut_fem_default)
        elif time.modalidade == 'Vôlei Misto':
            limite_nao_adventistas_para_frontend = getattr(config_current, 'limite_nao_adv_volei_misto',
                                                           limite_volei_misto_default)
        else:
            limite_nao_adventistas_para_frontend = 0
    else:
        if time.modalidade == 'Futebol Masculino':
            limite_nao_adventistas_para_frontend = limite_fut_masc_default
        elif time.modalidade == 'Futebol Feminino':
            limite_nao_adventistas_para_frontend = limite_fut_fem_default
        elif time.modalidade == 'Vôlei Misto':
            limite_nao_adventistas_para_frontend = limite_volei_misto_default
        else:
            limite_nao_adventistas_para_frontend = 0

    return render_template('cadastro_jogador.html',
                           time=time,
                           perfil='lider',
                           form_data={},  # form_data é vazio para GET inicial
                           limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                           count_nao_adventistas=count_nao_adventistas_para_frontend)

@app.route('/editar_jogador/<int:jogador_id>', methods=['GET', 'POST'])
@login_required
def editar_jogador(jogador_id):
    jogador = Jogador.query.get_or_404(jogador_id)
    time = jogador.time
    if time.lider_id != current_user.id and not current_user.is_admin:
        abort(403)
    if time.cadastros_encerrados and not current_user.is_admin:
        flash('As edições para este time foram encerrada.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    # Inicializa form_data e variáveis de frontend ANTES do bloco POST
    form_data = {}
    limite_nao_adventistas_para_frontend = 0
    count_nao_adventistas_para_frontend = 0  # Será atualizado abaixo

    # Define os defaults para os limites (caso config não exista ou atributos sejam None)
    limite_fut_masc_default = 1
    limite_fut_fem_default = 2
    limite_volei_misto_default = 1

    if request.method == 'POST':
        form_data = request.form.to_dict()  # Atualiza form_data com os dados do POST
        nome_completo = form_data.get('nome_completo')
        telefone = form_data.get('telefone')
        cpf = form_data.get('cpf')
        rg = form_data.get('rg')
        data_nascimento_str = form_data.get('data_nascimento')
        is_adventista = 'is_adventista' in form_data  # is_adventista do FORM (novo valor)
        is_capitao = 'is_capitao' in form_data
        foto_file = request.files.get('foto')
        foto_identidade_file = request.files.get('foto_identidade')

        # --- Suas validações existentes ---
        if not data_nascimento_str:
            flash('A data de nascimento é obrigatória.', 'danger')
            return render_template('editar_jogador.html',
                                   jogador=jogador, perfil='lider' if not current_user.is_admin else 'admin',
                                   form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        try:
            data_nascimento = datetime.strptime(data_nascimento_str, '%Y-%m-%d').date()
            data_campeonato = date(2025, 8, 2)
            idade = (data_campeonato - data_nascimento).days / 365.25

            if time.modalidade == 'Futebol Masculino':
                IDADE_MINIMA, IDADE_MAXIMA_PADRAO, MAX_EXCECOES = 15, 35, 2
                if idade < IDADE_MINIMA:
                    flash(f'Erro: O jogador precisa ter no mínimo {IDADE_MINIMA} anos.', 'danger')
                    return render_template('editar_jogador.html', jogador=jogador,
                                           perfil='lider' if not current_user.is_admin else 'admin',
                                           form_data=form_data,
                                           limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                           count_nao_adventistas=count_nao_adventistas_para_frontend), 400
                elif idade > IDADE_MAXIMA_PADRAO:
                    jogadores_acima_idade = [p for p in time.jogadores if p.id != jogador.id and p.data_nascimento and (
                            (data_campeonato - p.data_nascimento).days / 365.25) > IDADE_MAXIMA_PADRAO]
                    if len(jogadores_acima_idade) >= MAX_EXCECOES:
                        flash(
                            f'Erro: O time já atingiu o limite de {MAX_EXCECOES} jogadores com mais de {IDADE_MAXIMA_PADRAO} anos.',
                            'danger')
                        return render_template('editar_jogador.html', jogador=jogador,
                                               perfil='lider' if not current_user.is_admin else 'admin',
                                               form_data=form_data,
                                               limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                               count_nao_adventistas=count_nao_adventistas_para_frontend), 400
            elif time.modalidade in ['Futebol Feminino', 'Vôlei Misto']:
                if idade < 15:
                    flash(f'Erro: Para a modalidade "{time.modalidade}", o jogador deve ter no mínimo 15 anos.',
                          'danger')
                    return render_template('editar_jogador.html', jogador=jogador,
                                           perfil='lider' if not current_user.is_admin else 'admin',
                                           form_data=form_data,
                                           limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                           count_nao_adventistas=count_nao_adventistas_para_frontend), 400
        except ValueError:
            flash('Formato de data de nascimento inválido.', 'danger')
            return render_template('editar_jogador.html', jogador=jogador,
                                   perfil='lider' if not current_user.is_admin else 'admin', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        if cpf and cpf.strip():
            if Jogador.query.filter(Jogador.cpf == cpf.strip(), Jogador.id != jogador_id).first():
                flash(f'Erro: O CPF {cpf} já pertence a outro jogador.', 'danger')
                return render_template('editar_jogador.html', jogador=jogador,
                                       perfil='lider' if not current_user.is_admin else 'admin',
                                       form_data=form_data,
                                       limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                       count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        if rg and rg.strip():
            if Jogador.query.filter(Jogador.rg == rg.strip(), Jogador.id != jogador_id).first():
                flash(f'Erro: O RG {rg} já pertence a outro jogador.', 'danger')
                return render_template('editar_jogador.html', jogador=jogador,
                                       perfil='lider' if not current_user.is_admin else 'admin',
                                       form_data=form_data,
                                       limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                       count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        if is_capitao:
            outro_capitao = Jogador.query.filter(Jogador.time_id == time.id, Jogador.is_capitao == True,
                                                 Jogador.id != jogador_id).first()
            if outro_capitao:
                flash(
                    f'O time já possui um capitão ({outro_capitao.nome_completo}). Desmarque o capitão antigo antes de definir um novo.',
                    'danger')
                return render_template('editar_jogador.html', jogador=jogador,
                                       perfil='lider' if not current_user.is_admin else 'admin',
                                       form_data=form_data,
                                       limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                       count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        # --- VALIDAÇÃO: LIMITE DE JOGADORES NÃO ADVENTISTAS NA EDIÇÃO ---
        if not is_adventista:
            config = Configuracao.query.first()
            limite_atual = 0
            config_nao_definida = False

            if config:
                if time.modalidade == 'Futebol Masculino':
                    limite_atual = getattr(config, 'limite_nao_adv_fut_masc', limite_fut_masc_default)
                elif time.modalidade == 'Futebol Feminino':
                    limite_atual = getattr(config, 'limite_nao_adv_fut_fem', limite_fut_fem_default)
                elif time.modalidade == 'Vôlei Misto':
                    limite_atual = getattr(config, 'limite_nao_adv_volei_misto', limite_volei_misto_default)
                else:
                    limite_atual = 0
            else:
                config_nao_definida = True
                if time.modalidade == 'Futebol Masculino':
                    limite_atual = limite_fut_masc_default
                elif time.modalidade == 'Futebol Feminino':
                    limite_atual = limite_fut_fem_default
                elif time.modalidade == 'Vôlei Misto':
                    limite_atual = limite_volei_misto_default
                else:
                    limite_atual = 0

            jogadores_nao_adv_no_time_sem_este = Jogador.query.filter(
                Jogador.time_id == time.id,
                Jogador.is_adventista == False,
                Jogador.id != jogador.id
            ).count()

            if (jogadores_nao_adv_no_time_sem_este + 1 > limite_atual):
                flash(
                    f"Você já cadastrou o limite de {limite_atual} jogador(es) não adventista(s) no time de {time.modalidade}, conforme o boletim informativo. Portanto, não poderá cadastrar/alterar esse jogador.",
                    'danger')
                return render_template('editar_jogador.html',
                                       jogador=jogador, perfil='lider' if not current_user.is_admin else 'admin',
                                       form_data=form_data,
                                       limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                       count_nao_adventistas=count_nao_adventistas_para_frontend), 400

            if config_nao_definida:
                flash(
                    'Aviso: As configurações de limite de jogadores não adventistas não foram definidas pelo administrador. Limites padrão aplicados.',
                    'warning')

        # --- FIM DAS VALIDAÇÕES ---

        # Se todas as validações passarem, processa o upload e salva o jogador
        foto_url, foto_identidade_url = None, None
        try:
            if foto_file and allowed_file(foto_file.filename):
                if jogador.foto:
                    old_path = get_path_from_dropbox_url(jogador.foto)
                    delete_from_dropbox(old_path)
                foto_url = upload_and_get_shared_link(foto_file)
            if foto_identidade_file and allowed_file(foto_identidade_file.filename):
                if jogador.foto_identidade:
                    old_path = get_path_from_dropbox_url(jogador.foto_identidade)
                    delete_from_dropbox(old_path)
                foto_identidade_url = upload_and_get_shared_link(foto_identidade_file)
        except Exception as e:
            # As linhas que adicionamos para o log detalhado
            print("--- OCORREU UM ERRO DETALHADO AO PROCESSAR IMAGEM ---")
            traceback.print_exc()
            print("-----------------------------------------------------")

            # A mensagem de flash original
            flash(f'Erro interno ao processar imagens. Verifique o terminal para detalhes.', 'danger')
            return render_template('editar_jogador.html', jogador=jogador,
                                   perfil='lider' if not current_user.is_admin else 'admin', form_data=form_data,
                                   limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                                   count_nao_adventistas=count_nao_adventistas_para_frontend), 400

        # Atualiza os dados do jogador no banco
        jogador.nome_completo = nome_completo
        jogador.telefone = telefone
        jogador.cpf = cpf
        jogador.rg = rg
        jogador.is_adventista = is_adventista
        jogador.is_capitao = is_capitao
        jogador.data_nascimento = data_nascimento
        if foto_url: jogador.foto = foto_url
        if foto_identidade_url: jogador.foto_identidade = foto_identidade_url

        db.session.commit()
        log_admin_action(
            f"Editou jogador '{jogador.nome_completo}' (ID: {jogador.id}) do time '{time.nome_igreja}' (ID: {time.id})")
        flash('Jogador atualizado com sucesso!', 'success')

        # --- SUBSTITUIÇÃO AQUI: REDIRECIONA PARA A PÁGINA DO TIME ---
        return redirect(url_for('ver_time', time_id=time.id))

    # --- Este bloco é executado APENAS se request.method == 'GET' ---
    # Calcula as variáveis de frontend para a carga inicial da página (GET)
    # form_data é vazio para GET inicial
    form_data = {}  # Garante que form_data é vazio para GET


    config_current = Configuracao.query.first()

    # Atualiza count_nao_adventistas_para_frontend para o GET inicial
    # Exclui o próprio jogador da contagem para a validação frontend
    count_nao_adventistas_para_frontend = Jogador.query.filter(
        Jogador.time_id == time.id,
        Jogador.is_adventista == False,
        Jogador.id != jogador.id
    ).count()

    if jogador.is_adventista == False:  # Se o jogador sendo editado JÁ é não-adventista, ele conta para o frontend
        count_nao_adventistas_para_frontend += 1

    if config_current:
        if time.modalidade == 'Futebol Masculino':
            limite_nao_adventistas_para_frontend = getattr(config_current, 'limite_nao_adv_fut_masc',
                                                           limite_fut_masc_default)
        elif time.modalidade == 'Futebol Feminino':
            limite_nao_adventistas_para_frontend = getattr(config_current, 'limite_nao_adv_fut_fem',
                                                           limite_fut_fem_default)
        elif time.modalidade == 'Vôlei Misto':
            limite_nao_adventistas_para_frontend = getattr(config_current, 'limite_nao_adv_volei_misto',
                                                           limite_volei_misto_default)
        else:
            limite_nao_adventistas_para_frontend = 0
    else:
        if time.modalidade == 'Futebol Masculino':
            limite_nao_adventistas_para_frontend = limite_fut_masc_default
        elif time.modalidade == 'Futebol Feminino':
            limite_nao_adventistas_para_frontend = limite_fut_fem_default
        elif time.modalidade == 'Vôlei Misto':
            limite_nao_adventistas_para_frontend = limite_volei_misto_default
        else:
            limite_nao_adventistas_para_frontend = 0

    return render_template('editar_jogador.html',
                           jogador=jogador,
                           perfil='lider' if not current_user.is_admin else 'admin',
                           form_data=form_data,  # form_data é vazio para GET inicial
                           limite_nao_adventistas=limite_nao_adventistas_para_frontend,
                           count_nao_adventistas=count_nao_adventistas_para_frontend)

@app.route('/admin/config_quadras', methods=['POST'])
@login_required
def config_quadras():
    if not current_user.is_admin:
        abort(403)
    config = Configuracao.query.first()
    if not config:
        config = Configuracao()
        db.session.add(config)
    config.num_quadras_fut_masc = int(request.form.get('num_quadras_fut_masc', 0))
    config.num_quadras_fut_fem = int(request.form.get('num_quadras_fut_fem', 0))
    config.num_quadras_volei_misto = int(request.form.get('num_quadras_volei_misto', 0))
    db.session.commit()
    log_auditoria(f"Atualizou número de quadras no BD: FutMasc={config.num_quadras_fut_masc}, FutFem={config.num_quadras_fut_fem}, Volei={config.num_quadras_volei_misto}")
    flash('Número de quadras atualizado com sucesso!', 'success')
    return redirect(url_for('admin_master'))

@app.route('/admin/gerar_tudo_automatico', methods=['POST'])
@login_required
def gerar_tudo_automatico_handler():
    if not current_user.is_admin:
        abort(403)

    config = Configuracao.query.first()
    if not config:
        flash("É necessário salvar a configuração de quadras primeiro.", "danger")
        return redirect(url_for('admin_master'))

    # Encontra todas as modalidades que têm times
    modalidades_com_times = db.session.query(Time.modalidade).distinct().all()
    modalidades = [m[0] for m in modalidades_com_times]

    if not modalidades:
        flash("Não há times cadastrados para gerar um torneio.", "warning")
        return redirect(url_for('admin_master'))

    # Loop para gerar o torneio para cada modalidade encontrada
    for modalidade in modalidades:
        num_quadras = 0
        if modalidade == 'Futebol Masculino':
            num_quadras = config.num_quadras_fut_masc
        elif modalidade == 'Vôlei Misto':
            num_quadras = config.num_quadras_volei_misto
        # Adicione outras modalidades aqui se necessário

        if num_quadras > 0:
            print(f"Gerando torneio automático para {modalidade}...")
            gerar_grupos_e_jogos_automaticamente(modalidade, num_quadras)
        else:
            flash(f"Aviso: O torneio para '{modalidade}' não foi gerado porque o número de quadras é 0.", "warning")

    flash("Sorteio rápido executado para todas as modalidades ativas!", "success")
    return redirect(url_for('ver_chaveamento_admin'))

@app.route('/time/<int:time_id>')
@login_required
def ver_time(time_id):
    time = db.session.get(Time, time_id)
    if not time:
        abort(404)
    if not current_user.is_admin and time.lider_id != current_user.id:
        abort(403)

    return render_template('ver_time.html', time=time, perfil='admin' if current_user.is_admin else 'lider',
                           now=datetime.now(timezone.utc))

@app.route('/editar_time/<token>', methods=['GET', 'POST'])
@login_required
def editar_time(token):
    time = Time.query.filter_by(token=token).first_or_404()
    if time.lider_id != current_user.id and not current_user.is_admin:
        abort(403)

    if time.cadastros_encerrados and not current_user.is_admin:
        flash('As edições para este time foram encerradas.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if request.method == 'POST':
        # --- 1. ATUALIZA OS DADOS DE TEXTO PRIMEIRO ---
        time.nome_igreja = request.form.get('nome_igreja')
        time.distrito = request.form.get('distrito')
        time.regiao = request.form.get('regiao')
        time.nome_base = request.form.get('nome_base')
        time.modalidade = request.form.get('modalidade')
        time.pagou = 'pagou' in request.form
        time.diretor_jovem = request.form.get('diretor_jovem')
        time.link_pagamento = LINK_PAGAMENTO_PADRAO

        # --- 2. LÓGICA DE UPLOAD REFINADA ---

        # Lógica para o Comprovante de Pagamento
        comprovante_file = request.files.get('comprovante_pagamento')
        if comprovante_file and comprovante_file.filename: # Garante que um arquivo foi selecionado
            if allowed_file(comprovante_file.filename):
                try:
                    if time.comprovante_pagamento:
                        old_path = get_path_from_dropbox_url(time.comprovante_pagamento)
                        delete_from_dropbox(old_path)
                    time.comprovante_pagamento = upload_and_get_shared_link(comprovante_file)
                except Exception as e:
                    flash(f'Erro ao atualizar o comprovante: {e}', 'danger')
                    return redirect(url_for('editar_time', token=token))
            else:
                flash('Formato de comprovante inválido. Use PNG, JPG, JPEG, GIF ou PDF.', 'danger')
                return redirect(url_for('editar_time', token=token))

        # Lógica para a Imagem do Time
        imagem_file = request.files.get('imagem')
        if imagem_file and imagem_file.filename: # Garante que um arquivo foi selecionado
            if allowed_file(imagem_file.filename):
                try:
                    if time.imagem:
                        old_path = get_path_from_dropbox_url(time.imagem)
                        delete_from_dropbox(old_path)
                    time.imagem = upload_and_get_shared_link(imagem_file)
                except Exception as e:
                    flash(f'Erro ao atualizar a imagem: {e}', 'danger')
                    return redirect(url_for('editar_time', token=token))
            else:
                flash('Formato de imagem inválido. Use PNG, JPG, JPEG ou GIF.', 'danger')
                return redirect(url_for('editar_time', token=token))

        # --- 3. SALVA TODAS AS ALTERAÇÕES NO BANCO DE DADOS ---
        db.session.commit()
        log_admin_action(f"Editou time: '{time.nome_igreja}'")
        flash('Time atualizado com sucesso.', 'success')
        return redirect(url_for('ver_time', time_id=time.id))

    # Para requisições GET, apenas renderiza o formulário
    return render_template('editar_time.html',
                           time=time,
                           regiao_opcoes=REGIAO_OPCOES,
                           LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO,
                           perfil='lider')

@app.route('/excluir_jogador/<int:jogador_id>', methods=['POST'])
@login_required
def excluir_jogador(jogador_id):
    jogador = Jogador.query.get_or_404(jogador_id)
    time = jogador.time
    if time.lider_id != current_user.id and not current_user.is_admin:
        abort(403)

    if time.cadastros_encerrados and not current_user.is_admin:
        flash('As edições para este time foram encerrada.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    # Apaga a foto do jogador do Cloudinary, se existir
    if jogador.foto:
        file_path = get_path_from_dropbox_url(jogador.foto)
        delete_from_dropbox(file_path)
        log_auditoria(f"Excluiu do Dropbox (foto jogador): {file_path}")

    # Apaga a foto da identidade do Cloudinary, se existir
    if jogador.foto_identidade:
        file_path = get_path_from_dropbox_url(jogador.foto_identidade)
        delete_from_dropbox(file_path)
        log_auditoria(f"Excluiu do Dropbox (identidade): {file_path}")

    db.session.delete(jogador)
    db.session.commit()
    log_admin_action(
        f"Excluiu jogador '{jogador.nome_completo}' (ID: {jogador.id}) do time '{time.nome_igreja}' (ID: {time.id})")
    flash('Jogador excluído com sucesso.', 'success')
    return redirect(url_for('ver_time', time_id=time.id))

@app.route('/excluir_time/<int:time_id>', methods=['POST'])
@login_required
def excluir_time(time_id):
    time = Time.query.get_or_404(time_id)

    # Esta é a VERIFICAÇÃO DE PERMISSÃO.
    # Se o usuário NÃO É admin E NÃO É o líder do time, ele ABORTA com 403.
    # Caso contrário, o código continua.
    if not current_user.is_admin and time.lider_id != current_user.id:
        abort(403)

    # TODO O CÓDIGO ABAIXO DEVE ESTAR AQUI (com este recuo),
    # ou seja, 4 espaços à direita do 'def', não 8 ou mais.

    # Apaga a imagem/logo do time do Cloudinary
    if time.imagem:
        file_path = get_path_from_dropbox_url(time.imagem)
        delete_from_dropbox(file_path)
        log_auditoria(f"Excluiu do Dropbox (logo time): {file_path}")

    # Apaga o comprovante de pagamento do Cloudinary
    if time.comprovante_pagamento:
        # CORREÇÃO: o nome da variável estava 'comprovante_pagante' no seu código original
        file_path = get_path_from_dropbox_url(time.comprovante_pagamento)
        delete_from_dropbox(file_path)
        log_auditoria(f"Excluiu do Dropbox (comprovante): {file_path}")

    # Itera sobre todos os jogadores do time e apaga suas imagens também
    for jogador in time.jogadores:
        if jogador.foto:
            file_path = get_path_from_dropbox_url(jogador.foto)
            delete_from_dropbox(file_path)
            log_auditoria(f"Excluiu do Dropbox (foto jogador): {file_path}")

        if jogador.foto_identidade:
            file_path = get_path_from_dropbox_url(jogador.foto_identidade)
            delete_from_dropbox(file_path)
            log_auditoria(f"Excluiu do Dropbox (identidade): {file_path}")

    # Deleta os jogos associados ao time
    Game.query.filter(
        (Game.time_a_id == time.id) |
        (Game.time_b_id == time.id) |
        (Game.vencedor_id == time.id)
    ).delete(synchronize_session=False)

    # Deleta o próprio time
    db.session.delete(time)
    db.session.commit() # Salva todas as alterações no banco de dados
    log_admin_action(f"Excluiu time: '{time.nome_igreja}' (ID: {time.id})")
    flash('Time excluído com sucesso.', 'success')
    return redirect(url_for('index'))

# --- Rotas e Lógica para Admin Master ---

@app.route('/admin_master')
@login_required
def admin_master():
    if not current_user.is_admin:
        return redirect(url_for('index'))

    config = Configuracao.query.first()
    if not config:
        config = Configuracao()
        db.session.add(config)
        db.session.commit()

    times_validos = Time.query.order_by(Time.modalidade, Time.nome_igreja).all()

    torneio_gerado = db.session.query(Game.id).first() is not None

    # --- LÓGICA DE VALIDAÇÃO INTELIGENTE ---
    # Verifica se existem times para cada modalidade
    tem_times_masc = Time.query.filter_by(modalidade='Futebol Masculino', pagou=True).first() is not None
    tem_times_fem = Time.query.filter_by(modalidade='Futebol Feminino', pagou=True).first() is not None
    tem_times_volei = Time.query.filter_by(modalidade='Vôlei Misto', pagou=True).first() is not None

    # Constrói a lista de condições dinamicamente
    condicoes = []
    if tem_times_masc:
        condicoes.append(config.num_quadras_fut_masc > 0)
    if tem_times_fem:
        condicoes.append(config.num_quadras_fut_fem > 0)
    if tem_times_volei:
        condicoes.append(config.num_quadras_volei_misto > 0)

    # O botão só será habilitado se todas as modalidades COM times tiverem quadras configuradas.
    # Se uma modalidade não tem times, o número de quadras dela é ignorado.
    quadras_configuradas = all(condicoes) if condicoes else False

    return render_template('admin_master.html',
                           times=times_validos,
                           config=config,
                           torneio_gerado=torneio_gerado,
                           quadras_configuradas=quadras_configuradas)

# Adicionar em app.py
@app.route('/admin/config_limites', methods=['POST'])
@login_required
def config_limites():
    if not current_user.is_admin:
        abort(403)
    config = Configuracao.query.first()
    if not config:
        config = Configuracao()
        db.session.add(config)

    config.limite_nao_adv_fut_masc = int(request.form.get('limite_nao_adv_fut_masc', 1))
    config.limite_nao_adv_fut_fem = int(request.form.get('limite_nao_adv_fut_fem', 2))
    config.limite_nao_adv_volei_misto = int(request.form.get('limite_nao_adv_volei_misto', 1))

    db.session.commit()
    flash('Limites de jogadores não adventistas atualizados!', 'success')
    return redirect(url_for('admin_master'))

@app.route('/admin/config_time/<int:time_id>', methods=['GET', 'POST'])
@login_required
def admin_config_time(time_id):
    if not current_user.is_admin:
        abort(403)

    time = Time.query.get_or_404(time_id)

    if request.method == 'POST':
        time.cadastros_encerrados = 'cadastros_encerrados' in request.form

        try:
            limite = int(request.form.get('limite_nao_adventistas', 0))
            if limite < 0:
                flash('O limite não pode ser um número negativo.', 'danger')
            else:
                time.limite_nao_adventistas = limite
                db.session.commit()
                log_admin_action(
                    f"Configurou o time '{time.nome_igreja}': Encerrado={time.cadastros_encerrados}, Limite Não Adventistas={time.limite_nao_adventistas}")
                flash(f'Configurações do time "{time.nome_igreja}" salvas com sucesso!', 'success')
                return redirect(url_for('admin_master'))
        except ValueError:
            flash('O limite de jogadores não adventistas deve ser um número inteiro.', 'danger')

    return render_template('admin_config_time.html', time=time)


@app.route('/admin/toggle_cadastros_globais', methods=['POST'])
@login_required
def toggle_cadastros_globais():
    if not current_user.is_admin:
        abort(403)

    all_times_closed = all(t.cadastros_encerrados for t in Time.query.all())
    new_status = not all_times_closed

    for time in Time.query.all():
        time.cadastros_encerrados = new_status

    db.session.commit()
    log_admin_action(f"Alterou status de cadastros globais para {'Encerrados' if new_status else 'Abertos'}.")
    flash(f'Status de cadastros globais alterado para {"Encerrados" if new_status else "Abertos"}.', 'success')
    return redirect(url_for('admin_master'))


@app.route('/admin/relatorio_excel')
@login_required
def relatorio_excel():
    if not current_user.is_admin:
        abort(403)

    try:
        output = io.BytesIO()
        writer = pd.ExcelWriter(output, engine='xlsxwriter')

        # --- ABA 1: Times (sem alteração) ---
        times_query = Time.query.order_by(Time.nome_igreja).all()
        dados_times = [{
            'ID do Time': time.id,
            'Nome da Igreja': time.nome_igreja,
            'Diretor Jovem': time.diretor_jovem,
            'Distrito': time.distrito,
            'Região': time.regiao,
            'Nome da Base': time.nome_base,
            'Modalidade': time.modalidade,
            'Pagamento Confirmado': 'Sim' if time.pagou else 'Não',
            'Comprovante (Link)': time.comprovante_pagamento or 'N/A',
            'Cadastro Encerrado': 'Sim' if time.cadastros_encerrados else 'Não'
        } for time in times_query]
        df_times = pd.DataFrame(dados_times)
        df_times.to_excel(writer, sheet_name='Times Cadastrados', index=False)

        # --- ABA 2: Jogadores (COM AS NOVAS COLUNAS) ---
        jogadores_query = db.session.query(Jogador).join(Time).order_by(Time.modalidade, Time.nome_igreja,
                                                                        Jogador.nome_completo).all()
        dados_jogadores = []
        for jogador in jogadores_query:
            dados_jogadores.append({
                # Colunas que já existiam (mantidas)
                'Nome do Jogador': jogador.nome_completo,
                'Telefone': jogador.telefone,
                'CPF': jogador.cpf,
                'RG': jogador.rg,
                'Data de Nascimento': jogador.data_nascimento.strftime('%d/%m/%Y') if jogador.data_nascimento else '',
                'É Adventista?': 'Sim' if jogador.is_adventista else 'Não',
                'É Capitão?': 'Sim' if jogador.is_capitao else 'Não',

                # --- COLUNAS ACRESCENTADAS ---
                'Modalidade': jogador.time.modalidade,
                'Nome da Base/Time': jogador.time.nome_base or jogador.time.nome_igreja,
                'Nome da Igreja': jogador.time.nome_igreja,
                'Distrito': jogador.time.distrito,
                # -----------------------------

                # Colunas que já existiam (mantidas)
                'Foto do Jogador (Link)': jogador.foto or 'N/A',
                'Foto da Identidade (Link)': jogador.foto_identidade or 'N/A'
            })

        df_jogadores = pd.DataFrame(dados_jogadores)
        df_jogadores.to_excel(writer, sheet_name='Jogadores Inscritos', index=False)

        writer.close()
        output.seek(0)
        log_auditoria("Gerou relatório Excel com abas de Times e Jogadores.")
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name='relatorio_campeonato_oneday.xlsx',
            as_attachment=True
        )

    except Exception as e:
        log_auditoria(f"Falha ao gerar relatório Excel: {e}")
        flash(f'Ocorreu um erro ao gerar o relatório: {e}', 'danger')
        return redirect(url_for('admin_master'))


def gerar_jogos_para_grupos_prontos(modalidade, num_quadras):
    """
    Esta função é chamada DEPOIS que os grupos são montados manualmente.
    Ela apenas pega os grupos existentes e gera a tabela de jogos.
    """
    grupos = Grupo.query.filter_by(modalidade=modalidade).all()

    jogos_por_grupo = {grupo.id: [] for grupo in grupos}
    for grupo in grupos:
        times_no_grupo = Time.query.filter_by(grupo_id=grupo.id).all()
        confrontos_do_grupo = list(combinations(times_no_grupo, 2))
        random.shuffle(confrontos_do_grupo)
        jogos_por_grupo[grupo.id] = confrontos_do_grupo

    todos_os_confrontos_intercalados = []
    max_jogos_por_grupo = max(len(jogos) for jogos in jogos_por_grupo.values()) if jogos_por_grupo else 0
    for i in range(max_jogos_por_grupo):
        for grupo_id in jogos_por_grupo:
            if i < len(jogos_por_grupo[grupo_id]):
                todos_os_confrontos_intercalados.append(jogos_por_grupo[grupo_id][i])

    # PARA (Nova versão usando as constantes)
    horario_inicial = datetime.now().replace(hour=HORA_INICIO_JOGOS, minute=MINUTO_INICIO_JOGOS, second=0,
                                             microsecond=0)

    if 'Futebol' in modalidade:
        duracao_jogo_min = INTERVALO_JOGOS_FUTEBOL_MINUTOS
        proximo_horario_quadra = {i: horario_inicial for i in range(1, num_quadras + 1)}
        for i, (time_a, time_b) in enumerate(todos_os_confrontos_intercalados):
            quadra_agendamento = min(proximo_horario_quadra, key=proximo_horario_quadra.get)
            horario_agendamento = proximo_horario_quadra[quadra_agendamento]
            jogo = Game(time_a_id=time_a.id, time_b_id=time_b.id, modalidade=modalidade, fase="Fase de Grupos",
                        ordem_na_fase=i + 1, local=f"Quadra {quadra_agendamento}", data_hora=horario_agendamento)
            db.session.add(jogo)
            proximo_horario_quadra[quadra_agendamento] += timedelta(minutes=duracao_jogo_min)
    else:  # Vôlei
        # --- LÓGICA DE SORTEIO DE QUADRAS INICIAIS ---
        # 1. Cria uma lista com os nomes das quadras
        quadras_iniciais = [f"Quadra {q + 1}" for q in range(num_quadras)]
        # 2. Embaralha a lista de quadras
        random.shuffle(quadras_iniciais)

        for i, (time_a, time_b) in enumerate(todos_os_confrontos_intercalados):
            jogo = Game(time_a_id=time_a.id, time_b_id=time_b.id, modalidade=modalidade, fase="Fase de Grupos",
                        ordem_na_fase=i + 1)
            # Para os primeiros jogos, usa a lista de quadras embaralhada
            if i < num_quadras:
                jogo.local = quadras_iniciais[i]  # <-- Atribuição aleatória
                jogo.data_hora = horario_inicial
            else:
                jogo.local = "Na Fila"
            db.session.add(jogo)

    db.session.commit()
    log_auditoria(f"Jogos gerados para grupos manuais de {modalidade}.")


# Adicione estas duas novas rotas em app.py

@app.route('/admin/escolher_metodo/<modalidade>')
@login_required
def escolher_metodo_geracao(modalidade):
    if not current_user.is_admin:
        abort(403)
    return render_template('admin_escolher_metodo.html', modalidade=modalidade)


@app.route('/admin/gerar_automatico/<modalidade>', methods=['POST'])
@login_required
def gerar_automatico_handler(modalidade):
    if not current_user.is_admin:
        abort(403)

    config = Configuracao.query.first()
    num_quadras = 0
    if modalidade == 'Futebol Masculino':
        num_quadras = config.num_quadras_fut_masc
    elif modalidade == 'Vôlei Misto':
        num_quadras = config.num_quadras_volei_misto

    if num_quadras > 0:
        gerar_grupos_e_jogos_automaticamente(modalidade, num_quadras)
        flash(f"Grupos para {modalidade} gerados automaticamente com sucesso!", "success")
    else:
        flash(f"Configure o número de quadras para {modalidade} antes de gerar o torneio.", "danger")

    return redirect(url_for('ver_chaveamento_admin'))

@app.route('/admin/escolher_modalidade_grupos')
@login_required
def escolher_modalidade_grupos():
    if not current_user.is_admin:
        abort(403)

    modalidades_com_times = db.session.query(Time.modalidade).distinct().all()
    modalidades = [m[0] for m in modalidades_com_times]

    # --- ADICIONE ESTA LINHA DE TESTE AQUI ---
    print(f"DEBUG: Modalidades encontradas no banco: {modalidades}")
    # -----------------------------------------

    return render_template('admin_escolher_modalidade.html', modalidades=modalidades)

def gerar_grupos_e_jogos_automaticamente(modalidade, num_quadras):
    """
    FUNÇÃO PARA SORTEIO AUTOMÁTICO:
    Sorteia os times em grupos de forma aleatória e depois gera os jogos.
    """
    # Limpa dados antigos da modalidade para garantir um começo limpo
    Game.query.filter_by(modalidade=modalidade).delete()
    # Encontra e deleta classificações e grupos antigos da modalidade
    grupos_antigos = Grupo.query.filter_by(modalidade=modalidade).all()
    for grupo in grupos_antigos:
        Classificacao.query.filter_by(grupo_id=grupo.id).delete()
        db.session.delete(grupo)
    db.session.commit()

    # Esta função agora contém toda a lógica de geração automática que já construímos
    times_da_modalidade = Time.query.filter_by(modalidade=modalidade, pagou=True).all()
    num_times = len(times_da_modalidade)

    if num_times < 3:
        flash(f'Erro para {modalidade}: São necessários pelo menos 3 times.', 'danger')
        return

    # Lógica para definir o número de grupos
    if num_times >= 15:
        num_grupos = 4
    elif 12 <= num_times <= 14:
        num_grupos = 3
    else:
        num_grupos = math.ceil(num_times / 4.0)

    print(f"Gerando {int(num_grupos)} grupos automaticamente para {modalidade}...")
    random.shuffle(times_da_modalidade)

    grupos_criados = []
    for i in range(int(num_grupos)):
        grupo = Grupo(nome=f"Grupo {chr(65 + i)}", modalidade=modalidade)
        db.session.add(grupo)
        grupos_criados.append(grupo)
    db.session.commit()

    for i, time in enumerate(times_da_modalidade):
        grupo_destino = grupos_criados[i % int(num_grupos)]
        time.grupo_id = grupo_destino.id
        classificacao = Classificacao(time_id=time.id, grupo_id=grupo_destino.id)
        db.session.add(classificacao)
    db.session.commit()

    # Após os grupos serem criados e populados, gera os jogos
    gerar_jogos_para_grupos_prontos(modalidade, num_quadras)
    log_auditoria(f"Grupos e jogos para {modalidade} gerados automaticamente.")

def gerar_fase_mata_mata(modalidade):
    # Trava de segurança para evitar duplicatas (sem alteração)
    jogos_mata_mata_existentes = Game.query.filter(
        Game.modalidade == modalidade,
        Game.fase.in_(['Quartas de Final', 'Semifinal', 'Final'])
    ).first()
    if jogos_mata_mata_existentes:
        print(f"Mata-mata para {modalidade} já existe. Geração pulada.")
        return

    print(f"Iniciando geração do mata-mata para {modalidade}...")
    grupos = Grupo.query.filter_by(modalidade=modalidade).order_by(Grupo.nome).all()

    classificados = []
    terceiros_lugares = []

    for grupo in grupos:
        ranking_grupo = sorted(
            grupo.classificacao,
            key=lambda c: (c.pontos, c.saldo_gols, c.gols_pro),
            reverse=True
        )
        classificados.extend(ranking_grupo[:2])
        if len(ranking_grupo) > 2:
            terceiros_lugares.append(ranking_grupo[2])

    if len(grupos) == 3 and len(classificados) == 6 and len(terceiros_lugares) > 0:
        print("Detectados 3 grupos. Normalizando e classificando os 2 melhores 3ºs lugares...")

        # --- LÓGICA DE NORMALIZAÇÃO CORRIGIDA ---
        dados_para_ordenacao = []
        for terceiro in terceiros_lugares:
            pontos_finais = terceiro.pontos
            saldo_finais = terceiro.saldo_gols
            gols_pro_finais = terceiro.gols_pro

            tamanho_grupo = len(terceiro.grupo.times)
            if tamanho_grupo > 4:  # Lógica de normalização para qualquer grupo maior que 4
                ranking_do_grupo = sorted(terceiro.grupo.classificacao,
                                          key=lambda c: (c.pontos, c.saldo_gols, c.gols_pro), reverse=True)
                ultimo_colocado = ranking_do_grupo[-1]

                jogo_a_descartar = Game.query.filter(
                    ((Game.time_a_id == terceiro.time_id) & (Game.time_b_id == ultimo_colocado.time_id)) |
                    ((Game.time_b_id == terceiro.time_id) & (Game.time_a_id == ultimo_colocado.time_id))
                ).first()

                if jogo_a_descartar and jogo_a_descartar.finalizado:
                    if jogo_a_descartar.vencedor_id == terceiro.time_id:
                        pontos_finais -= 3
                    elif jogo_a_descartar.vencedor_id is None:
                        pontos_finais -= 1

                    placar_terceiro = jogo_a_descartar.gols_time_a if jogo_a_descartar.time_a_id == terceiro.time_id else jogo_a_descartar.gols_time_b
                    placar_ultimo = jogo_a_descartar.gols_time_b if jogo_a_descartar.time_a_id == terceiro.time_id else jogo_a_descartar.gols_time_a

                    gols_pro_finais -= placar_terceiro or 0
                    saldo_finais -= (placar_terceiro or 0) - (placar_ultimo or 0)

            # Guarda o objeto original e sua chave de ordenação (normalizada ou não)
            dados_para_ordenacao.append({
                'objeto_classificacao': terceiro,
                'chave_ordenacao': (pontos_finais, saldo_finais, gols_pro_finais)
            })

        # Ordena a lista usando a chave de ordenação calculada
        ordenados = sorted(dados_para_ordenacao, key=lambda x: x['chave_ordenacao'], reverse=True)

        # Pega os 2 melhores objetos de classificação originais
        melhores_terceiros = [item['objeto_classificacao'] for item in ordenados[:2]]
        classificados.extend(melhores_terceiros)

    if len(classificados) != 8:
        flash(f"Não foi possível gerar as Quartas de Final. Número de classificados ({len(classificados)}) é inválido.",
              "danger")
        return

    # O resto da função para criar os jogos continua o mesmo
    ranking_geral = sorted(classificados, key=lambda c: (c.pontos, c.saldo_gols, c.gols_pro), reverse=True)
    confrontos_quartas = [(ranking_geral[0].time, ranking_geral[7].time),
                          (ranking_geral[3].time, ranking_geral[4].time),
                          (ranking_geral[2].time, ranking_geral[5].time),
                          (ranking_geral[1].time, ranking_geral[6].time)]
    final = Game(modalidade=modalidade, fase="Final", ordem_na_fase=1);
    disputa_terceiro = Game(modalidade=modalidade, fase="Disputa 3º Lugar", ordem_na_fase=1)
    db.session.add_all([final, disputa_terceiro]);
    db.session.commit()
    semi1 = Game(modalidade=modalidade, fase="Semifinal", ordem_na_fase=1, proximo_jogo_id=final.id);
    semi2 = Game(modalidade=modalidade, fase="Semifinal", ordem_na_fase=2, proximo_jogo_id=final.id)
    db.session.add_all([semi1, semi2]);
    db.session.commit()
    quartas1 = Game(time_a=confrontos_quartas[0][0], time_b=confrontos_quartas[0][1], modalidade=modalidade,
                    fase="Quartas de Final", ordem_na_fase=1, proximo_jogo_id=semi1.id)
    quartas2 = Game(time_a=confrontos_quartas[1][0], time_b=confrontos_quartas[1][1], modalidade=modalidade,
                    fase="Quartas de Final", ordem_na_fase=2, proximo_jogo_id=semi1.id)
    quartas3 = Game(time_a=confrontos_quartas[2][0], time_b=confrontos_quartas[2][1], modalidade=modalidade,
                    fase="Quartas de Final", ordem_na_fase=3, proximo_jogo_id=semi2.id)
    quartas4 = Game(time_a=confrontos_quartas[3][0], time_b=confrontos_quartas[3][1], modalidade=modalidade,
                    fase="Quartas de Final", ordem_na_fase=4, proximo_jogo_id=semi2.id)
    db.session.add_all([quartas1, quartas2, quartas3, quartas4]);
    db.session.commit()
    log_auditoria(f"Fase de Mata-Mata (Classificação Geral) gerada para {modalidade}.")

def atualizar_classificacao_e_avancar_time(game):
    if game is None or not game.time_a or not game.time_b: return

    vencedor, perdedor, empate = None, None, False
    placar_a = int(game.gols_time_a or 0)
    placar_b = int(game.gols_time_b or 0)

    # Lógica para determinar vencedor (incluindo pênaltis)
    if placar_a > placar_b:
        vencedor, perdedor = game.time_a, game.time_b
    elif placar_b > placar_a:
        vencedor, perdedor = game.time_b, game.time_a
    else:
        if 'Futebol' in game.modalidade and game.fase != 'Fase de Grupos':
            if game.pontos_sets:
                try:
                    dados_penaltis = json.loads(game.pontos_sets)
                    penaltis_a = dados_penaltis.get('penaltis_a', 0)
                    penaltis_b = dados_penaltis.get('penaltis_b', 0)
                    if penaltis_a > penaltis_b:
                        vencedor, perdedor = game.time_a, game.time_b
                    elif penaltis_b > penaltis_a:
                        vencedor, perdedor = game.time_b, game.time_a
                except (json.JSONDecodeError, TypeError):
                    pass
        elif 'Futebol' in game.modalidade:
            empate = True

    if 'Vôlei' in game.modalidade and game.fase not in ['Fase de Grupos', 'Quartas de Final']:
        sets_a = int(game.sets_vencidos_a or 0);
        sets_b = int(game.sets_vencidos_b or 0)
        if sets_a > sets_b:
            vencedor, perdedor = game.time_a, game.time_b
        else:
            vencedor, perdedor = game.time_b, game.time_a

    game.vencedor_id = vencedor.id if vencedor else None

    # Lógica para avançar vencedor (sem alteração)
    if vencedor and game.proximo_jogo_id:
        proximo_jogo = Game.query.get(game.proximo_jogo_id)
        if proximo_jogo:
            if proximo_jogo.time_a_id is None:
                proximo_jogo.time_a_id = vencedor.id
            else:
                proximo_jogo.time_b_id = vencedor.id

    # Lógica para perdedores da semifinal (sem alteração)
    if perdedor and game.fase == "Semifinal":
        disputa_terceiro = Game.query.filter_by(modalidade=game.modalidade, fase="Disputa 3º Lugar").first()
        if disputa_terceiro:
            if disputa_terceiro.time_a_id is None:
                disputa_terceiro.time_a_id = perdedor.id
            else:
                disputa_terceiro.time_b_id = perdedor.id

    # Lógica de classificação na fase de grupos (sem alteração)
    if game.fase == "Fase de Grupos":
        class_a = Classificacao.query.filter_by(time_id=game.time_a_id).first()
        class_b = Classificacao.query.filter_by(time_id=game.time_b_id).first()
        if class_a and class_b:
            class_a.jogos_disputados += 1;
            class_b.jogos_disputados += 1
            class_a.gols_pro += placar_a;
            class_a.gols_contra += placar_b
            class_b.gols_pro += placar_b;
            class_b.gols_contra += placar_a
            if empate:
                class_a.empates += 1; class_b.empates += 1
            elif vencedor == game.time_a:
                class_a.vitorias += 1; class_b.derrotas += 1
            elif vencedor == game.time_b:
                class_b.vitorias += 1; class_a.derrotas += 1

    # Lógica da fila dinâmica (sem alteração)
    quadra_liberada = game.local
    if quadra_liberada and "Quadra" in quadra_liberada:
        proximo_jogo_na_fila = Game.query.filter_by(modalidade=game.modalidade, local="Na Fila").order_by(
            Game.ordem_na_fase).first()
        if proximo_jogo_na_fila:
            proximo_jogo_na_fila.local = quadra_liberada
            proximo_jogo_na_fila.data_hora = datetime.now() + timedelta(minutes=2)

    # --- BLOCO CORRIGIDO ---
    # Verifica se a fase de grupos terminou para gerar o mata-mata
    if game.fase == "Fase de Grupos":
        jogos_pendentes = Game.query.filter(
            Game.modalidade == game.modalidade,
            Game.fase == "Fase de Grupos",  # <-- CORRIGIDO
            Game.finalizado == False  # <-- CORRIGIDO
        ).count()
        if jogos_pendentes == 0:
            print(f"Fase de grupos da {game.modalidade} finalizada. Gerando mata-mata...")
            gerar_fase_mata_mata(game.modalidade)

    db.session.commit()
    log_auditoria(f"Jogo {game.id} ({game.time_a.nome_igreja} vs {game.time_b.nome_igreja}) finalizado.")


# Em app.py
@app.route('/admin/chaveamento')
@login_required
def ver_chaveamento_admin():
    if not current_user.is_admin:
        abort(403)

    # Dicionários para guardar os jogos organizados
    jogos_organizados = {
        'Futebol Masculino': {},
        'Futebol Feminino': {},
        'Vôlei Misto': {}
    }

    # --- NOVA LÓGICA DE ORDENAÇÃO ---
    # 1. Define a ordem correta de exibição
    ordem_exibicao = ["Grupo A", "Grupo B", "Grupo C", "Grupo D", "Quartas de Final", "Semifinal", "Disputa 3º Lugar",
                      "Final"]

    todos_os_jogos = Game.query.options(
        db.joinedload(Game.time_a).joinedload(Time.grupo),
        db.joinedload(Game.time_b)
    ).order_by(Game.ordem_na_fase).all()

    # 2. Organiza os jogos em um dicionário
    for jogo in todos_os_jogos:
        chave = jogo.time_a.grupo.nome if jogo.fase == "Fase de Grupos" and jogo.time_a and jogo.time_a.grupo else jogo.fase
        if chave not in jogos_organizados[jogo.modalidade]:
            jogos_organizados[jogo.modalidade][chave] = []
        jogos_organizados[jogo.modalidade][chave].append(jogo)

    # 3. Cria uma lista ordenada de chaves para cada modalidade
    chaves_ordenadas = {}
    for modalidade, grupos_e_fases in jogos_organizados.items():
        chaves_ordenadas[modalidade] = [chave for chave in ordem_exibicao if chave in grupos_e_fases]

    return render_template('chaveamento_admin.html',
                           jogos_organizados=jogos_organizados,
                           chaves_ordenadas=chaves_ordenadas)

@app.route('/admin/montar_grupos/<modalidade>')
@login_required
def montar_grupos_admin(modalidade):
    if not current_user.is_admin:
        abort(403)

    # --- LÓGICA DE LIMPEZA ADICIONADA AQUI ---
    # Garante que, ao entrar na montagem manual, o torneio antigo da modalidade seja apagado.
    print(f"Limpando torneio antigo para {modalidade} antes de montar novos grupos...")
    Game.query.filter_by(modalidade=modalidade).delete()
    grupos_antigos = Grupo.query.filter_by(modalidade=modalidade).all()
    for g in grupos_antigos:
        Classificacao.query.filter_by(grupo_id=g.id).delete()
        db.session.delete(g)
    db.session.commit()
    # --- FIM DA LÓGICA DE LIMPEZA ---

    times = Time.query.filter_by(modalidade=modalidade, pagou=True).all()
    num_times = len(times)

    if num_times < 3:
        flash(f"Não há times suficientes em {modalidade} para formar grupos.", "warning")
        return redirect(url_for('admin_master'))

    # Lógica para definir o número de grupos (a mesma que já temos)
    if num_times >= 15:
        num_grupos = 4
    elif 12 <= num_times <= 14:
        num_grupos = 3
    elif 9 <= num_times <= 11:
        num_grupos = 3
    elif 6 <= num_times <= 8:
        num_grupos = 2
    else:
        num_grupos = 1

    # Cria os grupos vazios
    grupos_criados = []
    for i in range(num_grupos):
        grupo = Grupo(nome=f"Grupo {chr(65 + i)}", modalidade=modalidade)
        db.session.add(grupo)
        grupos_criados.append(grupo)
    db.session.commit()

    return render_template('admin_montar_grupos.html',
                           modalidade=modalidade,
                           times=times,
                           times_sem_grupo=times,
                           grupos=grupos_criados)


@app.route('/api/salvar_grupos', methods=['POST'])
@login_required
def salvar_grupos_manualmente():
    if not current_user.is_admin:
        return jsonify(success=False, message="Acesso negado"), 403

    data = request.json
    modalidade = data.get('modalidade')
    grupos_data = data.get('grupos')

    try:
        for grupo_id, time_ids in grupos_data.items():
            for time_id in time_ids:
                time = Time.query.get(time_id)
                if time:
                    time.grupo_id = grupo_id
                    # Cria a entrada na tabela de classificação
                    if not Classificacao.query.filter_by(time_id=time_id).first():
                        classificacao = Classificacao(time_id=time_id, grupo_id=grupo_id)
                        db.session.add(classificacao)
        db.session.commit()

        # Agora, chama a função para gerar os jogos com os grupos já montados
        config = Configuracao.query.first()
        num_quadras = 0
        if modalidade == 'Futebol Masculino':
            num_quadras = config.num_quadras_fut_masc
        elif modalidade == 'Vôlei Misto':
            num_quadras = config.num_quadras_volei_misto

        # Chamada para uma nova função que SÓ gera os jogos
        gerar_jogos_para_grupos_prontos(modalidade, num_quadras)

        return jsonify(success=True)
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500

@app.route('/admin/editar_resultado/<int:game_id>', methods=['GET', 'POST'])
@login_required
def editar_resultado(game_id):
    if not current_user.is_admin:
        abort(403)
    game = Game.query.get_or_404(game_id)
    if request.method == 'POST':
        # Salva placares normais
        game.gols_time_a = request.form.get('gols_time_a') if request.form.get('gols_time_a') else None
        game.gols_time_b = request.form.get('gols_time_b') if request.form.get('gols_time_b') else None
        game.sets_vencidos_a = request.form.get('sets_vencidos_a') if request.form.get('sets_vencidos_a') else None
        game.sets_vencidos_b = request.form.get('sets_vencidos_b') if request.form.get('sets_vencidos_b') else None

        # --- LÓGICA PARA SALVAR PÊNALTIS SEM MUDAR O BANCO ---
        penaltis_a_str = request.form.get('penaltis_time_a')
        penaltis_b_str = request.form.get('penaltis_time_b')
        if penaltis_a_str and penaltis_b_str:
            dados_penaltis = {
                "penaltis_a": int(penaltis_a_str),
                "penaltis_b": int(penaltis_b_str)
            }
            game.pontos_sets = json.dumps(dados_penaltis)  # Salva como texto JSON

        # Lógica para salvar horário e finalizar o jogo (sem alterações)
        horario_str = request.form.get('horario')
        if horario_str and game.data_hora:
            try:
                horas, minutos = map(int, horario_str.split(':'))
                game.data_hora = game.data_hora.replace(hour=horas, minute=minutos)
            except ValueError:
                flash("Formato de horário inválido. Use HH:MM.", "danger")
        action = request.form.get('action')
        if action == 'finalizar':
            game.finalizado = True
            atualizar_classificacao_e_avancar_time(game)

        db.session.commit()
        flash('Jogo atualizado com sucesso!', 'success')
        return redirect(url_for('ver_chaveamento_admin'))

    return render_template('editar_resultado_jogo.html', game=game)

# --- Página de Visualização Pública (Sem Login) ---

@app.route('/portal')
def portal():
    """
    Esta é a nova página do portal público.
    Ela busca por modalidades que já têm grupos criados e as exibe como um menu.
    """
    # Consulta o banco para encontrar as modalidades distintas que já possuem grupos gerados.
    # Isso garante que só vamos mostrar links para torneios que realmente existem.
    modalidades_ativas_tuplas = db.session.query(Grupo.modalidade).distinct().all()

    # O resultado vem como uma lista de tuplas, ex: [('Futebol Masculino',), ('Futebol Feminino',)].
    # Vamos converter para uma lista simples, ex: ['Futebol Masculino', 'Futebol Feminino'].
    modalidades_ativas = [item[0] for item in modalidades_ativas_tuplas]

    # Renderiza o novo template, passando a lista de modalidades ativas.
    return render_template('portal.html', modalidades=modalidades_ativas)


@app.route('/grupos/<modalidade>')
def visualizar_grupos(modalidade):
    grupos = Grupo.query.filter_by(modalidade=modalidade).order_by(Grupo.nome).all()
    for grupo in grupos:
        grupo.classificacao_ordenada = sorted(
            grupo.classificacao,
            key=lambda c: (c.pontos, c.saldo_gols, c.gols_pro),
            reverse=True
        )

    jogos_fase_de_grupos_query = Game.query.filter_by(modalidade=modalidade, fase='Fase de Grupos').options(
        db.joinedload(Game.time_a).joinedload(Time.grupo),
        db.joinedload(Game.time_b)
    ).order_by(Game.local, Game.data_hora).all()

    jogos_por_quadra = {}
    for jogo in jogos_fase_de_grupos_query:
        quadra = jogo.local if jogo.local else "Na Fila"
        if quadra not in jogos_por_quadra: jogos_por_quadra[quadra] = []
        jogos_por_quadra[quadra].append(jogo)

    ordem_fases_mata_mata = ['Quartas de Final', 'Semifinal', 'Disputa 3º Lugar', 'Final']
    tem_fase_final = Game.query.filter(
        Game.modalidade == modalidade,
        Game.fase.in_(ordem_fases_mata_mata)
    ).first() is not None

    jogos_mata_mata = []
    if tem_fase_final:
        jogos_mata_mata = Game.query.filter(
            Game.modalidade == modalidade,
            Game.fase.in_(ordem_fases_mata_mata)
        ).all()

    # Lógica do campeão (sem alterações)
    campeao, vice_campeao, terceiro_lugar = None, None, None
    if tem_fase_final:
        jogo_final = Game.query.filter_by(modalidade=modalidade, fase='Final').first()
        if jogo_final and jogo_final.finalizado and jogo_final.vencedor_id:
            campeao = Time.query.get(jogo_final.vencedor_id)
            outro_time_id = jogo_final.time_b_id if jogo_final.vencedor_id == jogo_final.time_a_id else jogo_final.time_a_id
            if outro_time_id: vice_campeao = Time.query.get(outro_time_id)
        jogo_terceiro = Game.query.filter_by(modalidade=modalidade, fase='Disputa 3º Lugar').first()
        if jogo_terceiro and jogo_terceiro.finalizado and jogo_terceiro.vencedor_id:
            terceiro_lugar = Time.query.get(jogo_terceiro.vencedor_id)

    return render_template('painel_publico.html',
                           grupos=grupos,
                           modalidade=modalidade,
                           jogos_por_quadra=jogos_por_quadra,
                           tem_fase_final=tem_fase_final,
                           jogos_mata_mata=jogos_mata_mata,
                           ordem_fases_mata_mata=ordem_fases_mata_mata,  # <-- NOVA VARIÁVEL
                           campeao=campeao,
                           vice_campeao=vice_campeao,
                           terceiro_lugar=terceiro_lugar)


@app.route('/time_publico/<int:time_id>')
def visualizar_time_publico(time_id):
    time = Time.query.get_or_404(time_id)

    # --- ADICIONE ESTAS DUAS LINHAS DE TESTE ---
    print(f"DEBUG: Verificando time: '{time.nome_base or time.nome_igreja}' (ID: {time.id})")
    print(f"DEBUG: Lista de jogadores encontrada no banco para este time: {time.jogadores}")
    # ---------------------------------------------

    # Separa o capitão dos outros jogadores
    capitao = None
    outros_jogadores = []
    for jogador in time.jogadores:
        if jogador.is_capitao:
            capitao = jogador
        else:
            outros_jogadores.append(jogador)

    # Ordena os outros jogadores por nome para manter a consistência
    outros_jogadores.sort(key=lambda x: x.nome_completo)

    return render_template('time_publico.html',
                           time=time,
                           capitao=capitao,
                           outros_jogadores=outros_jogadores)

@app.route('/api/dados_mata_mata/<modalidade>')
def api_dados_mata_mata(modalidade):
    ordem_fases = ['Quartas de Final', 'Semifinal', 'Final']
    jogos_mata_mata = Game.query.filter(Game.modalidade == modalidade, Game.fase.in_(ordem_fases)).order_by(Game.fase, Game.ordem_na_fase).all()
    if not jogos_mata_mata: return jsonify(teams=[], results=[])

    primeira_fase_existente = next((fase for fase in ordem_fases if any(j.fase == fase for j in jogos_mata_mata)), None)
    if not primeira_fase_existente: return jsonify(teams=[], results=[])

    jogos_primeira_rodada = [j for j in jogos_mata_mata if j.fase == primeira_fase_existente]
    teams = [[(j.time_a.nome_igreja if j.time_a else "A definir"), (j.time_b.nome_igreja if j.time_b else "A definir")] for j in jogos_primeira_rodada]

    results = []
    fases_encontradas = sorted(list(set(j.fase for j in jogos_mata_mata)), key=lambda x: ordem_fases.index(x))
    for fase in fases_encontradas:
        jogos_da_fase = [j for j in jogos_mata_mata if j.fase == fase]
        rodada_atual = []
        for jogo in jogos_da_fase:
            placar_a, placar_b = None, None
            # --- LÓGICA ALTERADA: Mostra o placar mesmo se não estiver finalizado ---
            if 'Futebol' in jogo.modalidade:
                if jogo.gols_time_a is not None:
                    placar_a, placar_b = jogo.gols_time_a, jogo.gols_time_b
                    if jogo.pontos_sets:
                        try:
                            dados_penaltis = json.loads(jogo.pontos_sets)
                            placar_a = f"{placar_a} ({dados_penaltis.get('penaltis_a')})"
                            placar_b = f"{placar_b} ({dados_penaltis.get('penaltis_b')})"
                        except: pass
            else: # Vôlei
                placar_a = jogo.sets_vencidos_a if jogo.sets_vencidos_a is not None else jogo.gols_time_a
                placar_b = jogo.sets_vencidos_b if jogo.sets_vencidos_b is not None else jogo.gols_time_b
            rodada_atual.append([placar_a, placar_b])
        results.append(rodada_atual)
    return jsonify(teams=teams, results=results)


if __name__ == '__main__':
    app.run(debug=True)