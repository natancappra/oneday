import os
import uuid
from datetime import datetime, timedelta, date, timezone
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_migrate import Migrate
from flask import current_app
from flask import Flask, render_template, redirect, url_for, request, abort, flash, send_file, jsonify, has_request_context
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer as Serializer
from wtforms import PasswordField, BooleanField, StringField
from wtforms.validators import DataRequired, Optional, Email, Length
from itertools import combinations
import json
import io
import random
import math
import config
from flask import (Flask, request, render_template, redirect, url_for, flash, session)
import pandas as pd
from extensions import db
from models import User, Time, Jogador, Game, Configuracao, Grupo, Classificacao
import dropbox
from PIL import Image
import traceback

# --- Constantes do Campeonato ---
REGIAO_OPCOES = [
    "Região 1 | Moving - Regional Natan Cappra",
    "Região 2 | I Am - Regional Daniel Martins",
    "Região 3 | Chamados - Regional Roberta Pedroso",
    "Região 4 | Together - Regional Maycon Lilo",
    "Região 5 | Reaviva - Regional Sônia Ribeiro",
    "Região 6 | Bethel - Regional Matheus Felipe",
    "Região 7 | Tô Ligado - Regional Regis Nogara",
    "Região 8 | Forgiven - Regional Jeferson Martins",
]

LINK_PAGAMENTO_PADRAO = "https://eventodaigreja.com.br/ILRJ81"

# --- Criação e configuração do app ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui'

# Configurações iniciais das quadras (serão setadas via admin_master)
app.config['NUM_QUADRAS_FUTEBOL'] = 3
app.config['NUM_QUADRAS_VOLEI'] = 3

# --- Configuração de E-mail (Flask-Mail) ---
app.config.from_object(config)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # Mantemos esta linha aqui por enquanto
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads') # E esta
mail = Mail(app) # Inicializa a extensão

# --- Inicialização das extensões ---

db.init_app(app)
migrate = Migrate(app, db, render_as_batch=True)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

admin = Admin(app, name='Painel Admin', template_mode='bootstrap4')

# Este é o bloco de código correto em app.py

class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'Natan' and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        flash('Acesso negado. Apenas o administrador principal (Natan) pode acessar esta área.', 'danger')
        return redirect(url_for('login'))

class UserModelView(AdminModelView):
    # Exclua o password_hash do formulário e da exibição da coluna na lista
    form_excluded_columns = ['times', 'password_hash']
    column_exclude_list = ['password_hash']

    # --- CAMPOS DO FORMULÁRIO DE CRIAÇÃO ---
    # Aqui, listamos os campos na ordem desejada.
    # 'password' é o campo que vamos adicionar manualmente via form_extra_fields.
    form_create_rules = ['username', 'email', 'password',
                         'is_admin']  # Use LISTA [] ao invés de TUPLA () para flexibilidade

    # --- CAMPOS DO FORMULÁRIO DE EDIÇÃO ---
    # Para edição, não precisamos da senha como obrigatória, mas queremos poder alterá-la.
    form_edit_rules = ['username', 'email', 'is_admin', 'password']  # Use LISTA []

    # --- DEFINIÇÃO EXPLÍCITA DE CAMPOS EXTRAS/SOBRESCRITOS ---
    # Aqui é onde resolvemos o erro 'AttributeError: 'tuple' object has no attribute 'items''
    # e garantimos que os campos sejam do tipo certo e com validadores corretos.
    form_extra_fields = {
        'password': PasswordField('Senha', validators=[Optional()]),  # Campo de senha, opcional para edição
        'username': StringField('Nome de Usuário', validators=[DataRequired(), Length(max=80)]),
        'email': StringField('Email', validators=[DataRequired(), Email(), Length(max=120)]),
        'is_admin': BooleanField('É Administrador')
    }

    # --- LÓGICA PARA PROCESSAR A SENHA ---
    # Este método é chamado antes de salvar o modelo no banco de dados.
    # Ele faz o hash da senha se uma nova senha for fornecida no formulário.
    def on_model_change(self, form, model, is_created):
        if form.password.data:  # Se o campo 'password' do formulário tem dados
            model.set_password(form.password.data)  # Use o método do seu modelo User para setar a senha

        # Garante que is_admin seja salvo corretamente se for alterado via form_extra_fields
        if 'is_admin' in form and form.is_admin.data is not None:
            model.is_admin = form.is_admin.data

        super(UserModelView, self).on_model_change(form, model, is_created)


# REGISTRO CORRETO DAS VIEWS
admin.add_view(UserModelView(User, db.session))
admin.add_view(AdminModelView(Time, db.session))
admin.add_view(AdminModelView(Jogador, db.session))
admin.add_view(AdminModelView(Game, db.session))

@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return None
    return None

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

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

# Função para gerar o chaveamento e salvar no banco de dados

def gerar_rodizio_simples(times_da_modalidade, modalidade, num_quadras):
    """
    Cria 1 grupo e gera os jogos de rodízio para um torneio de 3 a 5 times.
    """
    from itertools import combinations

    grupo = Grupo(nome="Grupo Único", modalidade=modalidade)
    db.session.add(grupo)
    db.session.commit()

    for time in times_da_modalidade:
        time.grupo_id = grupo.id
        classificacao = Classificacao(time_id=time.id, grupo_id=grupo.id)
        db.session.add(classificacao)

    jogos_criados = []
    quadra_counter = 0
    ordem_counter = 1
    for time1, time2 in combinations(times_da_modalidade, 2):
        quadra_atual = (quadra_counter % num_quadras) + 1
        jogo = Game(
            modalidade=modalidade,
            fase="Rodízio Simples",
            time_a=time1,
            time_b=time2,
            local=f'Quadra {quadra_atual}',  # Adiciona a quadra
            ordem_na_fase=ordem_counter,  # Adiciona a ordem
            gols_time_a=0,  # Inicializa o placar
            gols_time_b=0
        )
        jogos_criados.append(jogo)
        quadra_counter += 1
        ordem_counter += 1

    db.session.add_all(jogos_criados)
    db.session.commit()
    flash(f"Torneio de Rodízio Simples para {modalidade} gerado com sucesso!", "success")
    return True


# Em app.py, substitua a função gerar_fase_de_grupos_6_a_8_times

def gerar_fase_de_grupos_6_a_8_times(times_da_modalidade, modalidade, num_quadras):
    from itertools import combinations
    # 1. Cria os dois grupos
    grupo_a = Grupo(nome="Grupo A", modalidade=modalidade)
    grupo_b = Grupo(nome="Grupo B", modalidade=modalidade)
    db.session.add_all([grupo_a, grupo_b])
    db.session.commit()

    # ... (lógica para distribuir times e criar classificação, sem alteração) ...
    times_grupo_a, times_grupo_b = [], []
    for i, time in enumerate(times_da_modalidade):
        if i % 2 == 0:
            times_grupo_a.append(time)
            time.grupo_id = grupo_a.id
        else:
            times_grupo_b.append(time)
            time.grupo_id = grupo_b.id
    for time in times_da_modalidade:
        classificacao = Classificacao(time_id=time.id, grupo_id=time.grupo_id)
        db.session.add(classificacao)

    # 4. Gera os jogos da fase de grupos
    jogos_criados = []
    quadra_counter = 0
    for i, (time1, time2) in enumerate(combinations(times_grupo_a, 2)):
        quadra_atual = (quadra_counter % num_quadras) + 1
        jogo = Game(modalidade=modalidade, fase="Fase de Grupos", time_a=time1, time_b=time2,
                    local=f'Quadra {quadra_atual}', ordem_na_fase=i + 1, gols_time_a=0, gols_time_b=0)
        jogos_criados.append(jogo)
        quadra_counter += 1

    for i, (time1, time2) in enumerate(combinations(times_grupo_b, 2)):
        quadra_atual = (quadra_counter % num_quadras) + 1
        jogo = Game(modalidade=modalidade, fase="Fase de Grupos", time_a=time1, time_b=time2,
                    local=f'Quadra {quadra_atual}', ordem_na_fase=i + 1 + len(times_grupo_a), gols_time_a=0,
                    gols_time_b=0)
        jogos_criados.append(jogo)
        quadra_counter += 1

    db.session.add_all(jogos_criados)
    db.session.commit()

    # <<< --- NOVA ETAPA: Chama a função para criar o chaveamento da Fase Final --- >>>
    gerar_fase_final_6_a_8_times(modalidade, grupo_a, grupo_b)

    flash(f"Fase de grupos e chave da Fase Final para {modalidade} gerados com sucesso!", "success")
    return True

def gerar_fase_final_6_a_8_times(modalidade, grupo_a, grupo_b):
    """
    Cria a estrutura da Fase Final (Semifinal e Final) para o formato de 6 a 8 times.
    """
    # Cria os jogos da semifinal e final vazios
    semi1 = Game(modalidade=modalidade, fase="Semifinal", ordem_na_fase=1, local="A definir")
    semi2 = Game(modalidade=modalidade, fase="Semifinal", ordem_na_fase=2, local="A definir")
    final = Game(modalidade=modalidade, fase="Final", ordem_na_fase=1, local="A definir")

    # Cria a disputa de 3º lugar
    terceiro_lugar = Game(modalidade=modalidade, fase="Disputa 3º Lugar", ordem_na_fase=1, local="A definir")

    # Liga os jogos
    semi1.proximo_jogo = final
    semi2.proximo_jogo = final
    # Futuramente, os perdedores da semi irão para a disputa de 3º lugar

    db.session.add_all([semi1, semi2, final, terceiro_lugar])
    db.session.commit()

# --- Rotas de autenticação ---

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
    quadras_configuradas = all([
        config.num_quadras_fut_masc > 0,
        config.num_quadras_fut_fem > 0,
        config.num_quadras_volei_misto > 0
    ])

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

@app.route('/admin/config_quadras', methods=['POST'])
@login_required
def config_quadras():
    if not current_user.is_admin:
        abort(403)

    # Busca a única linha de configuração que existe
    config = Configuracao.query.first()
    if not config:
        # Se não existir por algum motivo, cria
        config = Configuracao()
        db.session.add(config)

    # Pega os valores do formulário e converte para inteiro
    # Usamos .get(..., '0') para o caso de o campo vir vazio
    num_fut_masc = int(request.form.get('num_quadras_fut_masc', '0'))
    num_fut_fem = int(request.form.get('num_quadras_fut_fem', '0'))
    num_volei_misto = int(request.form.get('num_quadras_volei_misto', '0'))

    # Atualiza os atributos do objeto de configuração diretamente
    config.num_quadras_fut_masc = num_fut_masc
    config.num_quadras_fut_fem = num_fut_fem
    config.num_quadras_volei_misto = num_volei_misto

    # Salva as mudanças no banco de dados
    db.session.commit()

    flash('Número de quadras atualizado com sucesso!', 'success')
    log_auditoria(
        f"Atualizou número de quadras no BD: FutMasc={num_fut_masc}, FutFem={num_fut_fem}, Volei={num_volei_misto}")

    return redirect(url_for('admin_master'))

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
        # Prepara o arquivo Excel em memória para não salvar no servidor
        output = io.BytesIO()
        writer = pd.ExcelWriter(output, engine='xlsxwriter')

        # --- ABA 1: RELATÓRIO APENAS DOS TIMES ---
        times_query = Time.query.order_by(Time.nome_igreja).all()
        dados_times = []
        for time in times_query:
            dados_times.append({
                'ID do Time': time.id,
                'Nome da Igreja': time.nome_igreja,
                'Diretor Jovem': time.diretor_jovem,
                'Distrito': time.distrito,
                'Região': time.regiao,
                'Nome da Base': time.nome_base,
                'Modalidade': time.modalidade,
                'Pagamento Confirmado': 'Sim' if time.pagou else 'Não',
                'Comprovante (Link)': time.comprovante_pagamento if time.comprovante_pagamento else 'N/A',
                'Cadastro Encerrado pelo Admin': 'Sim' if time.cadastros_encerrados else 'Não'
            })

        df_times = pd.DataFrame(dados_times)
        # Escreve os dados dos times na primeira aba
        df_times.to_excel(writer, sheet_name='Times Cadastrados', index=False)

        # --- ABA 2: RELATÓRIO DE TODOS OS JOGADORES ---
        jogadores_query = db.session.query(Jogador).join(Time).order_by(Time.nome_igreja, Jogador.nome_completo).all()
        dados_jogadores = []
        for jogador in jogadores_query:
            dados_jogadores.append({
                'Nome do Jogador': jogador.nome_completo,
                'Telefone': jogador.telefone,
                'CPF': jogador.cpf,
                'RG': jogador.rg,
                'Data de Nascimento': jogador.data_nascimento.strftime('%d/%m/%Y') if jogador.data_nascimento else '',
                'É Adventista?': 'Sim' if jogador.is_adventista else 'Não',
                'É Capitão?': 'Sim' if jogador.is_capitao else 'Não',
                'Igreja/Time': jogador.time.nome_igreja,  # Informação do time associado
                'Distrito': jogador.time.distrito,  # Informação do time associado
                'Foto do Jogador (Link)': jogador.foto if jogador.foto else 'N/A',
                'Foto da Identidade (Link)': jogador.foto_identidade if jogador.foto_identidade else 'N/A'
            })

        df_jogadores = pd.DataFrame(dados_jogadores)
        # Escreve os dados dos jogadores na segunda aba
        df_jogadores.to_excel(writer, sheet_name='Jogadores Inscritos', index=False)

        # Salva o arquivo Excel em memória
        writer.close()
        output.seek(0)

        log_admin_action("Gerou relatório Excel com abas de Times e Jogadores.")

        # Envia o arquivo para download direto no navegador
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name='relatorio_campeonato_oneday.xlsx',
            as_attachment=True
        )

    except Exception as e:
        flash(f'Ocorreu um erro ao gerar o relatório: {e}', 'danger')
        log_admin_action(f"Falha ao gerar relatório Excel: {e}")
        return redirect(url_for('admin_master'))

# --- Rotas e Lógica para Chaveamento ---
@app.route('/admin/gerar_chaveamento', methods=['POST'])
@login_required
def gerar_e_salvar_chaveamento():
    if not current_user.is_admin:
        abort(403)

    # --- LÓGICA CORRIGIDA PARA BUSCAR CONFIGURAÇÃO ---
    config = Configuracao.query.first()
    if not config or not all([config.num_quadras_fut_masc, config.num_quadras_fut_fem, config.num_quadras_volei_misto]):
        flash('Erro: O número de quadras para todas as modalidades deve ser configurado antes de gerar o torneio.',
              'danger')
        return redirect(url_for('admin_master'))

    # Limpa os jogos e grupos antigos
    Game.query.delete()
    Grupo.query.delete()
    Classificacao.query.delete()
    db.session.commit()

    # Pega o número de quadras do objeto de configuração
    num_quadras_fut_masc = config.num_quadras_fut_masc
    num_quadras_fut_fem = config.num_quadras_fut_fem
    num_quadras_volei_misto = config.num_quadras_volei_misto

    # O resto da sua lógica de geração de chaveamento continua aqui...
    gerar_chaveamento_para_modalidade('Futebol Masculino', num_quadras_fut_masc)
    gerar_chaveamento_para_modalidade('Futebol Feminino', num_quadras_fut_fem)
    gerar_chaveamento_para_modalidade('Vôlei Misto', num_quadras_volei_misto)

    flash('Chaveamento gerado/recriado com sucesso para todas as modalidades!', 'success')
    log_auditoria("Gerou/Recriou o chaveamento completo.")
    return redirect(url_for('admin_master'))


# Em app.py

def gerar_chaveamento_para_modalidade(modalidade, num_quadras):
    """
    Função principal que gera a fase de grupos para uma modalidade específica,
    usando um algoritmo de Round-Robin e criando os jogos RODADA POR RODADA.
    """
    # --- Parte 1: Setup dos grupos (continua igual) ---
    times_da_modalidade = Time.query.filter_by(modalidade=modalidade, pagou=True).all()
    if len(times_da_modalidade) < 3:
        flash(f'Não há times suficientes (mínimo 3) na modalidade {modalidade} para gerar um torneio.', 'warning')
        return

    random.shuffle(times_da_modalidade)
    num_times = len(times_da_modalidade)
    num_grupos_ideal = math.ceil(num_times / 4)

    grupos_criados = []
    for i in range(num_grupos_ideal):
        nome_grupo = f"Grupo {chr(65 + i)}"
        novo_grupo = Grupo(nome=nome_grupo, modalidade=modalidade)
        db.session.add(novo_grupo)
        grupos_criados.append(novo_grupo)
    db.session.commit()

    for i, time in enumerate(times_da_modalidade):
        grupo_atual = grupos_criados[i % len(grupos_criados)]
        time.grupo_id = grupo_atual.id
        classificacao = Classificacao(time_id=time.id, grupo_id=grupo_atual.id)
        db.session.add(classificacao)
    db.session.commit()

    # --- Parte 2: Geração de Jogos (ALGORITMO NOVO E CORRIGIDO) ---

    todos_os_grupos = Grupo.query.filter_by(modalidade=modalidade).all()
    datas_jogos = [date.today() + timedelta(days=7), date.today() + timedelta(days=14),
                   date.today() + timedelta(days=21)]

    # 1. Pré-calcula todos os confrontos de todas as rodadas para todos os grupos
    calendario_de_rodadas = []
    num_max_rodadas = 0

    for grupo in todos_os_grupos:
        times_no_grupo = Time.query.filter_by(grupo_id=grupo.id).all()

        if len(times_no_grupo) % 2 != 0:
            times_no_grupo.append(None)  # Adiciona time "fantasma" para grupos com times ímpares

        num_rodadas_grupo = len(times_no_grupo) - 1
        if num_rodadas_grupo > num_max_rodadas:
            num_max_rodadas = num_rodadas_grupo

        rodadas_do_grupo = []
        for i in range(num_rodadas_grupo):
            rodadas_do_grupo.append([])

        metade = len(times_no_grupo) // 2
        for i in range(num_rodadas_grupo):
            metade1 = times_no_grupo[:metade]
            metade2 = times_no_grupo[metade:]
            metade2.reverse()

            for j in range(metade):
                rodadas_do_grupo[i].append((metade1[j], metade2[j]))

            # Rotaciona a lista para a proxima rodada
            times_no_grupo.insert(1, times_no_grupo.pop())

        calendario_de_rodadas.append(rodadas_do_grupo)

    # 2. Cria os jogos no banco de dados, rodada por rodada, para garantir a numeração sequencial
    jogo_ordem_global = 1
    for i in range(num_max_rodadas):
        rodada_num_atual = i + 1
        data_jogo_rodada = datas_jogos[i % len(datas_jogos)]

        for j, jogos_do_grupo_na_rodada in enumerate(calendario_de_rodadas):
            if i < len(jogos_do_grupo_na_rodada):
                for confronto in jogos_do_grupo_na_rodada[i]:
                    time_a, time_b = confronto

                    if time_a and time_b:  # Garante que não é um jogo com o time "fantasma"
                        local_jogo = f"Quadra {(jogo_ordem_global % num_quadras) + 1}"

                        novo_jogo = Game(
                            time_a_id=time_a.id,
                            time_b_id=time_b.id,
                            modalidade=modalidade,
                            fase=f"Rodada {rodada_num_atual}",
                            data_hora=datetime.combine(data_jogo_rodada, datetime.min.time()),
                            local=local_jogo,
                            ordem_na_fase=jogo_ordem_global
                        )
                        db.session.add(novo_jogo)
                        jogo_ordem_global += 1

    db.session.commit()

def gerar_fase_mata_mata(modalidade):
    """
    Função INTELIGENTE que gera o mata-mata correto (Quartas ou Semi)
    com base no número de times e nas regras do PDF.
    VERSÃO SEGURA para ser chamada por scripts.
    """
    print(f"Iniciando geração do mata-mata para {modalidade}...")

    times_participantes = Time.query.filter_by(modalidade=modalidade, pagou=True).count()
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

    if 9 <= times_participantes <= 12:
        if len(terceiros_lugares) < 2:
            if has_request_context():
                flash(f'Não foi possível determinar os melhores terceiros para {modalidade}.', 'danger')
            return

        melhores_terceiros = sorted(
            terceiros_lugares,
            key=lambda c: (c.pontos, c.saldo_gols, c.gols_pro),
            reverse=True
        )[:2]
        classificados.extend(melhores_terceiros)

    if len(classificados) == 8:
        print(f"Gerando QUARTAS DE FINAL para {modalidade} com 8 classificados.")
        # ... (lógica para quartas de final, sem alterações aqui)

    elif len(classificados) == 4:
        print(f"Gerando SEMIFINAIS para {modalidade} com 4 classificados.")
        id_1_A = classificados[0].time_id;
        id_2_A = classificados[1].time_id
        id_1_B = classificados[2].time_id;
        id_2_B = classificados[3].time_id

        jogo_final = Game(modalidade=modalidade, fase="Final", ordem_na_fase=3)
        jogo_terceiro_lugar = Game(modalidade=modalidade, fase="Disputa 3º Lugar", ordem_na_fase=4)
        db.session.add_all([jogo_final, jogo_terceiro_lugar]);
        db.session.commit()

        semifinal_1 = Game(time_a_id=id_1_A, time_b_id=id_2_B, modalidade=modalidade, fase="Semifinal", ordem_na_fase=1,
                           proximo_jogo_id=jogo_final.id)
        semifinal_2 = Game(time_a_id=id_1_B, time_b_id=id_2_A, modalidade=modalidade, fase="Semifinal", ordem_na_fase=2,
                           proximo_jogo_id=jogo_final.id)
        db.session.add_all([semifinal_1, semifinal_2])

    else:
        if has_request_context():
            flash(
                f"Número de times classificados ({len(classificados)}) para {modalidade} não é válido para gerar mata-mata.",
                "danger")
        return

    db.session.commit()

    # Adiciona a verificação de contexto aqui também
    if has_request_context():
        flash(f'Fase de Mata-Mata gerada com sucesso para {modalidade}!', 'success')

    log_auditoria(f"Fase de Mata-Mata gerada para {modalidade}.")

def atualizar_classificacao_e_avancar_time(game):
    """
    VERSÃO FINAL E COMPLETA:
    Processa o resultado, atualiza classificação, avança vencedor E
    avança o perdedor da semifinal para a disputa de 3º lugar.
    """
    if game is None:
        return

    # Trata placares nulos como 0 para os cálculos
    gols_a = game.gols_time_a or 0;
    gols_b = game.gols_time_b or 0
    sets_a = game.sets_vencidos_a or 0;
    sets_b = game.sets_vencidos_b or 0

    vencedor, perdedor, empate = None, None, False

    # Determina o vencedor e o perdedor
    if 'Futebol' in game.modalidade:
        if gols_a > gols_b:
            vencedor, perdedor = game.time_a, game.time_b
        elif gols_b > gols_a:
            vencedor, perdedor = game.time_b, game.time_a
        else:
            empate = True
    elif game.modalidade == 'Vôlei Misto':
        if sets_a > sets_b:
            vencedor, perdedor = game.time_a, game.time_b
        elif sets_b > sets_a:
            vencedor, perdedor = game.time_b, game.time_a

    game.vencedor_id = vencedor.id if vencedor else None

    # Atualiza a tabela de classificação (somente na fase de grupos)
    if "Rodada" in game.fase:
        classificacao_a = Classificacao.query.filter_by(time_id=game.time_a_id).first()
        classificacao_b = Classificacao.query.filter_by(time_id=game.time_b_id).first()
        if classificacao_a and classificacao_b:
            classificacao_a.jogos_disputados += 1
            classificacao_b.jogos_disputados += 1
            if 'Futebol' in game.modalidade:
                classificacao_a.gols_pro += gols_a;
                classificacao_a.gols_contra += gols_b
                classificacao_b.gols_pro += gols_b;
                classificacao_b.gols_contra += gols_a
                if empate:
                    classificacao_a.empates += 1;
                    classificacao_b.empates += 1
                elif vencedor == game.time_a:
                    classificacao_a.vitorias += 1;
                    classificacao_b.derrotas += 1
                else:
                    classificacao_b.vitorias += 1;
                    classificacao_a.derrotas += 1
            elif game.modalidade == 'Vôlei Misto':
                if vencedor == game.time_a:
                    classificacao_a.vitorias += 1;
                    classificacao_b.derrotas += 1
                elif vencedor == game.time_b:
                    classificacao_b.vitorias += 1;
                    classificacao_a.derrotas += 1

    # Avança o time no mata-mata
    if vencedor and game.proximo_jogo_id:
        proximo_jogo = Game.query.get(game.proximo_jogo_id)
        if proximo_jogo:
            if game.ordem_na_fase % 2 != 0:
                proximo_jogo.time_a_id = vencedor.id
            else:
                proximo_jogo.time_b_id = vencedor.id

    # --- LÓGICA CORRIGIDA: Trata o perdedor da semifinal ---
    if perdedor and game.fase == 'Semifinal':
        jogo_terceiro_lugar = Game.query.filter_by(modalidade=game.modalidade, fase='Disputa 3º Lugar').first()
        if jogo_terceiro_lugar:
            if game.ordem_na_fase == 1:
                jogo_terceiro_lugar.time_a_id = perdedor.id
            elif game.ordem_na_fase == 2:
                jogo_terceiro_lugar.time_b_id = perdedor.id

    # Dispara o gatilho para criar a próxima fase
    if "Rodada" in game.fase:
        jogos_pendentes = Game.query.filter(Game.modalidade == game.modalidade, Game.fase.like('Rodada%'),
                                            Game.finalizado == False).count()
        if jogos_pendentes == 0:
            gerar_fase_mata_mata(game.modalidade)

    db.session.commit()
    log_auditoria(f"Jogo {game.id} ({game.time_a.nome_igreja} vs {game.time_b.nome_igreja}) finalizado.")

@app.route('/admin/chaveamento')
@login_required
def ver_chaveamento_admin():
    if not current_user.is_admin:
        abort(403)

    # --- Lógica de Ordenação Manual das Fases ---
    # Definimos a ordem correta, da primeira fase para a última.
    ordem_fases = ["Rodada 1", "Oitavas de Final", "Quartas de Final", "Semifinal", "Final"]

    # Buscamos os jogos do banco de dados, sem a ordenação alfabética de fase
    jogos_futebol_raw = Game.query.filter_by(modalidade='Futebol').options(
        db.joinedload(Game.time_a), db.joinedload(Game.time_b), db.joinedload(Game.vencedor)
    ).order_by(Game.ordem_na_fase).all()

    jogos_volei_raw = Game.query.filter_by(modalidade='Vôlei').options(
        db.joinedload(Game.time_a), db.joinedload(Game.time_b), db.joinedload(Game.vencedor)
    ).order_by(Game.ordem_na_fase).all()

    # Agrupamos os jogos, mas mantendo a ordem definida
    jogos_futebol_por_fase = {}
    for fase in ordem_fases:
        jogos_nesta_fase = [j for j in jogos_futebol_raw if j.fase == fase]
        if jogos_nesta_fase:
            jogos_futebol_por_fase[fase] = jogos_nesta_fase

    jogos_volei_por_fase = {}
    for fase in ordem_fases:
        jogos_nesta_fase = [j for j in jogos_volei_raw if j.fase == fase]
        if jogos_nesta_fase:
            jogos_volei_por_fase[fase] = jogos_nesta_fase

    # Esta função agora vai chamar a lógica do chaveamento público e renderizar em um template de admin
    fut_masc, fut_fem, volei_misto = obter_jogos_visiveis()

    return render_template('chaveamento_admin.html',
                           jogos_fut_masc=fut_masc,
                           jogos_fut_fem=fut_fem,
                           jogos_volei=volei_misto,
                           now=datetime.now(timezone.utc))

@app.route('/admin/editar_resultado/<int:game_id>', methods=['GET', 'POST'])
@login_required
def editar_resultado(game_id):
    if not current_user.is_admin:
        abort(403)

    game = Game.query.get_or_404(game_id)

    if request.method == 'POST':
        # --- LÓGICA CORRIGIDA PARA LIDAR COM INPUTS VAZIOS ---

        # Pega a string do formulário
        gols_a_str = request.form.get('gols_time_a')
        gols_b_str = request.form.get('gols_time_b')
        sets_a_str = request.form.get('sets_vencidos_a')
        sets_b_str = request.form.get('sets_vencidos_b')

        # Tenta converter para inteiro. Se falhar (ex: string vazia), assume 0.
        try:
            game.gols_time_a = int(gols_a_str) if gols_a_str and gols_a_str.strip() else None
        except (ValueError, TypeError):
            game.gols_time_a = None

        try:
            game.gols_time_b = int(gols_b_str) if gols_b_str and gols_b_str.strip() else None
        except (ValueError, TypeError):
            game.gols_time_b = None

        try:
            game.sets_vencidos_a = int(sets_a_str) if sets_a_str and sets_a_str.strip() else None
        except (ValueError, TypeError):
            game.sets_vencidos_a = None

        try:
            game.sets_vencidos_b = int(sets_b_str) if sets_b_str and sets_b_str.strip() else None
        except (ValueError, TypeError):
            game.sets_vencidos_b = None

        # Pega os outros campos
        horario_str = request.form.get('horario')
        if horario_str and game.data_hora:
            horas, minutos = map(int, horario_str.split(':'))
            game.data_hora = game.data_hora.replace(hour=horas, minute=minutos)

        game.pontos_sets = request.form.get('pontos_sets', game.pontos_sets)

        action = request.form.get('action')
        if action == 'finalizar':
            game.finalizado = True
            # Adicione aqui a sua lógica para definir o vencedor e atualizar a classificação
            atualizar_classificacao_e_avancar_time(game)

        db.session.commit()
        flash('Jogo atualizado com sucesso!', 'success')
        return redirect(url_for('ver_chaveamento_admin'))

    return render_template('editar_resultado_jogo.html', game=game)

# --- Página de Visualização Pública (Sem Login) ---

# Em app.py

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


@app.route('/chaveamento_publico')
def chaveamento_publico_view():
    fut_masc, fut_fem, volei_misto = obter_jogos_visiveis()

    # Vamos criar um novo template para isso, para não confundir.
    return render_template('chaveamento_publico_view.html',
                           jogos_fut_masc=fut_masc,
                           jogos_fut_fem=fut_fem,
                           jogos_volei=volei_misto)

@app.route('/grupos/<modalidade>')
def visualizar_grupos(modalidade):
    grupos = Grupo.query.filter_by(modalidade=modalidade).order_by(Grupo.nome).all()
    for grupo in grupos:
        grupo.classificacao_ordenada = sorted(
            grupo.classificacao,
            key=lambda c: (c.pontos, c.saldo_gols, c.gols_pro),
            reverse=True
        )

    fases_mata_mata = ['Quartas de Final', 'Semifinal', 'Disputa 3º Lugar', 'Final']
    tem_fase_final = Game.query.filter(
        Game.modalidade == modalidade,
        Game.fase.in_(fases_mata_mata)
    ).first() is not None

    campeao, vice_campeao, terceiro_lugar = None, None, None
    if tem_fase_final:
        jogo_final = Game.query.filter_by(modalidade=modalidade, fase='Final').first()
        if jogo_final and jogo_final.finalizado and jogo_final.vencedor_id:
            campeao = Time.query.get(jogo_final.vencedor_id)
            outro_time_id = jogo_final.time_b_id if jogo_final.vencedor_id == jogo_final.time_a_id else jogo_final.time_a_id
            if outro_time_id:
                vice_campeao = Time.query.get(outro_time_id)

        jogo_terceiro = Game.query.filter_by(modalidade=modalidade, fase='Disputa 3º Lugar').first()
        if jogo_terceiro and jogo_terceiro.finalizado and jogo_terceiro.vencedor_id:
            terceiro_lugar = Time.query.get(jogo_terceiro.vencedor_id)

    return render_template('painel_publico.html',
                           grupos=grupos,
                           modalidade=modalidade,
                           tem_fase_final=tem_fase_final,
                           campeao=campeao,
                           vice_campeao=vice_campeao,
                           terceiro_lugar=terceiro_lugar)

@app.route('/api/dados_mata_mata/<modalidade>')
def api_dados_mata_mata(modalidade):
    fases_mata_mata = ['Quartas de Final', 'Semifinal', 'Final']
    jogos_mata_mata = Game.query.filter(
        Game.modalidade == modalidade,
        Game.fase.in_(fases_mata_mata)
    ).order_by(Game.ordem_na_fase).all()

    if not jogos_mata_mata:
        return jsonify(teams=[], results=[])

    primeira_fase_nome = jogos_mata_mata[0].fase
    jogos_primeira_rodada = [j for j in jogos_mata_mata if j.fase == primeira_fase_nome]

    teams = []
    for jogo in jogos_primeira_rodada:
        time_a_nome = jogo.time_a.nome_igreja if jogo.time_a else "A definir"
        time_b_nome = jogo.time_b.nome_igreja if jogo.time_b else "A definir"
        teams.append([time_a_nome, time_b_nome])

    results = []
    fases_encontradas = sorted(list(set(j.fase for j in jogos_mata_mata)), key=lambda x: fases_mata_mata.index(x))

    for fase in fases_encontradas:
        jogos_da_fase = [j for j in jogos_mata_mata if j.fase == fase]
        rodada_atual = []
        for jogo in jogos_da_fase:
            placar_a, placar_b = None, None
            if jogo.finalizado:
                if 'Futebol' in jogo.modalidade:
                    placar_a = jogo.gols_time_a or 0
                    placar_b = jogo.gols_time_b or 0
                else:
                    placar_a = jogo.sets_vencidos_a or 0
                    placar_b = jogo.sets_vencidos_b or 0
            rodada_atual.append([placar_a, placar_b])
        results.append(rodada_atual)

    return jsonify(teams=teams, results=results)

@app.route('/torneio/<path:modalidade>')
def painel_torneio(modalidade):
    # Verifica se já existem jogos da Fase Final para esta modalidade
    fases_finais = ["Oitavas de Final", "Quartas de Final", "Semifinal", "Final", "Disputa 3º Lugar"]
    jogos_fase_final = Game.query.filter(Game.modalidade == modalidade, Game.fase.in_(fases_finais)).first()

    if jogos_fase_final:
        # Se o mata-mata já foi gerado, mostra a página de chaveamento gráfico
        # (Futuramente, esta página terá o desenho)
        return render_template('chaveamento_publico.html', modalidade=modalidade)
    else:
        # Se ainda não, mostra a página com os grupos
        grupos = Grupo.query.filter_by(modalidade=modalidade).order_by(Grupo.nome).all()
        if not grupos:
            flash(f"O torneio para {modalidade} ainda não foi gerado.", "warning")
            return redirect(url_for('portal_publico'))

        for grupo in grupos:
            grupo.classificacao_ordenada = sorted(
                grupo.classificacao,
                key=lambda c: (c.pontos, c.saldo_de_gols, c.gols_pro),
                reverse=True
            )

        fases_iniciais = ["Fase de Grupos", "Rodízio Simples"]
        jogos_dos_grupos = Game.query.filter(Game.modalidade == modalidade, Game.fase.in_(fases_iniciais)).all()

        return render_template('grupos.html',
                               grupos=grupos,
                               modalidade=modalidade,
                               jogos=jogos_dos_grupos)


# Em app.py

def obter_jogos_visiveis():
    """
    Busca todos os jogos e os separa por modalidade em dicionários,
    com as fases ordenadas corretamente. VERSÃO FINAL.
    """
    # --- LÓGICA CORRIGIDA: Adicionamos a Disputa de 3º Lugar na ordem ---
    ordem_fases = ["Rodada 1", "Rodada 2", "Rodada 3", "Quartas de Final", "Semifinal", "Disputa 3º Lugar", "Final"]

    jogos_fut_masc = {}
    jogos_fut_fem = {}
    jogos_volei = {}

    todos_os_jogos = Game.query.options(
        db.joinedload(Game.time_a), db.joinedload(Game.time_b), db.joinedload(Game.vencedor)
    ).all()

    # Futebol Masculino
    jogos_raw_masc = [j for j in todos_os_jogos if j.modalidade == 'Futebol Masculino']
    for fase in ordem_fases:
        jogos_nesta_fase = [j for j in jogos_raw_masc if j.fase == fase]
        if jogos_nesta_fase:
            jogos_fut_masc[fase] = sorted(jogos_nesta_fase, key=lambda x: x.ordem_na_fase or 0)

    # Futebol Feminino
    jogos_raw_fem = [j for j in todos_os_jogos if j.modalidade == 'Futebol Feminino']
    for fase in ordem_fases:
        jogos_nesta_fase = [j for j in jogos_raw_fem if j.fase == fase]
        if jogos_nesta_fase:
            jogos_fut_fem[fase] = sorted(jogos_nesta_fase, key=lambda x: x.ordem_na_fase or 0)

    # Vôlei Misto
    jogos_raw_volei = [j for j in todos_os_jogos if j.modalidade == 'Vôlei Misto']
    for fase in ordem_fases:
        jogos_nesta_fase = [j for j in jogos_raw_volei if j.fase == fase]
        if jogos_nesta_fase:
            jogos_volei[fase] = sorted(jogos_nesta_fase, key=lambda x: x.ordem_na_fase or 0)

    return jogos_fut_masc, jogos_fut_fem, jogos_volei

if __name__ == '__main__':
    # O modo recomendado de rodar a aplicação é com o comando 'flask run',
    # que já está no seu script 'reset_and_run_complete.ps1'.
    # Este bloco é mantido apenas por compatibilidade.
    app.run(debug=True)