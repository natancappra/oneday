import os
import uuid
from datetime import datetime, timedelta, date, timezone
from flask import Flask, render_template, redirect, url_for, request, abort, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_migrate import Migrate
from flask import current_app
from flask import Flask, render_template, redirect, url_for, request, abort, flash, send_file, jsonify, has_request_context
import json
from itertools import combinations

import io
import random
import math

import pandas as pd

from extensions import db
from models import User, Time, Jogador, Game, Configuracao, Grupo, Classificacao

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

# --- Inicialização das extensões ---
db.init_app(app)
migrate = Migrate(app, db, render_as_batch=True)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

admin = Admin(app, name='Painel Admin', template_mode='bootstrap4')


class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'Natan' and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        flash('Acesso negado. Apenas o administrador principal (Natan) pode acessar esta área.', 'danger')
        return redirect(url_for('login'))


admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Time, db.session))
admin.add_view(AdminModelView(Jogador, db.session))
admin.add_view(AdminModelView(Game, db.session))

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

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


# --- Funções Auxiliares ---
def log_auditoria(acao):
    """
    Registra uma ação de auditoria no console.
    Agora é seguro para ser chamado de scripts fora de um request.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

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

def allowed_file(filename):
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


# Função para registrar ações administrativas (Auditoria simples no console)
def log_admin_action(action_description):
    if current_user.is_authenticated and current_user.is_admin:
        print(
            f"AUDITORIA: Admin '{current_user.username}' realizou a ação: {action_description} em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print(
            f"AUDITORIA: Usuário não admin tentou realizar ação: {action_description} em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


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
        username = request.form.get('username')
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
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já cadastrado', 'warning')
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash('Email já cadastrado', 'warning')
            return redirect(url_for('signup'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        log_admin_action(f"Novo usuário cadastrado: '{username}'")
        flash('Cadastro realizado com sucesso. Faça login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')


# --- Rotas principais ---

@app.route('/')
@login_required
def index():
    if current_user.is_admin:
        times = Time.query.all()
        return render_template('lista_times.html', times=times, perfil='admin', now=datetime.now(timezone.utc))
    else:
        times = Time.query.filter_by(lider_id=current_user.id).all()
        return render_template('lista_times.html', times=times, perfil='admin', now=datetime.now(timezone.utc))


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
    if request.method == 'POST':
        nome_igreja = request.form.get('nome_igreja')
        distrito = request.form.get('distrito')
        regiao = request.form.get('regiao')
        nome_base = request.form.get('nome_base')
        modalidade = request.form.get('modalidade')
        pagou = True if request.form.get('pagou') == 'on' else False
        diretor_jovem = request.form.get('diretor_jovem')

        comprovante_file = request.files.get('comprovante_pagamento')
        comprovante_filename = None
        if comprovante_file and allowed_file(comprovante_file.filename):
            ext = os.path.splitext(comprovante_file.filename)[1]
            comprovante_filename = f"{uuid.uuid4()}_comp{ext}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], comprovante_filename)
            try:
                comprovante_file.save(upload_path)
            except Exception as e:
                flash(f'Erro ao salvar o comprovante: {e}', 'danger')
                return redirect(url_for('cadastro_igreja'))
        elif comprovante_file and comprovante_file.filename != '' and not allowed_file(comprovante_file.filename):
            flash('Formato de comprovante inválido. Use PNG, JPG, JPEG, GIF ou PDF.', 'danger')
            return redirect(url_for('cadastro_igreja'))

        if not nome_igreja or not modalidade:
            flash('Nome da igreja e modalidade são campos obrigatórios.', 'warning')
            return redirect(url_for('cadastro_igreja'))

        imagem_file = request.files.get('imagem')
        imagem_filename = None
        if imagem_file and allowed_file(imagem_file.filename):
            ext = os.path.splitext(imagem_file.filename)[1]
            imagem_filename = f"{uuid.uuid4()}{ext}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], imagem_filename)
            try:
                imagem_file.save(upload_path)
            except Exception as e:
                flash(f'Erro ao salvar a imagem: {e}', 'danger')
                return redirect(url_for('cadastro_igreja'))
        elif imagem_file and imagem_file.filename != '' and not allowed_file(imagem_file.filename):
            flash('Formato de imagem inválido. Use PNG, JPG, JPEG ou GIF.', 'danger')
            return redirect(url_for('cadastro_igreja'))

        novo_time = Time(
            nome_igreja=nome_igreja,
            distrito=distrito,
            regiao=regiao,
            nome_base=nome_base,
            modalidade=modalidade,
            token=str(uuid.uuid4()),
            data_limite_edicao=datetime.utcnow() + timedelta(days=7),
            lider_id=current_user.id,
            imagem=imagem_filename,
            link_pagamento=LINK_PAGAMENTO_PADRAO,
            pagou=pagou,
            comprovante_pagamento=comprovante_filename,
            diretor_jovem=diretor_jovem,
            limite_nao_adventistas=0
        )
        db.session.add(novo_time)
        db.session.commit()
        log_admin_action(f"Cadastrou novo time: '{nome_igreja}'")
        flash('Time cadastrado com sucesso!', 'success')
        return redirect(url_for('index'))

    return render_template('cadastro_igreja.html',
                           regiao_opcoes=REGIAO_OPCOES,
                           LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO)


@app.route('/cadastro_jogador/<token>', methods=['GET', 'POST'])
@login_required
def cadastro_jogador(token):
    time = Time.query.filter_by(token=token).first_or_404()
    if time.lider_id != current_user.id and not current_user.is_admin:
        abort(403)
    if datetime.utcnow() > time.data_limite_edicao and not current_user.is_admin:
        flash('Prazo para edição expirado.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if time.cadastros_encerrados and not current_user.is_admin:
        flash('O cadastro de jogadores para este time foi encerrado.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if request.method == 'POST':
        # Coleta todos os dados do formulário primeiro
        nome_completo = request.form.get('nome_completo')
        cpf = request.form.get('cpf')
        rg = request.form.get('rg')
        data_nascimento_str = request.form.get('data_nascimento')
        is_adventista = 'is_adventista' in request.form
        is_capitao = 'is_capitao' in request.form
        foto_file = request.files.get('foto')
        foto_identidade_file = request.files.get('foto_identidade')

        if not nome_completo:
            flash('O nome completo do jogador é obrigatório.', 'danger')
            return redirect(url_for('cadastro_jogador', token=token))

        # ... (suas validações de capitão e não adventista) ...
        if not is_adventista and time.limite_nao_adventistas is not None:
            non_adventista_count = sum(1 for j in time.jogadores if not j.is_adventista)
            if non_adventista_count >= time.limite_nao_adventistas:
                flash(f'Limite de {time.limite_nao_adventistas} jogadores não adventistas atingido.', 'danger')
                return redirect(url_for('cadastro_jogador', token=token))

        if is_capitao:
            existing_captain = Jogador.query.filter_by(time_id=time.id, is_capitao=True).first()
            if existing_captain:
                flash(f'O time já possui um capitão ({existing_captain.nome_completo}).', 'danger')
                return redirect(url_for('cadastro_jogador', token=token))

        # Processamento de arquivos
        foto_filename = None
        if foto_file and allowed_file(foto_file.filename):
            ext = os.path.splitext(foto_file.filename)[1]
            foto_filename = f"{uuid.uuid4()}{ext}"
            foto_file.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))

        foto_identidade_filename = None
        if foto_identidade_file and allowed_file(foto_identidade_file.filename):
            ext = os.path.splitext(foto_identidade_file.filename)[1]
            foto_identidade_filename = f"{uuid.uuid4()}_id{ext}"
            foto_identidade_file.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_identidade_filename))

        # Converte a data
        data_nascimento = None
        if data_nascimento_str:
            try:
                data_nascimento = datetime.strptime(data_nascimento_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Formato de data de nascimento inválido. Use AAAA-MM-DD.', 'danger')
                return redirect(url_for('cadastro_jogador', token=token))

        # Agora sim, cria o objeto Jogador
        novo_jogador = Jogador(
            nome_completo=nome_completo,
            cpf=cpf,
            rg=rg,
            data_nascimento=data_nascimento,
            is_adventista=is_adventista,
            is_capitao=is_capitao,
            foto=foto_filename,
            foto_identidade=foto_identidade_filename,
            time_id=time.id
        )

        db.session.add(novo_jogador)
        db.session.commit()
        log_admin_action(f"Cadastrou jogador '{novo_jogador.nome_completo}' para o time '{time.nome_igreja}'")
        flash('Jogador cadastrado com sucesso!', 'success')
        return redirect(url_for('ver_time', time_id=time.id))

    return render_template('cadastro_jogador.html', time=time, perfil='lider')


@app.route('/time/<int:time_id>')
@login_required
def ver_time(time_id):
    time = db.session.get(Time, time_id) # Aproveitando para corrigir este também
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
    if datetime.utcnow() > time.data_limite_edicao and not current_user.is_admin:
        flash('Prazo para edição expirado.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if time.cadastros_encerrados and not current_user.is_admin:
        flash('As edições para este time foram encerradas.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if request.method == 'POST':
        time.nome_igreja = request.form.get('nome_igreja')
        time.distrito = request.form.get('distrito')
        time.regiao = request.form.get('regiao')
        time.nome_base = request.form.get('nome_base')
        time.modalidade = request.form.get('modalidade')
        time.pagou = True if request.form.get('pagou') == 'on' else False
        time.diretor_jovem = request.form.get('diretor_jovem')

        comprovante_file = request.files.get('comprovante_pagamento')
        if comprovante_file and allowed_file(comprovante_file.filename):
            ext = os.path.splitext(comprovante_file.filename)[1]
            new_filename = f"{uuid.uuid4()}_comp{ext}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            try:
                comprovante_file.save(upload_path)
                if time.comprovante_pagamento:
                    old_comp_path = os.path.join(app.config['UPLOAD_FOLDER'], time.comprovante_pagamento)
                    if os.path.exists(old_comp_path):
                        os.remove(old_comp_path)
                time.comprovante_pagamento = new_filename
            except Exception as e:
                flash(f'Erro ao atualizar o comprovante: {e}', 'danger')
                return redirect(url_for('editar_time', token=token))
        elif comprovante_file and comprovante_file.filename != '' and not allowed_file(comprovante_file.filename):
            flash('Formato de comprovante inválido. Use PNG, JPG, JPEG, GIF ou PDF.', 'danger')
            return redirect(url_for('editar_time', token=token))

        imagem_file = request.files.get('imagem')
        if imagem_file and allowed_file(imagem_file.filename):
            ext = os.path.splitext(imagem_file.filename)[1]
            new_filename = f"{uuid.uuid4()}{ext}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            try:
                imagem_file.save(upload_path)
                if time.imagem:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], time.imagem)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                time.imagem = new_filename
            except Exception as e:
                flash(f'Erro ao atualizar a imagem: {e}', 'danger')
                return redirect(url_for('editar_time', token=token))
        elif imagem_file and imagem_file.filename != '' and not allowed_file(imagem_file.filename):
            flash('Formato de imagem inválido. Use PNG, JPG, JPEG ou GIF.', 'danger')
            return redirect(url_for('editar_time', token=token))

        time.link_pagamento = LINK_PAGAMENTO_PADRAO

        db.session.commit()
        log_admin_action(f"Editou time: '{time.nome_igreja}'")
        flash('Time atualizado com sucesso.', 'success')
        return redirect(url_for('ver_time', time_id=time.id))
    return render_template('editar_time.html',
                           time=time,
                           regiao_opcoes=REGIAO_OPCOES,
                           LINK_PAGAMENTO_PADRAO=LINK_PAGAMENTO_PADRAO,
                           perfil='lider')


@app.route('/editar_jogador/<int:jogador_id>', methods=['GET', 'POST'])
@login_required
def editar_jogador(jogador_id):
    jogador = Jogador.query.get_or_404(jogador_id)
    time = jogador.time
    if time.lider_id != current_user.id and not current_user.is_admin:
        abort(403)
    if datetime.utcnow() > time.data_limite_edicao and not current_user.is_admin:
        flash('Prazo para edição expirado.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if time.cadastros_encerrados and not current_user.is_admin:
        flash('As edições para este time foram encerrada.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if request.method == 'POST':
        is_adventista = True if request.form.get('is_adventista') == 'on' else False
        is_capitao = True if request.form.get('is_capitao') == 'on' else False

        if not is_adventista and time.limite_nao_adventistas is not None:
            non_adventista_count = sum(1 for j in time.jogadores if not j.is_adventista)
            if non_adventista_count >= time.limite_nao_adventistas:
                flash(f'Limite de {time.limite_nao_adventistas} jogadores não adventistas atingido para este time.',
                      'danger')
                return redirect(url_for('editar_jogador', jogador_id=jogador_id))
        elif not is_adventista and time.limite_nao_adventistas is not None and jogador.is_adventista:
            non_adventista_count = sum(1 for j in time.jogadores if not j.is_adventista)
            if non_adventista_count >= time.limite_nao_adventistas:
                flash(
                    'Limite de {time.limite_nao_adventistas} jogadores não adventistas atingido para este time. Não é possível transformar este jogador em não-adventista.',
                    'danger')
                return redirect(url_for('editar_jogador', jogador_id=jogador_id))

        if is_capitao:
            existing_captain = Jogador.query.filter_by(time_id=time.id, is_capitao=True).first()
            if existing_captain:
                flash(
                    f'O time já possui um capitão ({existing_captain.nome_completo}). Por favor, remova o capitão atual antes de designar um novo.',
                    'danger')
                return redirect(url_for('editar_jogador', jogador_id=jogador_id))
            elif existing_captain and existing_captain.id == jogador.id and not is_capitao:
                jogador.is_capitao = False

        if not jogador.is_capitao and is_capitao:
            Jogador.query.filter_by(time_id=time.id, is_capitao=True).update({'is_capitao': False})
            db.session.commit()

        foto_file = request.files.get('foto')
        if foto_file and allowed_file(foto_file.filename):
            ext = os.path.splitext(foto_file.filename)[1]
            nome_arquivo = f"{uuid.uuid4()}{ext}"
            caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], nome_arquivo)
            try:
                foto_file.save(caminho_foto)
                if jogador.foto:
                    old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], jogador.foto)
                    if os.path.exists(old_photo_path):
                        os.remove(old_photo_path)
                jogador.foto = nome_arquivo
            except Exception as e:
                flash(f'Erro ao atualizar a foto do jogador: {e}', 'danger')
                return redirect(url_for('editar_jogador', jogador_id=jogador_id))
        elif foto_file and foto_file.filename != '' and not allowed_file(foto_file.filename):
            flash('Formato de foto do jogador inválido. Use PNG, JPG, JPEG ou GIF.', 'danger')
            return redirect(url_for('editar_jogador', jogador_id=jogador_id))

        foto_identidade_file = request.files.get('foto_identidade')
        if foto_identidade_file and allowed_file(foto_identidade_file.filename):
            ext = os.path.splitext(foto_identidade_file.filename)[1]
            foto_identidade_filename = f"{uuid.uuid4()}_id{ext}"
            caminho_identidade = os.path.join(app.config['UPLOAD_FOLDER'], foto_identidade_filename)
            try:
                foto_identidade_file.save(caminho_identidade)
                if jogador.foto_identidade:
                    old_id_path = os.path.join(app.config['UPLOAD_FOLDER'], jogador.foto_identidade)
                    if os.path.exists(old_id_path):
                        os.remove(old_id_path)
                jogador.foto_identidade = foto_identidade_filename
            except Exception as e:
                flash(f'Erro ao atualizar a foto da identidade: {e}', 'danger')
                return redirect(url_for('editar_jogador', jogador_id=jogador_id))
        elif foto_identidade_file and foto_identidade_file.filename != '' and not allowed_file(
                foto_identidade_file.filename):
            flash('Formato da foto da identidade inválido. Use PNG, JPG, JPEG ou GIF.', 'danger')
            return redirect(url_for('editar_jogador', jogador_id=jogador_id))

        jogador.nome_completo = request.form.get('nome_completo')
        jogador.cpf = request.form.get('cpf')
        jogador.rg = request.form.get('rg')
        jogador.is_adventista = is_adventista
        jogador.is_capitao = is_capitao

        data_nascimento_str = request.form.get('data_nascimento')
        if data_nascimento_str:
            try:
                jogador.data_nascimento = datetime.strptime(data_nascimento_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Formato de data de nascimento inválido. Use AAAA-MM-DD.', 'danger')
                return redirect(url_for('editar_jogador', jogador_id=jogador_id))
        else:
            jogador.data_nascimento = None

        db.session.commit()
        log_admin_action(
            f"Editou jogador '{jogador.nome_completo}' (ID: {jogador.id}) do time '{time.nome_igreja}' (ID: {time.id})")
        flash('Jogador atualizado com sucesso.', 'success')
        return redirect(url_for('ver_time', time_id=time.id))

    return render_template('editar_jogador.html', jogador=jogador,
                           perfil='lider' if not current_user.is_admin else 'admin')


@app.route('/excluir_jogador/<int:jogador_id>', methods=['POST'])
@login_required
def excluir_jogador(jogador_id):
    jogador = Jogador.query.get_or_404(jogador_id)
    time = jogador.time
    if time.lider_id != current_user.id and not current_user.is_admin:
        abort(403)
    if datetime.utcnow() > time.data_limite_edicao and not current_user.is_admin:
        flash('Prazo para edição expirado.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if time.cadastros_encerrados and not current_user.is_admin:
        flash('As edições para este time foram encerrada.', 'warning')
        return redirect(url_for('ver_time', time_id=time.id))

    if jogador.foto:
        foto_path = os.path.join(app.config['UPLOAD_FOLDER'], jogador.foto)
        if os.path.exists(foto_path):
            os.remove(foto_path)
    if jogador.foto_identidade:
        id_path = os.path.join(app.config['UPLOAD_FOLDER'], jogador.foto_identidade)
        if os.path.exists(id_path):
            os.remove(id_path)

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
    if not current_user.is_admin and time.lider_id != current_user.id:
        abort(403)

    if time.imagem:
        imagem_path = os.path.join(app.config['UPLOAD_FOLDER'], time.imagem)
        if os.path.exists(imagem_path):
            os.remove(imagem_path)

    for jogador in time.jogadores:
        if jogador.foto:
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], jogador.foto)
            if os.path.exists(foto_path):
                os.remove(foto_path)
        if jogador.foto_identidade:
            id_path = os.path.join(app.config['UPLOAD_FOLDER'], jogador.foto_identidade)
            if os.path.exists(id_path):
                os.remove(id_path)

    Game.query.filter(
        (Game.time_a_id == time.id) |
        (Game.time_b_id == time.id) |
        (Game.vencedor_id == time.id)
    ).delete(synchronize_session=False)

    db.session.delete(time)
    db.session.commit()
    log_admin_action(f"Excluiu time: '{time.nome_igreja}' (ID: {time.id})")
    flash('Time excluído com sucesso.', 'success')
    return redirect(url_for('index'))

# --- Rotas e Lógica para Admin Master ---

@app.route('/admin_master')
@login_required
def admin_master():
    if not current_user.is_admin:
        return redirect(url_for('index'))

    # Coletamos todas as informações que o template precisa saber
    config = Configuracao.query.first()
    if not config:
        config = Configuracao()
        db.session.add(config)
        db.session.commit()

    times_validos = Time.query.order_by(Time.modalidade, Time.nome_igreja).all()

    # --- NOVAS VERIFICAÇÕES LÓGICAS ---
    # 1. Verifica se o torneio (jogos) já foi gerado alguma vez
    torneio_gerado = db.session.query(Game.id).first() is not None

    # 2. Verifica se as quadras foram configuradas (se todos os campos são maiores que 0)
    quadras_configuradas = all([
        config.num_quadras_fut_masc > 0,
        config.num_quadras_fut_fem > 0,
        config.num_quadras_volei_misto > 0
    ])
    # ------------------------------------

    return render_template('admin_master.html',
                           times=times_validos,
                           config=config,
                           # Passamos as novas flags para o template
                           torneio_gerado=torneio_gerado,
                           quadras_configuradas=quadras_configuradas)


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

    data_for_excel = []
    times = db.session.query(Time).options(db.joinedload(Time.jogadores)).all()

    for time in times:
        for jogador in time.jogadores:
            data_for_excel.append({
                'ID Time': time.id,
                'Nome da Igreja': time.nome_igreja,
                'Diretor Jovem': time.diretor_jovem if time.diretor_jovem else '',
                'Distrito': time.distrito,
                'Região': time.regiao,
                'Nome da Base': time.nome_base,
                'Modalidade': time.modalidade,
                'Link Pagamento': time.link_pagamento,
                'Pagou': 'Sim' if time.pagou else 'Não',
                'Comprovante Pagamento': url_for('static', filename='uploads/' + time.comprovante_pagamento,
                                                 _external=True) if time.comprovante_pagamento else '',
                'Cadastro Encerrado': 'Sim' if time.cadastros_encerrados else 'Não',
                'Limite Não Adventistas': time.limite_nao_adventistas,
                'ID Jogador': jogador.id,
                'Nome Completo Jogador': jogador.nome_completo,
                'CPF Jogador': jogador.cpf,
                'RG Jogador': jogador.rg,
                'Data Nascimento Jogador': jogador.data_nascimento.strftime(
                    '%d/%m/%Y') if jogador.data_nascimento else '',
                'Adventista': 'Sim' if jogador.is_adventista else 'Não',
                'Capitão': 'Sim' if jogador.is_capitao else 'Não',
                'Caminho Foto Jogador': url_for('static', filename='uploads/' + jogador.foto,
                                                _external=True) if jogador.foto else '',
                'Caminho Foto Identidade': url_for('static', filename='uploads/' + jogador.foto_identidade,
                                                   _external=True) if jogador.foto_identidade else ''
            })

    df = pd.DataFrame(data_for_excel)

    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    df.to_excel(writer, sheet_name='Dados dos Times e Jogadores', index=False)
    writer.close()
    output.seek(0)

    log_admin_action("Gerou relatório Excel de times e jogadores.")
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        download_name='relatorio_times_jogadores.xlsx',
        as_attachment=True
    )

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


# Em app.py

# Em app.py

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

    # --- LÓGICA DE BUSCA DO PÓDIO MAIS ROBUSTA ---
    campeao, vice_campeao, terceiro_lugar = None, None, None
    if tem_fase_final:
        jogo_final = Game.query.filter_by(modalidade=modalidade, fase='Final').first()
        if jogo_final and jogo_final.finalizado and jogo_final.vencedor_id:
            campeao = Time.query.get(jogo_final.vencedor_id)
            # O vice-campeão é o outro time da final
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
    """
    VERSÃO FINAL REESCRITA: Garante a estrutura correta para o jquery-bracket.
    """
    fases_mata_mata = ['Quartas de Final', 'Semifinal', 'Final']

    jogos_mata_mata = Game.query.filter(
        Game.modalidade == modalidade,
        Game.fase.in_(fases_mata_mata)
    ).order_by(Game.ordem_na_fase).all()

    if not jogos_mata_mata:
        return jsonify(teams=[], results=[])

    # 1. Monta a lista de times da primeira rodada (Quartas ou Semis)
    primeira_fase_nome = jogos_mata_mata[0].fase
    jogos_primeira_rodada = [j for j in jogos_mata_mata if j.fase == primeira_fase_nome]

    teams = []
    for jogo in jogos_primeira_rodada:
        time_a_nome = jogo.time_a.nome_igreja if jogo.time_a else "A definir"
        time_b_nome = jogo.time_b.nome_igreja if jogo.time_b else "A definir"
        teams.append([time_a_nome, time_b_nome])

    # 2. Monta a estrutura de resultados
    results = []
    fases_encontradas = sorted(list(set(j.fase for j in jogos_mata_mata)), key=lambda x: fases_mata_mata.index(x))

    for fase in fases_encontradas:
        jogos_da_fase = [j for j in jogos_mata_mata if j.fase == fase]
        rodada_atual = []
        for jogo in jogos_da_fase:
            placar_a, placar_b = None, None
            if jogo.finalizado:
                # Trata placares nulos como 0 para não quebrar o gráfico
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