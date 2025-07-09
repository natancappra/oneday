# models.py
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime, timedelta, date, timezone

from extensions import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    times = db.relationship('Time', backref='lider', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)


class Time(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_igreja = db.Column(db.String(150), nullable=False)
    distrito = db.Column(db.String(100))
    regiao = db.Column(db.String(100))
    nome_base = db.Column(db.String(100))
    modalidade = db.Column(db.String(50), nullable=False)
    token = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    lider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    jogadores = db.relationship('Jogador', backref='time', cascade='all, delete-orphan')

    imagem = db.Column(db.String(255), nullable=True)
    link_pagamento = db.Column(db.String(200), nullable=True)
    pagou = db.Column(db.Boolean, default=False)
    comprovante_pagamento = db.Column(db.String(255), nullable=True)

    diretor_jovem = db.Column(db.String(150), nullable=True)

    cadastros_encerrados = db.Column(db.Boolean, default=False)
    chaveamento_json = db.Column(db.Text, nullable=True)
    limite_nao_adv_fut_masc = db.Column(db.Integer, default=1)
    limite_nao_adv_fut_fem = db.Column(db.Integer, default=2)
    limite_nao_adv_volei_misto = db.Column(db.Integer, default=1)
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'), nullable=True)
    classificacao = db.relationship('Classificacao', backref='time', uselist=False, cascade='all, delete-orphan')


    def __repr__(self):
        return f"<Time {self.nome_igreja} ({self.modalidade})>"


class Jogador(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    foto = db.Column(db.String(255), nullable=True)
    telefone = db.Column(db.String(20), nullable=False)
    nome_completo = db.Column(db.String(150), nullable=False)
    cpf = db.Column(db.String(20), nullable=True)
    rg = db.Column(db.String(20), nullable=True)
    data_nascimento = db.Column(db.Date, nullable=True)
    time_id = db.Column(db.Integer, db.ForeignKey('time.id'), nullable=False)

    is_adventista = db.Column(db.Boolean, default=True)
    foto_identidade = db.Column(db.String(255), nullable=True)
    is_capitao = db.Column(db.Boolean, default=False)


    def __repr__(self):
        return f"<Jogador {self.nome_completo} ({self.time.nome_igreja})>"


# Em models.py

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    modalidade = db.Column(db.String(50), nullable=False)
    fase = db.Column(db.String(100), nullable=True)
    data_hora = db.Column(db.DateTime, nullable=True)
    local = db.Column(db.String(100), nullable=True)
    finalizado = db.Column(db.Boolean, default=False, nullable=False)
    ordem_na_fase = db.Column(db.Integer, nullable=True)

    # --- Chaves Estrangeiras ---
    time_a_id = db.Column(db.Integer, db.ForeignKey('time.id'), nullable=True)
    time_b_id = db.Column(db.Integer, db.ForeignKey('time.id'), nullable=True)
    vencedor_id = db.Column(db.Integer, db.ForeignKey('time.id'), nullable=True)

    # --- Campos de Placar para TODAS as modalidades ---
    gols_time_a = db.Column(db.Integer)
    gols_time_b = db.Column(db.Integer)
    sets_vencidos_a = db.Column(db.Integer)  # <-- CAMPO ADICIONADO
    sets_vencidos_b = db.Column(db.Integer)  # <-- CAMPO ADICIONADO
    pontos_sets = db.Column(db.String(200))    # Para o JSON do Vôlei

    # --- Relações com outras tabelas (definidas uma única vez) ---
    time_a = db.relationship('Time', foreign_keys=[time_a_id], backref='jogos_como_time_a')
    time_b = db.relationship('Time', foreign_keys=[time_b_id], backref='jogos_como_time_b')
    vencedor = db.relationship('Time', foreign_keys=[vencedor_id], backref='jogos_vencidos')

    # --- Relação para o Mata-Mata ---
    proximo_jogo_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=True)
    jogos_anteriores = db.relationship('Game', backref=db.backref('proximo_jogo', remote_side=[id]))

    def __repr__(self):
        t_a_name = self.time_a.nome_igreja if self.time_a else "A definir"
        t_b_name = self.time_b.nome_igreja if self.time_b else "A definir"
        return f"<Game {t_a_name} vs {t_b_name} ({self.modalidade})>"

class Configuracao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cadastros_globais_encerrados = db.Column(db.Boolean, default=False)
    num_quadras_fut_masc = db.Column(db.Integer, default=3)
    num_quadras_fut_fem = db.Column(db.Integer, default=3)
    num_quadras_volei_misto = db.Column(db.Integer, default=3)
    # --- Certifique-se que estas colunas existem! ---
    limite_nao_adv_fut_masc = db.Column(db.Integer, default=1) # Limite padrão para Futebol Masculino
    limite_nao_adv_fut_fem = db.Column(db.Integer, default=2) # Limite padrão para Futebol Feminino
    limite_nao_adv_volei_misto = db.Column(db.Integer, default=1) # Limite padrão para Vôlei Misto

def __repr__(self):
    t_a_name = self.time_a.nome_igreja if self.time_a else "A definir"
    t_b_name = self.time_b.nome_igreja if self.time_b else "A definir"
    return f"<Game {t_a_name} vs {t_b_name} ({self.modalidade})>"

class Grupo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(50), nullable=False) # Ex: "Grupo A"
    modalidade = db.Column(db.String(50), nullable=False)
    times = db.relationship('Time', backref='grupo', lazy=True)
    classificacao = db.relationship('Classificacao', backref='grupo', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Grupo {self.nome} ({self.modalidade})>'

class Classificacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # pontos não é mais necessário, será uma propriedade calculada
    jogos_disputados = db.Column(db.Integer, default=0)
    vitorias = db.Column(db.Integer, default=0)
    empates = db.Column(db.Integer, default=0)
    derrotas = db.Column(db.Integer, default=0)
    gols_pro = db.Column(db.Integer, default=0)
    gols_contra = db.Column(db.Integer, default=0)

    time_id = db.Column(db.Integer, db.ForeignKey('time.id'), nullable=False)
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'), nullable=False)

    @property
    def saldo_gols(self):
        """Calcula o saldo de gols."""
        return self.gols_pro - self.gols_contra

    @property
    def pontos(self):
        return (self.vitorias * 3) + (self.empates * 1)

    def __repr__(self):
        return f'<Classificacao Time {self.time_id} - {self.pontos} Pts>'