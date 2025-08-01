# run_full_simulation.py
import random
from app import app, db, gerar_chaveamento_para_modalidade
from models import User, Time, Jogador, Game, Grupo, Classificacao, Configuracao
from simulate_games import simular_campeonato_inteiro


def limpar_banco_de_dados():
    """Apaga todos os dados das tabelas para um novo teste."""
    print("--- Limpando o banco de dados... ---")
    # A ordem é importante para evitar erros de chave estrangeira
    Game.query.delete()
    Classificacao.query.delete()
    Jogador.query.delete()
    Grupo.query.delete()
    Time.query.delete()
    User.query.delete()
    Configuracao.query.delete()
    db.session.commit()


def criar_times(modalidade, quantidade, lider):
    """Cria uma quantidade específica de times para uma modalidade."""
    print(f"--- Criando {quantidade} times para {modalidade}... ---")
    times_criados = []
    for i in range(1, quantidade + 1):
        time = Time(
            nome_igreja=f"Time Simulado {modalidade} {i}",
            distrito=f"Distrito {chr(65 + i % 5)}",  # Gera Distritos de A a E
            regiao=f"Região {i % 8 + 1}",
            nome_base=f"Base de Teste {i}",
            modalidade=modalidade,
            lider_id=lider.id,
            pagou=True  # Essencial para que entrem no chaveamento
        )
        times_criados.append(time)
    db.session.add_all(times_criados)
    db.session.commit()


def configurar_quadras():
    """Cria a configuração de quadras no banco de dados."""
    print("--- Configurando o número de quadras... ---")
    config = Configuracao(
        num_quadras_fut_masc=4,  # Exemplo: 4 quadras para masculino
        num_quadras_fut_fem=2,  # Não usado neste teste, mas precisa existir
        num_quadras_volei_misto=3  # Exemplo: 3 quadras para vôlei
    )
    db.session.add(config)
    db.session.commit()
    return config


def main():
    """Função principal que orquestra toda a simulação."""
    with app.app_context():
        # 1. Limpa o ambiente
        limpar_banco_de_dados()

        # 2. Cria um usuário líder
        print("--- Criando usuário de teste... ---")
        admin_user = User(username="AdminTeste", email="admin@teste.com")
        admin_user.set_password("123")
        db.session.add(admin_user)
        db.session.commit()

        # 3. Cria os times conforme solicitado
        criar_times("Futebol Masculino", 16, admin_user)
        criar_times("Vôlei Misto", 13, admin_user)

        # 4. Cria a configuração de quadras
        config = configurar_quadras()

        # 5. Gera o chaveamento inicial (Fase de Grupos)
        print("\n--- Gerando chaveamento da Fase de Grupos... ---")
        gerar_chaveamento_para_modalidade('Futebol Masculino', config.num_quadras_fut_masc)
        gerar_chaveamento_para_modalidade('Vôlei Misto', config.num_quadras_volei_misto)
        print("Chaveamentos de grupo gerados com sucesso!")

        # 6. Simula todos os jogos do início ao fim
        simular_campeonato_inteiro()


if __name__ == '__main__':
    main()