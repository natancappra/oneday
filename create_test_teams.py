# create_test_teams.py
from app import app, db
from models import User, Time, Jogador  # Adicionado Jogador

# Defina as quantidades aqui para fácil alteração
TIMES_FUTEBOL_MASCULINO = 16
TIMES_VOLEI_MISTO = 13
JOGADORES_POR_TIME = 12  # Define quantos jogadores criar por time


def criar_times_e_jogadores(modalidade, quantidade, lider):
    """
    Cria uma quantidade específica de times e, para cada time,
    cria um elenco de jogadores de teste, incluindo um capitão.
    """
    print(f"--- Criando {quantidade} times e seus elencos para {modalidade}... ---")

    times_criados = []
    for i in range(1, quantidade + 1):
        time = Time(
            nome_igreja=f"Igreja do Time {i} ({modalidade[:1]})",
            nome_base=f"Time {i} ({modalidade[:1]})",
            distrito=f"Distrito {chr(65 + i % 5)}",
            regiao=f"Região {i % 8 + 1}",
            modalidade=modalidade,
            lider_id=lider.id,
            pagou=True
        )
        times_criados.append(time)

    db.session.add_all(times_criados)
    db.session.commit()  # Salva todos os times para que eles ganhem IDs

    # Agora, com os times já criados, cria os jogadores
    for time in times_criados:
        jogadores_para_adicionar = []

        # Cria o Capitão
        capitao = Jogador(
            nome_completo=f"Capitão {time.nome_base}",
            telefone="00000000000",
            is_capitao=True,
            time_id=time.id
        )
        jogadores_para_adicionar.append(capitao)

        # Cria os outros jogadores
        for j in range(1, JOGADORES_POR_TIME):
            jogador = Jogador(
                nome_completo=f"Jogador {j} ({time.nome_base})",
                telefone="00000000000",
                is_capitao=False,
                time_id=time.id
            )
            jogadores_para_adicionar.append(jogador)

        db.session.add_all(jogadores_para_adicionar)

    db.session.commit()  # Salva todos os jogadores de todos os times
    print(f"--- Elencos de {quantidade} times de {modalidade} foram criados com sucesso! ---")


def main():
    """Função principal que orquestra a criação dos times e jogadores."""
    with app.app_context():
        lider_teste = User.query.filter_by(is_admin=True).first()

        if not lider_teste:
            print("ERRO: Nenhum usuário administrador foi encontrado no banco de dados.")
            return

        print(f"Usando o líder '{lider_teste.username}' para criar os times de teste.")

        criar_times_e_jogadores("Futebol Masculino", TIMES_FUTEBOL_MASCULINO, lider_teste)
        criar_times_e_jogadores("Vôlei Misto", TIMES_VOLEI_MISTO, lider_teste)

        print("\nProcesso de criação de times e jogadores finalizado!")


if __name__ == '__main__':
    main()