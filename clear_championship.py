# clear_championship.py
from app import app, db
# Note que o modelo 'User' NÃO é importado aqui de propósito
from models import Game, Classificacao, Grupo, Jogador, Time, Configuracao


def main():
    """
    Função principal para limpar os dados do campeonato do banco de dados.
    Esta função NÃO apaga os usuários.
    """
    with app.app_context():
        print("--- INICIANDO LIMPEZA DO CAMPEONATO ---")
        print("AVISO: Esta ação é irreversível e irá apagar todos os dados de jogos,")
        print("times, jogadores e grupos, mas MANTERÁ as contas de usuário.")

        confirmacao = input("Para confirmar a limpeza, digite 'LIMPAR' e pressione Enter: ")

        if confirmacao == 'LIMPAR':
            print("\nDeletando jogos...")
            Game.query.delete()

            print("Deletando classificações...")
            Classificacao.query.delete()

            print("Deletando jogadores...")
            Jogador.query.delete()

            print("Deletando grupos...")
            Grupo.query.delete()

            print("Deletando times...")
            Time.query.delete()

            print("Deletando configurações do torneio...")
            Configuracao.query.delete()

            # A linha "User.query.delete()" NÃO EXISTE AQUI. É isso que garante a segurança.

            db.session.commit()
            print("\n--- LIMPEZA DO CAMPEONATO CONCLUÍDA COM SUCESSO! ---")
        else:
            print("\nOperação cancelada pelo usuário.")


if __name__ == '__main__':
    main()