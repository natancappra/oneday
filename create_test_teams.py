# create_test_teams.py
from app import app, db
from models import User, Time

# Defina as quantidades aqui para fácil alteração
TIMES_FUTEBOL_MASCULINO = 16
TIMES_VOLEI_MISTO = 13

def criar_times(modalidade, quantidade, lider):
    """Cria uma quantidade específica de times para uma modalidade."""
    print(f"--- Criando {quantidade} times para {modalidade}... ---")
    times_criados = []
    for i in range(1, quantidade + 1):
        time = Time(
            nome_igreja=f"Time {i} ({modalidade[:1]})", # <<< LINHA ALTERADA (Ex: Time 1 (F), Time 2 (V))
            distrito=f"Distrito {chr(65 + i % 5)}",     # <<< LINHA ALTERADA (Ex: Distrito A)
            regiao=f"Região {i % 8 + 1}",               # <<< LINHA ALTERADA (Ex: Região 1)
            nome_base=f"Base {i}",                      # <<< LINHA ALTERADA (Ex: Base 1)
            modalidade=modalidade,
            lider_id=lider.id,
            pagou=True # Marcados como pagos para os testes
        )
        times_criados.append(time)
    db.session.add_all(times_criados)
    db.session.commit()
    print(f"--- {quantidade} times de {modalidade} criados com sucesso! ---")

def main():
    """Função principal que orquestra a criação dos times."""
    with app.app_context():
        # Tenta encontrar o primeiro usuário administrador para ser o líder dos times.
        lider_teste = User.query.filter_by(is_admin=True).first()

        if not lider_teste:
            print("ERRO: Nenhum usuário administrador foi encontrado no banco de dados.")
            print("Por favor, crie um usuário primeiro (usando seu script create_admin.py, por exemplo) antes de rodar este script.")
            return

        print(f"Usando o líder '{lider_teste.username}' para criar os times de teste.")

        # Cria os times para cada modalidade
        criar_times("Futebol Masculino", TIMES_FUTEBOL_MASCULINO, lider_teste)
        criar_times("Vôlei Misto", TIMES_VOLEI_MISTO, lider_teste)

        print("\nProcesso de criação de times finalizado!")

if __name__ == '__main__':
    main()