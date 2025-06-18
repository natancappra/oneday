# seed_data.py - VERSÃO FINAL (COM PAGAMENTO AUTOMÁTICO PARA TESTES)

from app import app, db
from models import Time, User
import random


def popular_banco():
    """
    Esta função cria times de teste para cada modalidade,
    garantindo que não sejam criados em duplicidade e já definindo-os como PAGOS.
    """
    with app.app_context():
        print("--- Iniciando script para popular o banco de dados ---")

        lider_padrao = User.query.filter_by(username='TestUser').first()
        if not lider_padrao:
            lider_padrao = User.query.filter_by(is_admin=True).first()

        if not lider_padrao:
            print("\n!!! ERRO CRÍTICO: Nenhum usuário administrador encontrado no banco. !!!")
            return

        print(f"Usuário '{lider_padrao.username}' será usado como líder padrão para os times de teste.")

        nomes_times = [
            "Guerreiros da Fé", "Leões de Judá", "Águias de Cristo", "Filhos do Rei",
            "Atalaias", "Mensageiros da Paz", "Vencedores em Cristo", "Restaurados",
            "Nova Geração", "Semeadores", "Herdeiros da Promessa", "Defensores do Evangelho"
        ]

        modalidades = ['Futebol Masculino', 'Futebol Feminino', 'Vôlei Misto']

        times_criados = 0
        for modalidade in modalidades:
            print(f"\nVerificando times para a modalidade: {modalidade}")
            random.shuffle(nomes_times)

            for nome_time in nomes_times[:8]:
                time_existente = Time.query.filter_by(nome_igreja=nome_time, modalidade=modalidade).first()

                if not time_existente:
                    novo_time = Time(
                        nome_igreja=nome_time,
                        modalidade=modalidade,
                        regiao=f"Região {random.randint(1, 8)}",
                        distrito=f"Distrito {random.choice(['Norte', 'Sul', 'Leste', 'Oeste'])}",
                        lider_id=lider_padrao.id,
                        # <<< AJUSTE FINAL: MARCAR O TIME COMO PAGO >>>
                        pagou=True
                    )
                    db.session.add(novo_time)
                    times_criados += 1
                    print(f"  -> Criando time: '{nome_time}' (Status: Pago)")
                else:
                    print(f"  -- Pulando time '{nome_time}', pois já existe.")

        if times_criados > 0:
            db.session.commit()
            print(f"\n{times_criados} novos times foram criados com sucesso!")
        else:
            print("\nNenhum time novo foi criado, todos já estavam no banco.")

        print("--- Script finalizado ---")


if __name__ == '__main__':
    popular_banco()