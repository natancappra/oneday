# simulate_group_stage.py
import random
from app import app, db
from models import Game
from app import atualizar_classificacao_e_avancar_time, gerar_fase_mata_mata  # Importa a nova função


def simular_fase_de_grupos(modalidade):
    """Encontra, simula todos os jogos da fase de grupos E garante a criação do mata-mata."""
    with app.app_context():
        jogos_para_simular = Game.query.filter_by(
            modalidade=modalidade,
            fase='Fase de Grupos',
            finalizado=False
        ).all()

        if not jogos_para_simular:
            print(f"Nenhum jogo da Fase de Grupos pendente para '{modalidade}'.")
            return

        print(f"--- Simulando {len(jogos_para_simular)} jogos da Fase de Grupos para {modalidade} ---")

        for jogo in jogos_para_simular:
            if 'Futebol' in jogo.modalidade:
                jogo.gols_time_a = random.randint(0, 5)
                jogo.gols_time_b = random.randint(0, 5)
                print(
                    f"Jogo {jogo.id}: {jogo.time_a.nome_igreja} {jogo.gols_time_a} x {jogo.gols_time_b} {jogo.time_b.nome_igreja}")

            elif 'Vôlei' in jogo.modalidade:
                placar_perdedor = random.randint(0, 18)
                if random.choice([True, False]):
                    jogo.gols_time_a = 20
                    jogo.gols_time_b = placar_perdedor
                else:
                    jogo.gols_time_a = placar_perdedor
                    jogo.gols_time_b = 20
                print(
                    f"Jogo {jogo.id}: {jogo.time_a.nome_igreja} {jogo.gols_time_a} x {jogo.gols_time_b} {jogo.time_b.nome_igreja}")

            jogo.finalizado = True
            # A função abaixo ainda é chamada, mas não confiaremos mais nela para gerar o mata-mata
            atualizar_classificacao_e_avancar_time(jogo)

        print("\n--- Simulação da Fase de Grupos concluída! ---")

        # --- NOVA VERIFICAÇÃO DE SEGURANÇA ---
        # Após o loop, verifica se realmente não há mais jogos pendentes e chama a geração do mata-mata
        jogos_pendentes = Game.query.filter_by(modalidade=modalidade, fase='Fase de Grupos', finalizado=False).count()
        if jogos_pendentes == 0:
            print("Confirmado! Todos os jogos finalizados. Gerando fase de mata-mata...")
            gerar_fase_mata_mata(modalidade)
        else:
            print(f"AVISO: Ainda existem {jogos_pendentes} jogos pendentes. O mata-mata não foi gerado.")


if __name__ == '__main__':
    modalidade_input = input(
        "Digite a modalidade para simular a Fase de Grupos (ex: Futebol Masculino ou Vôlei Misto): ")
    if modalidade_input in ['Futebol Masculino', 'Vôlei Misto']:
        simular_fase_de_grupos(modalidade_input)
    else:
        print("Modalidade inválida. Tente novamente.")