# simulate_quarter_finals.py
import random
import json
from app import app, db
from models import Game
from app import atualizar_classificacao_e_avancar_time


def simular_quartas_de_final(modalidade):
    """Encontra e simula todos os jogos das Quartas de Final para uma modalidade."""
    with app.app_context():
        jogos_para_simular = Game.query.filter_by(
            modalidade=modalidade,
            fase='Quartas de Final',
            finalizado=False
        ).all()

        if not jogos_para_simular:
            print(
                f"Nenhum jogo das Quartas de Final pendente para '{modalidade}'. Verifique se a fase de grupos foi concluída.")
            return

        print(f"--- Simulando {len(jogos_para_simular)} jogos das Quartas de Final para {modalidade} ---")

        for jogo in jogos_para_simular:
            if 'Futebol' in jogo.modalidade:
                # Placar aleatório de futebol, com chance de empate
                jogo.gols_time_a = random.randint(0, 3)
                jogo.gols_time_b = random.randint(0, 3)

                # Se empatar, simula pênaltis
                if jogo.gols_time_a == jogo.gols_time_b:
                    penaltis_perdedor = random.randint(0, 4)
                    if random.choice([True, False]):
                        dados_penaltis = {"penaltis_a": 5, "penaltis_b": penaltis_perdedor}
                    else:
                        dados_penaltis = {"penaltis_a": penaltis_perdedor, "penaltis_b": 5}
                    jogo.pontos_sets = json.dumps(dados_penaltis)
                    print(
                        f"Jogo {jogo.id}: {jogo.time_a.nome_igreja} {jogo.gols_time_a} ({dados_penaltis['penaltis_a']}) x ({dados_penaltis['penaltis_b']}) {jogo.gols_time_b} {jogo.time_b.nome_igreja}")
                else:
                    print(
                        f"Jogo {jogo.id}: {jogo.time_a.nome_igreja} {jogo.gols_time_a} x {jogo.gols_time_b} {jogo.time_b.nome_igreja}")

            elif 'Vôlei' in jogo.modalidade:
                # Placar aleatório de vôlei (set único de 20 pontos)
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
            atualizar_classificacao_e_avancar_time(jogo)

        print("\n--- Simulação das Quartas de Final concluída! ---")
        print("As Semifinais agora devem estar com os times definidos.")


if __name__ == '__main__':
    modalidade_input = input(
        "Digite a modalidade para simular as Quartas de Final (ex: Futebol Masculino ou Vôlei Misto): ")
    if modalidade_input in ['Futebol Masculino', 'Vôlei Misto']:
        simular_quartas_de_final(modalidade_input)
    else:
        print("Modalidade inválida. Tente novamente.")