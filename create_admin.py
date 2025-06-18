# create_admin.py
import os
import csv
import secrets
import string
from app import app, db
from models import User


def generate_random_password(length=8):  # Senha de 8 caracteres
    """Gera uma senha aleatória com letras minúsculas e dígitos."""
    characters = string.ascii_lowercase + string.digits  # Apenas minúsculas e dígitos
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password


def create_multiple_admins():
    with app.app_context():
        admin_users_info = [
            {'name': 'Natan', 'email_prefix': 'natan'},
            {'name': 'Daniel', 'email_prefix': 'daniel'},
            {'name': 'Roberta', 'email_prefix': 'roberta'},
            {'name': 'Maycon', 'email_prefix': 'maycon'},
            {'name': 'Sonia', 'email_prefix': 'sonia'},
            {'name': 'Matheus', 'email_prefix': 'matheus'},
            {'name': 'Regis', 'email_prefix': 'regis'},
            {'name': 'Jeferson', 'email_prefix': 'jeferson'},
            {'name': 'Giliard', 'email_prefix': 'giliard'},
            {'name': 'Estefany', 'email_prefix': 'estefany'},
        ]

        # Adicionar admins genéricos (adm1 a adm15)
        for i in range(1, 16):
            admin_users_info.append({'name': f'adm{i}', 'email_prefix': f'adm{i}'})

        # O admin principal e de teste podem ser mantidos para fácil acesso
        admin_users_info.append({'name': 'AdminMaster', 'email_prefix': 'adminmaster'})
        admin_users_info.append({'name': 'TestUser', 'email_prefix': 'testuser'})

        output_file_name = 'admin_logins.csv'
        output_file_path = os.path.join(os.path.dirname(__file__), output_file_name)

        print("Iniciando criação/verificação de usuários administradores e salvando em arquivo...")

        with open(output_file_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
            csvfile.write('sep=,\n')  # Linha que informa o delimitador ao Excel

            fieldnames = ['Nome de Usuário (Login)', 'Email', 'Senha']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()

            for user_data in admin_users_info:
                username = user_data['name']
                email = f"{user_data['email_prefix']}@oneday.com"

                password = generate_random_password(length=8)

                user_exists = User.query.filter_by(username=username).first()
                if user_exists:
                    print(f'Usuário admin "{username}" já existe. Pulando criação.')
                else:
                    admin_user = User(username=username, email=email, is_admin=True)
                    admin_user.set_password(password)
                    db.session.add(admin_user)
                    db.session.commit()
                    print(f'Usuário admin "{username}" criado com sucesso. Email: {email} Senha: {password}')

                writer.writerow({'Nome de Usuário (Login)': username, 'Email': email, 'Senha': password})

        print(f"\nCriação/verificação de administradores concluída.")
        print(f"Logins salvos em: {output_file_path}")


if __name__ == '__main__':
    create_multiple_admins()