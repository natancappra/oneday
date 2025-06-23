import os
import secrets
import string
from app import app, db
from models import User

def generate_random_password(length=8):
    """Gera uma senha aleatória com letras minúsculas e dígitos."""
    characters = string.ascii_lowercase + string.digits
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password


def create_multiple_admins():
    with app.app_context():
        admin_users_info = [
            # Seus usuários personalizados
            {'name': 'Natan', 'email': 'natan.cappra@gmail.com'},
            {'name': 'Giliard', 'email': 'giliard.ferreira@adventistas.org'},
            {'name': 'Estefany', 'email': 'sttefany.rukhaber@adventistas.org'},
            {'name': 'Elias', 'email': 'eliasbueno.adv@gmail.com'},
            {'name': 'Daniel', 'email': 'daniel.dm99282946@gmail.com'},
            {'name': 'Roberta', 'email': 'roberta@oneday.com'},
            {'name': 'Maycon', 'email': 'maycon@oneday.com'},
            {'name': 'Sonia', 'email': 'sonia@oneday.com'},
            {'name': 'Matheus', 'email': 'matheus@oneday.com'},
            {'name': 'Regis', 'email': 'regis@oneday.com'},
            {'name': 'Jeferson', 'email': 'jeferson@oneday.com'},
        ]

        # --- CORREÇÃO APLICADA AQUI ---
        # Adiciona admins genéricos com a estrutura PADRONIZADA
        for i in range(1, 16):
            admin_users_info.append({'name': f'adm{i}', 'email': f'adm{i}@oneday.com'})

        admin_users_info.append({'name': 'AdminMaster', 'email': 'adminmaster@oneday.com'})
        admin_users_info.append({'name': 'TestUser', 'email': 'testuser@oneday.com'})

        logins_para_salvar = []
        print("Iniciando criação/verificação de usuários administradores e salvando em arquivo...")

        # O loop agora funciona para todos, pois todos têm a chave 'email'
        for user_data in admin_users_info:
            username = user_data['name']
            email = user_data['email']

            password = generate_random_password(length=8)

            user_exists = User.query.filter_by(username=username).first()
            if not user_exists:
                admin_user = User(username=username, email=email, is_admin=True)
                admin_user.set_password(password)
                db.session.add(admin_user)
                db.session.commit()
                print(f'Usuário admin "{username}" criado com sucesso.')

            logins_para_salvar.append({'username': username, 'email': email, 'password': password})

        # O resto da sua função para salvar o .txt continua igual e correta
        output_file_name = 'admin_logins.txt'
        output_file_path = os.path.join(os.path.dirname(__file__), output_file_name)

        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.write("--- Logins e Senhas dos Administradores ---\n\n")
            for login_info in logins_para_salvar:
                file.write(f"Username: {login_info['username']}\n")
                file.write(f"Email:    {login_info['email']}\n")
                file.write(f"Password: {login_info['password']}\n")
                file.write("----------------------------------------\n")

        print(f"\nCriação/verificação de administradores concluída.")
        print(f"Logins salvos em: {output_file_path}")


if __name__ == '__main__':
    create_multiple_admins()