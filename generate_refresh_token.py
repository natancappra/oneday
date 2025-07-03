# generate_refresh_token.py
import requests
import urllib.parse

# --------------------------------------------------------------------------
# PASSO 1: Cole sua App Key e App Secret que você pegou do site do Dropbox
# --------------------------------------------------------------------------
APP_KEY = "3uemkxlkebni3jy"
APP_SECRET = "yqt7bycxxyscbuh"
# --------------------------------------------------------------------------


# Monta a URL de autorização manualmente
params = {
    "client_id": APP_KEY,
    "token_access_type": "offline",
    "response_type": "code",
    "redirect_uri": "http://localhost"  # Adicionado para compatibilidade
}
authorize_url = "https://www.dropbox.com/oauth2/authorize?" + urllib.parse.urlencode(params)

# Imprime a URL no terminal
print("1. Vá para esta URL no seu navegador:", authorize_url)
print("2. Clique em 'Permitir' (você pode ter que fazer login no Dropbox).")
print("3. Você será redirecionado para uma página que não funciona (localhost) - ISSO É NORMAL.")
print("4. Copie o 'código' da URL na barra de endereço do navegador. Ele se parece com 'z4q...AAA'.")

# Pede para o usuário colar o código
auth_code = input("5. Cole o código de autorização aqui e pressione Enter: ").strip()

# Troca o código de autorização pelo refresh token
token_url = "https://api.dropbox.com/oauth2/token"
token_params = {
    "code": auth_code,
    "grant_type": "authorization_code",
    "redirect_uri": "http://localhost"  # Adicionado para compatibilidade
}

try:
    # Faz a requisição direta para a API do Dropbox
    response = requests.post(token_url, data=token_params, auth=(APP_KEY, APP_SECRET))
    response.raise_for_status()  # Lança um erro se a requisição falhar (status != 2xx)

    result = response.json()
    refresh_token = result.get("refresh_token")

    if not refresh_token:
        print("\nERRO: Não foi possível obter o Refresh Token. Verifique suas credenciais e o código de autorização.")
        print("Resposta do Dropbox:", result)
    else:
        # Imprime o refresh token!
        print("\n===================================================================")
        print("SUCESSO! Seu Refresh Token permanente foi gerado.")
        print("Guarde-o com segurança. Você só precisa fazer isso uma vez.")
        print("\nSEU REFRESH TOKEN:")
        print(refresh_token)
        print("\n===================================================================")
        print("\nPróximo passo: Copie este Refresh Token e cole no seu arquivo config.py")

except requests.exceptions.RequestException as e:
    print('Erro de conexão: %s' % (e,))
    if hasattr(e, 'response') and e.response is not None:
        print("Detalhes do erro:", e.response.text)