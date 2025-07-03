# ----------------------------------------------------
# ARQUIVO: config.py (VERSÃO FINAL E PERMANENTE)
# ----------------------------------------------------
import os

# Chave secreta do Flask
SECRET_KEY = 'vkexidzlrxtpyarh'

# Credenciais de E-mail
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True
MAIL_USERNAME = 'onedaycampeonato@gmail.com'
MAIL_PASSWORD = 'wzdkomhpczvgokgb' # Senha de App do Gmail

# --- CREDENCIAIS DO DROPBOX (MÉTODO PERMANENTE) ---
# Cole os valores que você obteve nos passos anteriores.
# A App Key e App Secret estão no site do Dropbox.
# O Refresh Token é o que acabamos de gerar.

DROPBOX_APP_KEY = "3uemkxlkebni3jy" # A sua App Key
DROPBOX_APP_SECRET = "yqt7bycxxyscbuh" # A sua App Secret
DROPBOX_REFRESH_TOKEN = "KBMshj6pU6cAAAAAAAAAAUQaAAdFmqvTDUe5AB1hMM1bcQWQSaYZ3Css1CZ7CM9B" # O Refresh Token que você gerou
