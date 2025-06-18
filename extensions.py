
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData

# 1. Definimos uma "convenção de nomes" padrão para o banco de dados.
# Isso diz ao Alembic/SQLAlchemy como nomear chaves, índices, etc.
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

# 2. Criamos um objeto de metadados com essa convenção.
metadata = MetaData(naming_convention=convention)

# 3. Inicializamos o SQLAlchemy passando os metadados.
# O render_as_batch=True é crucial para o bom funcionamento com SQLite.
db = SQLAlchemy(metadata=metadata)