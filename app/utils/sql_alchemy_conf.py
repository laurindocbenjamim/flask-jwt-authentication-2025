
import os
class SqlAchemyConfig:
    #SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///development.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False