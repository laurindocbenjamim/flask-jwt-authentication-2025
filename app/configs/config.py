
import os, secrets
from datetime import timedelta

from .jwt_conf import JwtConfig
from .sql_alchemy_conf import SqlAchemyConfig

class Config(JwtConfig, SqlAchemyConfig):
    PORT = 5000
    SECRET_KEY = os.getenv('SECRET_KEY', 'paaoeAtEpkR5IcoMb6AjISxhpSEz7--1iWoB6QloNjRdjsKrVwlVJGKNM8V5su1humYcrblV01svzoTmXg0e3A')


class ProductionConfig(Config):
    DEBUG = False
    

class DevelopementConfig(Config):
   DEBUG = True
   