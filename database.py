from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

client = None
db = None

try:
    if not MONGO_URI:
        print("AVISO: MONGO_URI não definida no .env!")
    else:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client["home_office_db"]
        client.admin.command('ping')
        print("Conexão com o MongoDB Atlas estabelecida com sucesso!")

except Exception as e:
    print(f"Erro ao inicializar MongoDB: {e}")

