#!/usr/bin/env python3
"""Exemplo de script para inserir um documento de face na coleção `faces`.
Uso:
  python scripts/insert_face.py --file face.json
Onde `face.json` é um JSON com:
{
  "usuario_id": "<id_usuario>",
  "nome": "Nome da Pessoa",
  "embedding": [0.123, 0.234, ...],
  "empresa_id": "<empresa_id>"  # opcional
}

Este script usa MONGO_URI do .env.
"""
import os
import json
import argparse
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise SystemExit("MONGO_URI não encontrado no .env")

client = MongoClient(MONGO_URI)
db = client.get_database()

parser = argparse.ArgumentParser()
parser.add_argument("--file", required=True, help="Caminho para JSON com dados da face")
args = parser.parse_args()

with open(args.file, "r", encoding="utf-8") as f:
    payload = json.load(f)

# validações simples
if "nome" not in payload or "embedding" not in payload:
    raise SystemExit("O JSON deve conter pelo menos 'nome' e 'embedding'.")

doc = {
    "usuario_id": payload.get("usuario_id"),
    "nome": payload["nome"],
    "embedding": payload["embedding"],
    "empresa_id": payload.get("empresa_id"),
    "criado_em": __import__("datetime").datetime.utcnow(),
}

res = db["faces"].insert_one(doc)
print("Inserido com id:", str(res.inserted_id))
