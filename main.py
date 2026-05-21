import os
from datetime import datetime, timedelta
from io import BytesIO
import base64
import asyncio
from typing import Any, List, Optional

import jwt
import face_recognition
import cv2
import numpy as np
from bson.objectid import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel
from PIL import Image

from database import db

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("Aviso Crítico: JWT_SECRET_KEY não foi encontrada no arquivo .env!")

ALGORITHM = "HS256"
TOKEN_EXPIRACAO_MINUTOS = 60 * 8
ROLES_VALIDOS = {"admin", "funcionario"}
security = HTTPBearer()
security_opcional = HTTPBearer(auto_error=False)

app = FastAPI(title="API - VERIFIQ OS", description="Motor principal do sistema de gestão e segurança.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "Authorization", "Content-Type"],
)

# Middleware para adicionar headers anti-cache
@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def criar_token(usuario_id: str):
    exp = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRACAO_MINUTOS)
    payload = {"usuario_id": usuario_id, "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decodificar_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        usuario_id = payload.get("usuario_id")
        if not usuario_id:
            raise HTTPException(status_code=401, detail="Token inválido: usuário ausente.")
        return usuario_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado. Faça login novamente.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Acesso negado. Token inválido.")


def extrair_token_websocket(websocket: WebSocket) -> str | None:
    """Extrai token JWT do WebSocket em formatos comuns do frontend/proxy."""
    candidatos = [
        websocket.query_params.get("token"),
        websocket.query_params.get("access_token"),
        websocket.query_params.get("jwt"),
        websocket.query_params.get("authorization"),
        websocket.headers.get("authorization"),
    ]

    for token in candidatos:
        if not token:
            continue
        token_limpo = token.strip().strip('"').strip("'")
        if token_limpo.lower().startswith("bearer "):
            token_limpo = token_limpo[7:].strip()
        if token_limpo:
            return token_limpo
    return None


def validar_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return decodificar_token(credentials.credentials)


def validar_object_id(object_id: str, detalhe_erro: str):
    if not ObjectId.is_valid(object_id):
        raise HTTPException(status_code=400, detail=detalhe_erro)
    return ObjectId(object_id)


def buscar_usuario(usuario_id: str):
    object_id = validar_object_id(usuario_id, "ID de usuário inválido.")
    usuario = db["usuarios"].find_one({"_id": object_id})
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    return usuario


def usuario_tem_rosto_cadastrado(usuario_id: str) -> bool:
    return db["rostos_registrados"].find_one({"usuario_id": usuario_id}) is not None


def obter_admin_da_empresa(usuario_id: str):
    usuario = buscar_usuario(usuario_id)
    if usuario.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Somente admin pode realizar esta operação.")
    empresa_id = usuario.get("empresa_id")
    if not empresa_id:
        raise HTTPException(status_code=400, detail="Admin sem empresa vinculada.")
    return usuario


def garantir_acesso_chat(chat_id: str, usuario_id: str):
    object_id = validar_object_id(chat_id, "ID de chat inválido.")
    chat = db["chats"].find_one({"_id": object_id})
    if not chat:
        raise HTTPException(status_code=404, detail="Chat não encontrado.")
    if usuario_id not in chat.get("participantes_ids", []):
        raise HTTPException(status_code=403, detail="Você não participa deste chat.")
    return chat


@app.get("/")
def home():
    return {"status": "API online e rodando perfeitamente!"}


@app.get("/verificar-token")
def verificar_token(usuario_id: str = Depends(validar_token)):
    """Endpoint para verificar se o token é válido"""
    usuario = buscar_usuario(usuario_id)
    return {
        "valido": True,
        "usuario_id": usuario_id,
        "nome": usuario.get("nome"),
        "email": usuario.get("email"),
        "role": usuario.get("role"),
        "tem_rosto": usuario_tem_rosto_cadastrado(usuario_id),
    }


class UsuarioCadastro(BaseModel):
    nome: str
    email: str
    senha: str
    empresa_id: str
    role: str = "funcionario"


class UsuarioLogin(BaseModel):
    email: str
    senha: str


class StatusCamera(BaseModel):
    status: str


class Tarefa(BaseModel):
    titulo: str
    descricao: str
    status: str = "A Fazer"
    usuario_id: str


class AtualizarStatus(BaseModel):
    status: str


class EditarTextoTarefa(BaseModel):
    titulo: str
    descricao: str


class RelatorioDiario(BaseModel):
    resumo_dia: str
    atividades_realizadas: list[str]
    dificuldades: str | None = None
    proxima_meta: str | None = None


class CriarChatPayload(BaseModel):
    nome_chat: str
    funcionarios_ids: list[str]


class MensagemChat(BaseModel):
    chat_id: str
    mensagem: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def gerar_hash_senha(senha: str):
    return pwd_context.hash(senha)


def verificar_senha(senha_plana: str, senha_hash: str):
    return pwd_context.verify(senha_plana, senha_hash)


@app.post("/cadastro", status_code=201)
def cadastrar_usuario(
    usuario: UsuarioCadastro,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_opcional),
):
    total_usuarios = db["usuarios"].count_documents({})
    admin_autenticado = None

    if total_usuarios > 0:
        if not credentials:
            raise HTTPException(status_code=401, detail="Somente admin autenticado pode cadastrar usuários.")

        admin_id = decodificar_token(credentials.credentials)
        admin_autenticado = buscar_usuario(admin_id)
        if admin_autenticado.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Somente admin pode cadastrar novos usuários.")

    if total_usuarios == 0 and usuario.role.lower().strip() != "admin":
        raise HTTPException(status_code=400, detail="O primeiro usuário do sistema deve ser admin.")

    usuario_existente = db["usuarios"].find_one({"email": usuario.email})
    if usuario_existente:
        raise HTTPException(status_code=400, detail="Este e-mail já está cadastrado.")

    role_normalizada = usuario.role.lower().strip()
    if role_normalizada not in ROLES_VALIDOS:
        raise HTTPException(status_code=400, detail="Role inválida. Use 'admin' ou 'funcionario'.")

    empresa_id_novo_usuario = usuario.empresa_id.strip()
    if admin_autenticado:
        empresa_id_novo_usuario = admin_autenticado.get("empresa_id")

    novo_usuario = {
        "nome": usuario.nome,
        "email": usuario.email,
        "senha": gerar_hash_senha(usuario.senha),
        "empresa_id": empresa_id_novo_usuario,
        "role": role_normalizada,
    }

    resultado = db["usuarios"].insert_one(novo_usuario)
    return {"mensagem": "Usuário cadastrado com sucesso!", "id_usuario": str(resultado.inserted_id)}


@app.post("/login")
def login(usuario: UsuarioLogin):
    usuario_db = db["usuarios"].find_one({"email": usuario.email})
    if not usuario_db or not verificar_senha(usuario.senha, usuario_db["senha"]):
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")

    id_do_usuario = str(usuario_db["_id"])
    token_jwt = criar_token(id_do_usuario)
    tem_rosto = usuario_tem_rosto_cadastrado(id_do_usuario)
    return {
        "mensagem": "Login realizado com sucesso!",
        "token": token_jwt,
        "usuario": usuario_db["nome"],
        "usuario_id": id_do_usuario,
        "role": usuario_db.get("role", "funcionario"),
        "empresa_id": usuario_db.get("empresa_id"),
        "tem_rosto": tem_rosto,
    }


@app.get("/empresa/funcionarios")
def listar_funcionarios_empresa(usuario_id: str = Depends(validar_token)):
    admin = obter_admin_da_empresa(usuario_id)
    funcionarios = list(
        db["usuarios"].find(
            {"empresa_id": admin["empresa_id"], "role": "funcionario"},
            {"senha": 0},
        )
    )
    return [
        {
            "id_usuario": str(funcionario["_id"]),
            "nome": funcionario["nome"],
            "email": funcionario["email"],
            "empresa_id": funcionario["empresa_id"],
            "role": funcionario["role"],
        }
        for funcionario in funcionarios
    ]


@app.post("/chats", status_code=201)
def criar_chat(payload: CriarChatPayload, usuario_id: str = Depends(validar_token)):
    admin = obter_admin_da_empresa(usuario_id)
    empresa_id_admin = admin["empresa_id"]
    participantes = {usuario_id}

    for funcionario_id in payload.funcionarios_ids:
        funcionario = buscar_usuario(funcionario_id)
        if funcionario.get("empresa_id") != empresa_id_admin:
            raise HTTPException(
                status_code=400,
                detail=f"Funcionário {funcionario.get('nome')} não pertence à empresa do admin.",
            )
        participantes.add(funcionario_id)

    novo_chat = {
        "nome_chat": payload.nome_chat.strip(),
        "empresa_id": empresa_id_admin,
        "admin_id": usuario_id,
        "participantes_ids": list(participantes),
        "criado_em": datetime.utcnow(),
    }
    resultado = db["chats"].insert_one(novo_chat)
    return {"mensagem": "Chat criado com sucesso!", "id_chat": str(resultado.inserted_id)}


@app.get("/chats")
def listar_chats(usuario_id: str = Depends(validar_token)):
    chats_db = list(db["chats"].find({"participantes_ids": usuario_id}))
    return [
        {
            "id_chat": str(chat["_id"]),
            "nome_chat": chat["nome_chat"],
            "empresa_id": chat["empresa_id"],
            "admin_id": chat["admin_id"],
        }
        for chat in chats_db
    ]


@app.post("/tarefas")
def criar_tarefa(tarefa: Tarefa, usuario_id: str = Depends(validar_token)):
    nova_tarefa = tarefa.model_dump()
    nova_tarefa["usuario_id"] = usuario_id
    resultado = db["tarefas"].insert_one(nova_tarefa)
    return {"mensagem": "Tarefa criada!", "id": str(resultado.inserted_id)}


@app.get("/tarefas")
def listar_tarefas(usuario_id: str = Depends(validar_token)):
    tarefas_db = list(db["tarefas"].find({"usuario_id": usuario_id}))
    lista_tarefas = []
    for tarefa in tarefas_db:
        tarefa["_id"] = str(tarefa["_id"])
        lista_tarefas.append(tarefa)
    return lista_tarefas


@app.put("/tarefas/{tarefa_id}")
def atualizar_status_tarefa(tarefa_id: str, atualizacao: AtualizarStatus, usuario_id: str = Depends(validar_token)):
    object_id = validar_object_id(tarefa_id, "ID da tarefa inválido.")
    resultado = db["tarefas"].update_one(
        {"_id": object_id, "usuario_id": usuario_id},
        {"$set": {"status": atualizacao.status}},
    )
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada ou você não tem permissão para alterá-la.")
    return {"mensagem": f"Tarefa movida para: {atualizacao.status}"}


@app.put("/tarefas/editar-texto/{tarefa_id}")
def editar_texto(tarefa_id: str, dados: EditarTextoTarefa, usuario_id: str = Depends(validar_token)):
    object_id = validar_object_id(tarefa_id, "ID da tarefa inválido.")
    resultado = db["tarefas"].update_one(
        {"_id": object_id, "usuario_id": usuario_id},
        {"$set": {"titulo": dados.titulo, "descricao": dados.descricao}},
    )
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada ou sem permissão para editá-la.")
    return {"mensagem": "Texto da tarefa atualizado com sucesso!"}


@app.delete("/tarefas/{tarefa_id}")
def deletar_tarefa(tarefa_id: str, usuario_id: str = Depends(validar_token)):
    object_id = validar_object_id(tarefa_id, "ID da tarefa inválido.")
    resultado = db["tarefas"].delete_one({"_id": object_id, "usuario_id": usuario_id})
    if resultado.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada ou você não tem permissão para excluí-la.")
    return {"mensagem": "Tarefa excluída com sucesso!"}


@app.post("/relatorios-diarios", status_code=201)
def salvar_relatorio_diario(relatorio: RelatorioDiario, usuario_id: str = Depends(validar_token)):
    hoje = datetime.utcnow()
    novo_relatorio = {
        "usuario_id": usuario_id,
        "resumo_dia": relatorio.resumo_dia,
        "atividades_realizadas": relatorio.atividades_realizadas,
        "dificuldades": relatorio.dificuldades,
        "proxima_meta": relatorio.proxima_meta,
        "dia": hoje.day,
        "mes": hoje.month,
        "ano": hoje.year,
        "data_criacao": hoje,
    }
    resultado = db["relatorios_diarios"].insert_one(novo_relatorio)
    return {"mensagem": "Relatório diário salvo com sucesso!", "id_relatorio": str(resultado.inserted_id)}


class GerenciadorDeConexoes:
    def __init__(self):
        self.salas: dict[str, list[WebSocket]] = {}

    async def conectar(self, chat_id: str, websocket: WebSocket):
        await websocket.accept()
        if chat_id not in self.salas:
            self.salas[chat_id] = []
        self.salas[chat_id].append(websocket)

    def desconectar(self, chat_id: str, websocket: WebSocket):
        if chat_id not in self.salas:
            return
        if websocket in self.salas[chat_id]:
            self.salas[chat_id].remove(websocket)
        if not self.salas[chat_id]:
            del self.salas[chat_id]

    async def enviar_mensagem_chat(self, chat_id: str, mensagem: str):
        if chat_id not in self.salas:
            return
        for conexao in self.salas[chat_id]:
            await conexao.send_text(mensagem)


gerenciador_chat = GerenciadorDeConexoes()

import asyncio
from typing import Any, List, Optional

# Paths configuráveis via .env (usados pelo frontend)
API_PATH_GALERIA = os.getenv("API_PATH_GALERIA", "/faces/galeria")
API_PATH_CAMERA_STATUS = os.getenv("API_PATH_CAMERA_STATUS", "/cameras/status")
API_PATH_ALERTA = os.getenv("API_PATH_ALERTA", "/seguranca/alerta")
API_PATH_PONTO = os.getenv("API_PATH_PONTO", "/ponto")

# Timeout padrão (em segundos) para operações externas/DB. Força intervalo entre 15 e 45s.
API_TIMEOUT_SECONDS = int(os.getenv("API_TIMEOUT_SECONDS", "30"))
if API_TIMEOUT_SECONDS < 15:
    API_TIMEOUT_SECONDS = 15
if API_TIMEOUT_SECONDS > 45:
    API_TIMEOUT_SECONDS = 45

MOTIVOS_BLOQUEIO = {"rosto_desconhecido", "multiplas_pessoas", "deteccao_intruso"}


def _iso_or_none(valor: Optional[datetime]) -> Optional[str]:
    if not isinstance(valor, datetime):
        return None
    return valor.isoformat()


class FaceItem(BaseModel):
    usuario_id: Any
    nome: str
    embedding: List[float]


class AlertaPayload(BaseModel):
    motivo: str
    faces_detectadas: int
    score: Optional[float] = None
    usuario_id_reconhecido: Optional[str] = None


class DesbloquearSegurancaPayload(BaseModel):
    observacao: Optional[str] = None


class PontoPayload(BaseModel):
    tipo: str
    score_reconhecimento: Optional[float] = None
    usuario_id_reconhecido: Optional[str] = None


class CadastrarRostoPayload(BaseModel):
    """Payload para registrar rosto do usuário"""
    imagem_base64: str


class VerificarRostoPayload(BaseModel):
    """Payload para verificar um rosto contra a galeria"""
    imagem_base64: str
    limiar_confianca: float = 0.6


class RegistroPontoComRostoPayload(BaseModel):
    """Payload para registrar ponto com reconhecimento facial"""
    tipo: str  # "entrada" ou "saída"
    imagem_base64: str
    limiar_confianca: float = 0.6


# Funções auxiliares para reconhecimento facial
def extrair_embedding_de_imagem(imagem_bytes: bytes) -> Optional[np.ndarray]:
    """Extrai embedding facial de uma imagem em bytes. Retorna None se nenhuma face for detectada."""
    try:
        imagem_np = np.frombuffer(imagem_bytes, np.uint8)
        imagem_cv = cv2.imdecode(imagem_np, cv2.IMREAD_COLOR)
        if imagem_cv is None:
            return None
        
        # Converter de BGR para RGB
        imagem_rgb = cv2.cvtColor(imagem_cv, cv2.COLOR_BGR2RGB)
        
        # Detectar faces e extrair embeddings
        encodings = face_recognition.face_encodings(imagem_rgb)
        
        if len(encodings) == 0:
            return None
        
        # Retornar o primeiro encoding encontrado
        return encodings[0]
    except Exception as e:
        print(f"[ERRO EMBEDDING] {str(e)}")
        return None


def converter_base64_para_bytes(imagem_base64: str) -> Optional[bytes]:
    """Converte string base64 para bytes."""
    try:
        # Remover prefixo data:image se existir
        if imagem_base64.startswith("data:image"):
            imagem_base64 = imagem_base64.split(",")[1]
        return base64.b64decode(imagem_base64)
    except Exception as e:
        print(f"[ERRO DECODIFICACAO BASE64] {str(e)}")
        return None


def comparar_faces(embedding_capturado: np.ndarray, embeddings_galeria: List[List[float]]) -> tuple[Optional[str], float]:
    """
    Compara embedding capturado com galeria de rostos.
    Retorna (usuario_id ou None, maior_confianca).
    Confiança varia de 0 (idêntico) a 1 (completamente diferente).
    """
    if not embeddings_galeria or len(embeddings_galeria) == 0:
        return None, 1.0
    
    try:
        distancias = face_recognition.face_distance(embeddings_galeria, embedding_capturado)
        
        if len(distancias) == 0:
            return None, 1.0
        
        # Encontrar o melhor match (menor distância = maior confiança)
        indice_melhor = np.argmin(distancias)
        confianca_em_distancia = distancias[indice_melhor]
        
        return indice_melhor, confianca_em_distancia
    except Exception as e:
        print(f"[ERRO COMPARACAO FACES] {str(e)}")
        return None, 1.0


@app.get(API_PATH_GALERIA)
async def listar_galeria(usuario_id: str = Depends(validar_token)):
    """Retorna a galeria de faces autorizadas para a empresa do usuário autenticado."""
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")

    try:
        def _db_query():
            # busca por empresa se coleção possuir esse campo
            filtro = {"empresa_id": empresa_id} if empresa_id else {}
            return list(db["rostos_registrados"].find(filtro))

        faces_db = await asyncio.wait_for(asyncio.to_thread(_db_query), timeout=API_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Timeout ao buscar galeria de faces.")
    except Exception:
        raise HTTPException(status_code=500, detail="Erro interno ao buscar galeria de faces.")

    faces = []
    for f in faces_db:
        faces.append({
            "usuario_id": str(f.get("usuario_id") or f.get("_id")),
            "nome": f.get("nome"),
            "embedding": f.get("embedding", []),
        })

    return {"galeria": faces}


@app.get("/rosto/estado")
def estado_rosto(usuario_id: str = Depends(validar_token)):
    usuario = buscar_usuario(usuario_id)
    return {
        "usuario_id": usuario_id,
        "tem_rosto": usuario_tem_rosto_cadastrado(usuario_id),
        "nome": usuario.get("nome"),
        "email": usuario.get("email"),
    }


@app.post(API_PATH_CAMERA_STATUS)
async def registrar_status_camera(payload: StatusCamera, usuario_id: str = Depends(validar_token)):
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")

    documento = {
        "usuario_id": usuario_id,
        "empresa_id": empresa_id,
        "status": payload.status,
        "criado_em": datetime.utcnow(),
    }

    try:
        resultado = await asyncio.wait_for(asyncio.to_thread(lambda: db["camera_status"].insert_one(documento)), timeout=API_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Timeout ao registrar status da câmera.")
    except Exception:
        raise HTTPException(status_code=500, detail="Erro interno ao registrar status da câmera.")

    return {"ok": True, "id": str(resultado.inserted_id)}


@app.post(API_PATH_ALERTA)
async def registrar_alerta(payload: AlertaPayload, usuario_id: str = Depends(validar_token)):
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")

    documento = {
        "motivo": payload.motivo,
        "faces_detectadas": payload.faces_detectadas,
        "score": payload.score,
        "usuario_id_reconhecido": payload.usuario_id_reconhecido,
        "registrado_por": usuario_id,
        "empresa_id": empresa_id,
        "criado_em": datetime.utcnow(),
    }

    def _registrar_alerta_db() -> str:
        resultado = db["alertas"].insert_one(documento)

        if payload.motivo in MOTIVOS_BLOQUEIO and empresa_id:
            db["security_state"].update_one(
                {"empresa_id": empresa_id},
                {
                    "$set": {
                        "empresa_id": empresa_id,
                        "bloqueio_ativo": True,
                        "motivo": payload.motivo,
                        "ultimo_alerta_em": datetime.utcnow(),
                        "ultimo_alerta_por": usuario_id,
                        "desbloqueado_em": None,
                        "desbloqueado_por": None,
                    }
                },
                upsert=True,
            )

        return str(resultado.inserted_id)

    try:
        alerta_id = await asyncio.wait_for(asyncio.to_thread(_registrar_alerta_db), timeout=API_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Timeout ao registrar alerta de segurança.")
    except Exception:
        raise HTTPException(status_code=500, detail="Erro interno ao registrar alerta de segurança.")

    return {"ok": True, "id": alerta_id}


@app.get("/seguranca/estado")
async def obter_estado_seguranca(usuario_id: str = Depends(validar_token)):
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")

    if not empresa_id:
        return {
            "empresa_id": None,
            "bloqueio_ativo": False,
            "motivo": None,
            "ultimo_alerta_em": None,
            "desbloqueado_em": None,
            "desbloqueado_por": None,
        }

    try:
        estado = await asyncio.wait_for(
            asyncio.to_thread(lambda: db["security_state"].find_one({"empresa_id": empresa_id})),
            timeout=API_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Timeout ao consultar estado de segurança.")
    except Exception:
        raise HTTPException(status_code=500, detail="Erro interno ao consultar estado de segurança.")

    estado = estado or {}
    return {
        "empresa_id": empresa_id,
        "bloqueio_ativo": bool(estado.get("bloqueio_ativo", False)),
        "motivo": estado.get("motivo"),
        "ultimo_alerta_em": _iso_or_none(estado.get("ultimo_alerta_em")),
        "ultimo_alerta_por": estado.get("ultimo_alerta_por"),
        "desbloqueado_em": _iso_or_none(estado.get("desbloqueado_em")),
        "desbloqueado_por": estado.get("desbloqueado_por"),
    }


@app.post("/seguranca/desbloquear")
async def desbloquear_seguranca(
    payload: DesbloquearSegurancaPayload,
    usuario_id: str = Depends(validar_token),
):
    usuario = buscar_usuario(usuario_id)
    if usuario.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Somente admin pode desbloquear a segurança.")

    empresa_id = usuario.get("empresa_id")
    if not empresa_id:
        raise HTTPException(status_code=400, detail="Admin sem empresa vinculada.")

    def _desbloquear_db() -> None:
        db["security_state"].update_one(
            {"empresa_id": empresa_id},
            {
                "$set": {
                    "empresa_id": empresa_id,
                    "bloqueio_ativo": False,
                    "desbloqueado_em": datetime.utcnow(),
                    "desbloqueado_por": usuario_id,
                    "observacao": payload.observacao,
                }
            },
            upsert=True,
        )

    try:
        await asyncio.wait_for(asyncio.to_thread(_desbloquear_db), timeout=API_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Timeout ao desbloquear estado de segurança.")
    except Exception:
        raise HTTPException(status_code=500, detail="Erro interno ao desbloquear segurança.")

    return {"ok": True, "mensagem": "Segurança desbloqueada com sucesso."}


@app.post(API_PATH_PONTO)
async def registrar_ponto(payload: PontoPayload, usuario_id: str = Depends(validar_token)):
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")

    if payload.tipo not in {"entrada", "saída", "saida"}:
        raise HTTPException(status_code=400, detail="Tipo de ponto inválido. Use 'entrada' ou 'saída'.")

    documento = {
        "tipo": payload.tipo,
        "score_reconhecimento": payload.score_reconhecimento,
        "usuario_id_reconhecido": payload.usuario_id_reconhecido,
        "registrado_por": usuario_id,
        "empresa_id": empresa_id,
        "criado_em": datetime.utcnow(),
    }

    try:
        await asyncio.wait_for(asyncio.to_thread(lambda: db["pontos"].insert_one(documento)), timeout=API_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Timeout ao registrar ponto.")
    except Exception:
        raise HTTPException(status_code=500, detail="Erro interno ao registrar ponto.")

    return {"ok": True}



@app.post("/chat/mensagens", status_code=201)
async def enviar_mensagem_chat(payload: MensagemChat, usuario_id: str = Depends(validar_token)):
    try:
        chat = garantir_acesso_chat(payload.chat_id, usuario_id)
        usuario = buscar_usuario(usuario_id)
    except HTTPException as e:
        print(f"[ERRO AUTENTICAÇÃO] {e.detail}")
        raise
    
    mensagem_limpa = payload.mensagem.strip()
    if not mensagem_limpa:
        raise HTTPException(status_code=400, detail="A mensagem não pode ser vazia.")

    try:
        nova_mensagem = {
            "chat_id": payload.chat_id,
            "usuario_id": usuario_id,
            "nome_usuario": usuario["nome"],
            "mensagem": mensagem_limpa,
            "data_envio": datetime.utcnow(),
            "empresa_id": chat["empresa_id"],
        }
        resultado = db["mensagens_chat"].insert_one(nova_mensagem)

        mensagem_formatada = f"{usuario['nome']}: {mensagem_limpa}"
        await gerenciador_chat.enviar_mensagem_chat(payload.chat_id, mensagem_formatada)

        return {
            "mensagem": "Mensagem enviada com sucesso!",
            "id_mensagem": str(resultado.inserted_id),
            "texto_exibicao": mensagem_formatada,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        print(f"[ERRO ENVIO MENSAGEM] {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao enviar mensagem: {str(e)}")


@app.get("/chat/mensagens")
def listar_mensagens_chat(chat_id: str, limite: int = 50, usuario_id: str = Depends(validar_token)):
    garantir_acesso_chat(chat_id, usuario_id)
    if limite < 1 or limite > 200:
        raise HTTPException(status_code=400, detail="O limite deve estar entre 1 e 200.")

    mensagens_db = list(
        db["mensagens_chat"]
        .find({"chat_id": chat_id})
        .sort("data_envio", -1)
        .limit(limite)
    )
    mensagens_db.reverse()

    mensagens = []
    for msg in mensagens_db:
        mensagens.append(
            {
                "id_mensagem": str(msg["_id"]),
                "chat_id": msg["chat_id"],
                "usuario_id": msg["usuario_id"],
                "nome_usuario": msg["nome_usuario"],
                "mensagem": msg["mensagem"],
                "data_envio": msg["data_envio"],
            }
        )
    return mensagens


@app.websocket("/ws/chat/{chat_id}")
async def websocket_chat(websocket: WebSocket, chat_id: str):
    token = extrair_token_websocket(websocket)
    if not token:
        print(f"[WEBSOCKET ERRO] Sem token para chat {chat_id}")
        await websocket.close(code=1008, reason="Token obrigatório.")
        return

    try:
        usuario_id = decodificar_token(token)
        chat = garantir_acesso_chat(chat_id, usuario_id)
        usuario = buscar_usuario(usuario_id)
        print(f"[WEBSOCKET CONECTADO] Usuário {usuario['nome']} - Chat {chat_id}")
    except HTTPException as erro:
        print(f"[WEBSOCKET ERRO AUTENTICAÇÃO] {erro.detail}")
        await websocket.close(code=1008, reason=erro.detail)
        return
    except Exception as e:
        print(f"[WEBSOCKET ERRO] {str(e)}")
        await websocket.close(code=1008, reason=f"Erro: {str(e)}")
        return

    await gerenciador_chat.conectar(chat_id, websocket)
    nome_usuario = usuario["nome"]

    try:
        await gerenciador_chat.enviar_mensagem_chat(chat_id, f"{nome_usuario} entrou no chat.")

        while True:
            mensagem_recebida = (await websocket.receive_text()).strip()
            if not mensagem_recebida:
                continue

            db["mensagens_chat"].insert_one(
                {
                    "chat_id": chat_id,
                    "usuario_id": usuario_id,
                    "nome_usuario": nome_usuario,
                    "mensagem": mensagem_recebida,
                    "data_envio": datetime.utcnow(),
                    "empresa_id": chat["empresa_id"],
                }
            )
            await gerenciador_chat.enviar_mensagem_chat(chat_id, f"{nome_usuario}: {mensagem_recebida}")

    except WebSocketDisconnect:
        gerenciador_chat.desconectar(chat_id, websocket)
        await gerenciador_chat.enviar_mensagem_chat(chat_id, f"{nome_usuario} saiu do chat.")
        print(f"[WEBSOCKET DESCONECTADO] {nome_usuario} - Chat {chat_id}")
    except Exception as e:
        print(f"[WEBSOCKET ERRO RUNTIME] {str(e)}")
        gerenciador_chat.desconectar(chat_id, websocket)

@app.delete("/chats/{chat_id}")
def deletar_chat(chat_id: str, usuario_id: str = Depends(validar_token)):
    # 1. Garante que só o Admin da empresa pode excluir chats
    admin = obter_admin_da_empresa(usuario_id)
    object_id = validar_object_id(chat_id, "ID de chat inválido.")
    
    # 2. Deleta todas as mensagens que pertenciam a esse chat para não lotar o banco
    db["mensagens_chat"].delete_many({"chat_id": chat_id})
    
    # 3. Deleta o chat em si
    resultado = db["chats"].delete_one({"_id": object_id, "empresa_id": admin["empresa_id"]})
    
    if resultado.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Chat não encontrado ou você não tem permissão.")
        
    return {"mensagem": "Chat e mensagens excluídos com sucesso!"}
@app.post("/cameras/status")
async def registrar_status_camera(status: StatusCamera, usuario_id: str = Depends(validar_token)):
    db["status_cameras"].insert_one(
        {"usuario_id": usuario_id, "status": status.status, "timestamp": datetime.utcnow()}
    )

    log_db = {"usuario_id": usuario_id, "status": status.status, "timestamp": datetime.utcnow()}
    db["logs_camera"].insert_one(log_db)

    if status.status == "LIGADA":
        mensagem_alerta = f"[sistema] Alerta: A câmera foi LIGADA pelo usuário {usuario_id[-4:]}!"
    else:
        mensagem_alerta = f"[sistema] Alerta: A câmera foi DESLIGADA pelo usuário {usuario_id[-4:]}!"

    return {"mensagem": "Status da câmera registrado com sucesso!", "alerta": mensagem_alerta}


# ============================================================================
# ENDPOINTS DE RECONHECIMENTO FACIAL - CADASTRO, VERIFICAÇÃO E PONTO
# ============================================================================

@app.post("/rosto/cadastrar", status_code=201)
async def cadastrar_rosto_usuario(payload: CadastrarRostoPayload, usuario_id: str = Depends(validar_token)):
    """
    Cadastra o rosto do usuário a partir de uma imagem em base64.
    Armazena apenas um embedding por usuário (atualiza se já existir).
    """
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")
    
    # Converter base64 para bytes
    imagem_bytes = converter_base64_para_bytes(payload.imagem_base64)
    if not imagem_bytes:
        raise HTTPException(status_code=400, detail="Falha ao decodificar imagem. Verifique o formato base64.")
    
    # Extrair embedding
    embedding = extrair_embedding_de_imagem(imagem_bytes)
    if embedding is None:
        raise HTTPException(status_code=400, detail="Nenhuma face detectada na imagem. Tente novamente com uma foto mais clara.")
    
    # Converter embedding numpy para lista para salvar no MongoDB
    embedding_lista = embedding.tolist()
    
    try:
        # Verificar se usuário já tem rosto registrado
        rosto_existente = db["rostos_registrados"].find_one({"usuario_id": usuario_id})
        
        if rosto_existente:
            # Atualizar embedding existente
            db["rostos_registrados"].update_one(
                {"usuario_id": usuario_id},
                {
                    "$set": {
                        "embedding": embedding_lista,
                        "nome": usuario["nome"],
                        "email": usuario["email"],
                        "empresa_id": empresa_id,
                        "atualizado_em": datetime.utcnow(),
                    }
                },
            )
            mensagem = "Rosto cadastrado/atualizado com sucesso!"
        else:
            # Criar novo registro
            resultado = db["rostos_registrados"].insert_one(
                {
                    "usuario_id": usuario_id,
                    "nome": usuario["nome"],
                    "email": usuario["email"],
                    "empresa_id": empresa_id,
                    "embedding": embedding_lista,
                    "criado_em": datetime.utcnow(),
                    "atualizado_em": datetime.utcnow(),
                }
            )
            mensagem = "Rosto cadastrado com sucesso!"
        
        return {
            "mensagem": mensagem,
            "usuario_id": usuario_id,
            "nome_usuario": usuario["nome"],
        }
    except Exception as e:
        print(f"[ERRO CADASTRO ROSTO] {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao cadastrar rosto: {str(e)}")


@app.post("/rosto/verificar")
async def verificar_rosto(payload: VerificarRostoPayload, usuario_id: str = Depends(validar_token)):
    """
    Verifica um rosto capturado contra a galeria de rostos da empresa.
    Retorna o usuário identificado (se confiança acima do limiar) e score de confiança.
    """
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")
    
    # Converter base64 para bytes
    imagem_bytes = converter_base64_para_bytes(payload.imagem_base64)
    if not imagem_bytes:
        raise HTTPException(status_code=400, detail="Falha ao decodificar imagem. Verifique o formato base64.")
    
    # Extrair embedding da imagem capturada
    embedding_capturado = extrair_embedding_de_imagem(imagem_bytes)
    if embedding_capturado is None:
        raise HTTPException(status_code=400, detail="Nenhuma face detectada na imagem capturada.")
    
    try:
        # Buscar rostos registrados da empresa
        rostos_empresa = list(db["rostos_registrados"].find({"empresa_id": empresa_id}))
        
        if not rostos_empresa:
            return {
                "identificado": False,
                "confianca": 1.0,
                "mensagem": "Nenhum rosto registrado na empresa.",
                "usuario_identificado": None,
            }
        
        # Preparar lista de embeddings e mapeamento de índices
        embeddings_galeria = [np.array(rosto["embedding"]) for rosto in rostos_empresa]
        
        # Comparar faces
        indice, distancia = comparar_faces(embedding_capturado, embeddings_galeria)
        
        # Converter distância para confiança (0 = idêntico, 1 = diferente)
        # Considerar match se distância < limiar (padrão 0.6)
        confianca = float(distancia)
        identificado = confianca <= payload.limiar_confianca
        
        resultado = {
            "identificado": identificado,
            "confianca": confianca,
            "limiar_utilizado": payload.limiar_confianca,
            "usuario_identificado": None,
            "nome_usuario": None,
        }
        
        if identificado and indice is not None:
            rosto_match = rostos_empresa[indice]
            resultado["usuario_identificado"] = rosto_match["usuario_id"]
            resultado["nome_usuario"] = rosto_match["nome"]
        
        return resultado
    except Exception as e:
        print(f"[ERRO VERIFICACAO ROSTO] {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao verificar rosto: {str(e)}")


@app.post("/ponto/com-rosto", status_code=201)
async def registrar_ponto_com_rosto(
    payload: RegistroPontoComRostoPayload,
    usuario_id: str = Depends(validar_token),
):
    """
    Registra ponto de entrada/saída com verificação de reconhecimento facial.
    Valida se a face capturada corresponde ao usuário autenticado.
    """
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")
    
    if payload.tipo not in {"entrada", "saída", "saida"}:
        raise HTTPException(status_code=400, detail="Tipo de ponto inválido. Use 'entrada' ou 'saída'.")
    
    # Converter base64 para bytes
    imagem_bytes = converter_base64_para_bytes(payload.imagem_base64)
    if not imagem_bytes:
        raise HTTPException(status_code=400, detail="Falha ao decodificar imagem. Verifique o formato base64.")
    
    # Extrair embedding da imagem capturada
    embedding_capturado = extrair_embedding_de_imagem(imagem_bytes)
    if embedding_capturado is None:
        raise HTTPException(status_code=400, detail="Nenhuma face detectada na imagem capturada.")
    
    try:
        # Buscar rosto registrado do usuário autenticado
        rosto_usuario = db["rostos_registrados"].find_one({"usuario_id": usuario_id})
        
        if not rosto_usuario:
            raise HTTPException(
                status_code=404,
                detail="Usuário não tem rosto cadastrado. Cadastre primeiro em /rosto/cadastrar"
            )
        
        # Comparar com o rosto registrado do usuário
        embedding_registrado = np.array(rosto_usuario["embedding"])
        distancia = face_recognition.face_distance([embedding_registrado], embedding_capturado)[0]
        
        confianca = float(distancia)
        
        # Validar confiança
        if confianca > payload.limiar_confianca:
            raise HTTPException(
                status_code=403,
                detail=f"Rosto não corresponde ao usuário autenticado. Confiança: {confianca:.3f} (limiar: {payload.limiar_confianca})"
            )
        
        # Registrar ponto
        documento_ponto = {
            "tipo": payload.tipo,
            "usuario_id": usuario_id,
            "nome_usuario": usuario["nome"],
            "empresa_id": empresa_id,
            "confianca_facial": confianca,
            "criado_em": datetime.utcnow(),
        }
        
        resultado = db["pontos"].insert_one(documento_ponto)
        
        return {
            "mensagem": "Ponto registrado com sucesso!",
            "tipo": payload.tipo,
            "usuario": usuario["nome"],
            "confianca_facial": confianca,
            "timestamp": datetime.utcnow().isoformat(),
            "id_registro": str(resultado.inserted_id),
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERRO REGISTRO PONTO COM ROSTO] {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao registrar ponto: {str(e)}")


@app.post("/seguranca/detectar-intruso")
async def detectar_intruso(payload: VerificarRostoPayload):
    """
    Sistema de segurança: detecta se a pessoa capturada é um usuário conhecido.
    Usado para alertar sobre estranhos no ambiente.
    NÃO requer autenticação (para que câmeras de segurança possam usar).
    """
    # Converter base64 para bytes
    imagem_bytes = converter_base64_para_bytes(payload.imagem_base64)
    if not imagem_bytes:
        raise HTTPException(status_code=400, detail="Falha ao decodificar imagem. Verifique o formato base64.")
    
    # Extrair embedding da imagem capturada
    embedding_capturado = extrair_embedding_de_imagem(imagem_bytes)
    if embedding_capturado is None:
        return {
            "eh_intruso": True,
            "confianca": 1.0,
            "mensagem": "Nenhuma face detectada. Sistema de segurança ativado!",
            "usuario_identificado": None,
        }
    
    try:
        # Buscar todos os rostos registrados
        todos_rostos = list(db["rostos_registrados"].find({}))
        
        if not todos_rostos:
            return {
                "eh_intruso": True,
                "confianca": 1.0,
                "mensagem": "Nenhum usuário registrado no sistema.",
                "usuario_identificado": None,
            }
        
        # Preparar lista de embeddings
        embeddings_galeria = [np.array(rosto["embedding"]) for rosto in todos_rostos]
        
        # Comparar faces
        indice, distancia = comparar_faces(embedding_capturado, embeddings_galeria)
        
        confianca = float(distancia)
        eh_intruso = confianca > payload.limiar_confianca
        
        resultado = {
            "eh_intruso": eh_intruso,
            "confianca": confianca,
            "limiar_utilizado": payload.limiar_confianca,
            "usuario_identificado": None,
            "nome_usuario": None,
        }
        
        if not eh_intruso and indice is not None:
            rosto_match = todos_rostos[indice]
            resultado["usuario_identificado"] = rosto_match["usuario_id"]
            resultado["nome_usuario"] = rosto_match["nome"]
            resultado["mensagem"] = f"Usuário autorizado identificado: {rosto_match['nome']}"
        else:
            resultado["mensagem"] = "⚠️ ALERTA: ESTRANHO DETECTADO! Pessoa desconhecida no ambiente."
        
        # Registrar alerta se for intruso
        if eh_intruso:
            db["alertas_seguranca"].insert_one(
                {
                    "tipo": "deteccao_intruso",
                    "confianca": confianca,
                    "criado_em": datetime.utcnow(),
                    "estado": "ativo",
                }
            )
        
        return resultado
    except Exception as e:
        print(f"[ERRO DETECCAO INTRUSO] {str(e)}")
        raise HTTPException(status_code=500, detail=f"Erro ao detectar intruso: {str(e)}")


if __name__ == "__main__":
    import uvicorn

    porta = int(os.getenv("PORT", "10000"))
    uvicorn.run("main:app", host="0.0.0.0", port=porta)

