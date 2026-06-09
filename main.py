import os
import uuid
from datetime import datetime, timedelta
import asyncio
from typing import Any, List, Optional

import jwt
from bson.objectid import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from database import db
import bcrypt

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "chave-padrao-temporaria")
if os.getenv("JWT_SECRET_KEY") is None:
    print("AVISO: JWT_SECRET_KEY não encontrada no .env. Usando chave padrão!")

ALGORITHM = "HS256"
TOKEN_EXPIRACAO_MINUTOS = 60 * 8
DEVICE_TOKEN_EXPIRACAO_MINUTOS = 60 * 8
DEVICE_HEARTBEAT_TIMEOUT_SECONDS = 75
ROLES_VALIDOS = {"admin", "funcionario"}
security = HTTPBearer()
security_opcional = HTTPBearer(auto_error=False)

app = FastAPI(title="API - VERIFIQ OS", description="Motor principal do sistema de gestão e segurança.")

# Configuração de CORS extremamente permissiva para evitar bloqueios
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/debug-db")
def debug_db():
    """Endpoint para testar a conexão com o banco de dados"""
    try:
        from database import client
        client.admin.command('ping')
        return {"status": "Conexão com MongoDB Atlas OK!"}
    except Exception as e:
        return {"status": "Erro na conexão com MongoDB", "detalhe": str(e)}

# Middleware para adicionar headers anti-cache
@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    try:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    except Exception as e:
        # Se der erro, o FastAPI já vai tratar no exception handler, 
        # mas precisamos garantir que o erro suba se não quisermos tratá-lo aqui
        raise e

@app.exception_handler(Exception)
async def custom_exception_handler(request, exc):
    from fastapi.responses import JSONResponse
    import traceback
    
    # Log do erro no servidor (Render logs)
    print("--- ERRO CAPTURADO ---")
    print(traceback.format_exc())
    print("----------------------")
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Erro interno do servidor", 
            "error_type": type(exc).__name__,
            "error_msg": str(exc)
        },
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        }
    )


def criar_token(usuario_id: str):
    exp = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRACAO_MINUTOS)
    payload = {"usuario_id": usuario_id, "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def criar_token_dispositivo(device_id: str, usuario_id: str, token_version: int):
    exp = datetime.utcnow() + timedelta(minutes=DEVICE_TOKEN_EXPIRACAO_MINUTOS)
    payload = {
        "device_id": device_id,
        "usuario_id": usuario_id,
        "token_type": "device",
        "token_version": token_version,
        "exp": exp,
    }
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


def decodificar_token_dispositivo(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("token_type") != "device":
            raise HTTPException(status_code=401, detail="Token do dispositivo inválido.")

        device_id = payload.get("device_id")
        usuario_id = payload.get("usuario_id")
        if not device_id or not usuario_id:
            raise HTTPException(status_code=401, detail="Token do dispositivo incompleto.")

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token do dispositivo expirado. Renove o vínculo.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Acesso negado. Token do dispositivo inválido.")


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


def validar_token_dispositivo(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = decodificar_token_dispositivo(credentials.credentials)
    dispositivo = db["desktop_devices"].find_one(
        {"device_id": payload["device_id"], "usuario_id": payload["usuario_id"]}
    )
    if not dispositivo:
        raise HTTPException(status_code=401, detail="Dispositivo não encontrado.")

    if int(dispositivo.get("token_version", 0)) != int(payload.get("token_version", -1)):
        raise HTTPException(status_code=401, detail="Token do dispositivo desatualizado.")

    return payload


def validar_object_id(object_id: str, detalhe_erro: str):
    if not ObjectId.is_valid(object_id):
        raise HTTPException(status_code=400, detail=detalhe_erro)
    return ObjectId(object_id)


def _to_datetime(valor: Any) -> Optional[datetime]:
    if isinstance(valor, datetime):
        return valor
    if isinstance(valor, str):
        texto = valor.strip()
        if not texto:
            return None
        try:
            if texto.endswith("Z"):
                texto = texto[:-1] + "+00:00"
            return datetime.fromisoformat(texto)
        except ValueError:
            return None
    return None


def _esta_online(ultimo_heartbeat: Any) -> bool:
    instante = _to_datetime(ultimo_heartbeat)
    if not instante:
        return False
    return (datetime.utcnow() - instante.replace(tzinfo=None)).total_seconds() <= DEVICE_HEARTBEAT_TIMEOUT_SECONDS


def _novo_device_id() -> str:
    return uuid.uuid4().hex


def buscar_dispositivo_do_usuario(usuario_id: str):
    dispositivo = db["desktop_devices"].find_one({"usuario_id": usuario_id})
    return dispositivo if isinstance(dispositivo, dict) else None


def _serializar_dispositivo(dispositivo: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(dispositivo, dict) or not dispositivo:
        return {
            "pareado": False,
            "dispositivo": None,
            "conectado": False,
            "monitorando": False,
            "estado": "desconectado",
            "ultimo_heartbeat_em": None,
        }

    online = _esta_online(dispositivo.get("last_heartbeat_at"))
    monitoring_state = str(dispositivo.get("monitoring_state") or "idle").strip().lower()
    monitorando = online and monitoring_state in {"monitoring", "on", "ativo", "active"}
    estado = "monitorando" if monitorando else ("conectado" if online else "desconectado")

    return {
        "pareado": True,
        "dispositivo": {
            "device_id": dispositivo.get("device_id"),
            "device_name": dispositivo.get("device_name") or dispositivo.get("hostname"),
            "hostname": dispositivo.get("hostname"),
            "machine": dispositivo.get("machine"),
            "os_name": dispositivo.get("os_name"),
            "agent_version": dispositivo.get("agent_version"),
        },
        "conectado": online,
        "monitorando": monitorando,
        "estado": estado,
        "ultimo_heartbeat_em": _iso_or_none(_to_datetime(dispositivo.get("last_heartbeat_at"))),
        "ultimo_comando_em": _iso_or_none(_to_datetime(dispositivo.get("last_command_at"))),
        "token_expires_em": _iso_or_none(_to_datetime(dispositivo.get("token_expires_at"))),
    }


def _gerar_comando(device_id: str, usuario_id: str, acao: str, payload: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {
        "command_id": uuid.uuid4().hex,
        "device_id": device_id,
        "usuario_id": usuario_id,
        "action": acao,
        "payload": payload or {},
        "status": "pending",
        "created_at": datetime.utcnow(),
        "executed_at": None,
    }


def _enfileirar_start_monitoring(device: dict[str, Any], usuario_id: str) -> Optional[dict[str, Any]]:
    device_id = str(device.get("device_id") or "").strip()
    if not device_id:
        return None

    comando_existente = db["desktop_device_commands"].find_one(
        {
            "device_id": device_id,
            "usuario_id": usuario_id,
            "action": "START_MONITORING",
            "status": "pending",
        }
    )
    if comando_existente:
        return None

    monitoring_state = str(device.get("monitoring_state") or "idle").strip().lower()
    if monitoring_state == "monitoring" and _esta_online(device.get("last_heartbeat_at")):
        return None

    comando = _gerar_comando(device_id, usuario_id, "START_MONITORING", {"source": "login"})
    db["desktop_device_commands"].insert_one(comando)
    db["desktop_devices"].update_one(
        {"device_id": device_id, "usuario_id": usuario_id},
        {
            "$set": {
                "desired_state": "monitoring",
                "monitoring_state": "starting",
                "last_command_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }
        },
    )
    return comando


def _rotacionar_token_dispositivo(dispositivo: dict[str, Any]) -> tuple[str, datetime, int]:
    token_version = int(dispositivo.get("token_version", 0)) + 1
    token = criar_token_dispositivo(dispositivo["device_id"], dispositivo["usuario_id"], token_version)
    expira_em = datetime.utcnow() + timedelta(minutes=DEVICE_TOKEN_EXPIRACAO_MINUTOS)
    db["desktop_devices"].update_one(
        {"device_id": dispositivo["device_id"], "usuario_id": dispositivo["usuario_id"]},
        {
            "$set": {
                "token_version": token_version,
                "token_expires_at": expira_em,
                "updated_at": datetime.utcnow(),
            }
        },
    )
    return token, expira_em, token_version


def _resposta_dispositivo(dispositivo: dict[str, Any], comando_criado: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    payload = _serializar_dispositivo(dispositivo)
    payload.update(
        {
            "device_id": dispositivo.get("device_id"),
            "agent_version": dispositivo.get("agent_version"),
            "agent_token": None,
            "paired_at": _iso_or_none(_to_datetime(dispositivo.get("paired_at"))),
        }
    )
    if comando_criado:
        payload["pending_command_id"] = comando_criado.get("command_id")
    return payload


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


class DesktopDeviceRegister(BaseModel):
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    hostname: Optional[str] = None
    machine: Optional[str] = None
    os_name: Optional[str] = None
    agent_version: Optional[str] = None


class DesktopDeviceHeartbeat(BaseModel):
    device_id: str
    agent_version: Optional[str] = None
    monitoring_state: Optional[str] = None
    monitoring_active: Optional[bool] = None
    last_command_id: Optional[str] = None


class DesktopDeviceCommandAck(BaseModel):
    command_id: str
    result: Optional[dict[str, Any]] = None


def gerar_hash_senha(senha: str) -> str:
    """Gera hash da senha usando bcrypt diretamente, garantindo limite de 72 bytes."""
    senha_bytes = senha.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(senha_bytes, salt).decode('utf-8')


def verificar_senha(senha_plana: str, senha_hash: str) -> bool:
    """Verifica a senha usando bcrypt diretamente, garantindo limite de 72 bytes."""
    try:
        if not senha_hash:
            return False
        senha_plana_bytes = senha_plana.encode('utf-8')[:72]
        senha_hash_bytes = senha_hash.encode('utf-8')
        return bcrypt.checkpw(senha_plana_bytes, senha_hash_bytes)
    except Exception as e:
        print(f"Erro na verificação do Bcrypt manual: {e}")
        return False


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
    try:
        if db is None:
            raise HTTPException(status_code=500, detail="Banco de dados não conectado.")
            
        usuario_db = db["usuarios"].find_one({"email": usuario.email})
        
        if not usuario_db:
            raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")

        try:
            senha_valida = verificar_senha(usuario.senha, usuario_db.get("senha", ""))
        except Exception as e:
            print(f"Erro ao verificar senha: {e}")
            raise HTTPException(status_code=500, detail=f"Erro na verificação de senha: {str(e)}")

        if not senha_valida:
            raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")

        id_do_usuario = str(usuario_db["_id"])
        token_jwt = criar_token(id_do_usuario)
        tem_rosto = usuario_tem_rosto_cadastrado(id_do_usuario)
        dispositivo = buscar_dispositivo_do_usuario(id_do_usuario)
        agente_desktop = _serializar_dispositivo(dispositivo)

        if dispositivo:
            _enfileirar_start_monitoring(dispositivo, id_do_usuario)
        
        return {
            "mensagem": "Login realizado com sucesso!",
            "token": token_jwt,
            "usuario": usuario_db.get("nome", "Usuário"),
            "usuario_id": id_do_usuario,
            "role": usuario_db.get("role", "funcionario"),
            "empresa_id": usuario_db.get("empresa_id"),
            "tem_rosto": tem_rosto,
            "agente_desktop": agente_desktop,
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Erro interno no login: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno no servidor: {str(e)}")


@app.post("/desktop/devices/register")
def registrar_dispositivo_desktop(
    payload: DesktopDeviceRegister,
    usuario_id: str = Depends(validar_token),
):
    usuario = buscar_usuario(usuario_id)
    device_id = (payload.device_id or _novo_device_id()).strip()
    if not device_id:
        raise HTTPException(status_code=400, detail="device_id inválido.")

    existente = db["desktop_devices"].find_one({"device_id": device_id})
    if existente and existente.get("usuario_id") != usuario_id:
        raise HTTPException(status_code=403, detail="Este dispositivo já está pareado com outra conta.")

    agora = datetime.utcnow()
    token_version = int(existente.get("token_version", 0)) + 1 if existente else 1
    token_dispositivo = criar_token_dispositivo(device_id, usuario_id, token_version)
    documento = {
        "device_id": device_id,
        "usuario_id": usuario_id,
        "empresa_id": usuario.get("empresa_id"),
        "device_name": (payload.device_name or payload.hostname or usuario.get("nome") or "Desktop VERIFIQ").strip(),
        "hostname": payload.hostname,
        "machine": payload.machine,
        "os_name": payload.os_name,
        "agent_version": payload.agent_version or (existente.get("agent_version") if existente else None),
        "paired_at": existente.get("paired_at") if existente else agora,
        "last_heartbeat_at": existente.get("last_heartbeat_at") if existente else None,
        "last_command_at": existente.get("last_command_at") if existente else None,
        "monitoring_state": existente.get("monitoring_state") if existente else "idle",
        "desired_state": existente.get("desired_state") if existente else "idle",
        "token_version": token_version,
        "token_expires_at": agora + timedelta(minutes=DEVICE_TOKEN_EXPIRACAO_MINUTOS),
        "updated_at": agora,
    }

    db["desktop_devices"].update_one(
        {"device_id": device_id},
        {"$set": documento, "$setOnInsert": {"created_at": agora}},
        upsert=True,
    )
    dispositivo = db["desktop_devices"].find_one({"device_id": device_id})
    if not dispositivo:
        raise HTTPException(status_code=500, detail="Não foi possível registrar o dispositivo.")

    resposta = _resposta_dispositivo(dispositivo)
    resposta["agent_token"] = token_dispositivo
    resposta["token_version"] = token_version
    resposta["token_expires_em"] = _iso_or_none(documento["token_expires_at"])
    return resposta


@app.post("/desktop/devices/token/renew")
def renovar_token_dispositivo(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    payload = decodificar_token_dispositivo(credentials.credentials)
    dispositivo = db["desktop_devices"].find_one({"device_id": payload["device_id"], "usuario_id": payload["usuario_id"]})
    if not dispositivo:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")

    novo_token, expira_em, token_version = _rotacionar_token_dispositivo(dispositivo)
    atualizado = db["desktop_devices"].find_one({"device_id": payload["device_id"], "usuario_id": payload["usuario_id"]})
    resposta = _resposta_dispositivo(atualizado or dispositivo)
    resposta["agent_token"] = novo_token
    resposta["token_version"] = token_version
    resposta["token_expires_em"] = _iso_or_none(expira_em)
    return resposta


@app.post("/desktop/devices/{device_id}/heartbeat")
def heartbeat_dispositivo(
    device_id: str,
    payload: DesktopDeviceHeartbeat,
    device_payload: dict[str, Any] = Depends(validar_token_dispositivo),
):
    if payload.device_id != device_id or device_payload["device_id"] != device_id:
        raise HTTPException(status_code=400, detail="device_id inconsistente.")

    dispositivo = db["desktop_devices"].find_one({"device_id": device_id, "usuario_id": device_payload["usuario_id"]})
    if not dispositivo:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado.")

    monitoring_state = str(payload.monitoring_state or dispositivo.get("monitoring_state") or "idle").strip().lower()
    if payload.monitoring_active is True:
        monitoring_state = "monitoring"
    elif payload.monitoring_active is False and monitoring_state == "monitoring":
        monitoring_state = "idle"

    agora = datetime.utcnow()
    token = None
    token_expires_em = dispositivo.get("token_expires_at")
    token_expira_em = _to_datetime(token_expires_em)
    if token_expira_em and (token_expira_em - agora).total_seconds() <= 30 * 60:
        token, token_expires_em, _ = _rotacionar_token_dispositivo(dispositivo)

    db["desktop_devices"].update_one(
        {"device_id": device_id, "usuario_id": device_payload["usuario_id"]},
        {
            "$set": {
                "agent_version": payload.agent_version or dispositivo.get("agent_version"),
                "last_heartbeat_at": agora,
                "monitoring_state": monitoring_state,
                "updated_at": agora,
            }
        },
    )

    dispositivo_atualizado = db["desktop_devices"].find_one({"device_id": device_id, "usuario_id": device_payload["usuario_id"]})
    resposta = _resposta_dispositivo(dispositivo_atualizado or dispositivo)
    resposta["heartbeat_at"] = _iso_or_none(agora)
    resposta["server_time"] = _iso_or_none(agora)
    resposta["monitoring_state"] = monitoring_state
    resposta["last_command_id"] = payload.last_command_id
    if token:
        resposta["agent_token"] = token
        resposta["token_expires_em"] = _iso_or_none(token_expires_em)
    return resposta


@app.get("/desktop/devices/{device_id}/commands")
def buscar_comandos_dispositivo(
    device_id: str,
    after: Optional[str] = None,
    device_payload: dict[str, Any] = Depends(validar_token_dispositivo),
):
    if device_payload["device_id"] != device_id:
        raise HTTPException(status_code=400, detail="device_id inconsistente.")

    comandos_db = list(
        db["desktop_device_commands"].find(
            {"device_id": device_id, "usuario_id": device_payload["usuario_id"], "status": "pending"}
        ).sort("created_at", 1)
    )
    comandos = []
    for comando in comandos_db:
        comandos.append(
            {
                "command_id": comando.get("command_id"),
                "id": comando.get("command_id"),
                "device_id": comando.get("device_id"),
                "action": comando.get("action"),
                "payload": comando.get("payload") or {},
                "status": comando.get("status", "pending"),
                "created_at": _iso_or_none(_to_datetime(comando.get("created_at"))),
            }
        )

    return {"commands": comandos, "after": after, "device_id": device_id}


@app.post("/desktop/devices/{device_id}/commands/{command_id}/ack")
def confirmar_comando_dispositivo(
    device_id: str,
    command_id: str,
    payload: DesktopDeviceCommandAck,
    device_payload: dict[str, Any] = Depends(validar_token_dispositivo),
):
    if device_payload["device_id"] != device_id or payload.command_id != command_id:
        raise HTTPException(status_code=400, detail="Parâmetros do comando inconsistentes.")

    comando = db["desktop_device_commands"].find_one(
        {"device_id": device_id, "usuario_id": device_payload["usuario_id"], "command_id": command_id}
    )
    if not comando:
        raise HTTPException(status_code=404, detail="Comando não encontrado.")

    agora = datetime.utcnow()
    db["desktop_device_commands"].update_one(
        {"device_id": device_id, "usuario_id": device_payload["usuario_id"], "command_id": command_id},
        {
            "$set": {
                "status": "executed",
                "executed_at": agora,
                "result": payload.result or {},
                "updated_at": agora,
            }
        },
    )

    acao = str(comando.get("action") or "").strip().upper()
    monitoring_state = str(comando.get("payload", {}).get("monitoring_state") or "").strip().lower()
    if acao == "START_MONITORING":
        monitoring_state = "monitoring"
    elif acao in {"STOP_MONITORING", "PAUSE_MONITORING"}:
        monitoring_state = "idle"

    if monitoring_state:
        db["desktop_devices"].update_one(
            {"device_id": device_id, "usuario_id": device_payload["usuario_id"]},
            {
                "$set": {
                    "monitoring_state": monitoring_state,
                    "last_command_at": agora,
                    "updated_at": agora,
                }
            },
        )

    return {
        "ok": True,
        "command_id": command_id,
        "status": "executed",
        "monitoring_state": monitoring_state or comando.get("payload", {}).get("monitoring_state"),
        "executed_at": _iso_or_none(agora),
    }


@app.get("/desktop/devices/status")
def status_dispositivo_web(usuario_id: str = Depends(validar_token)):
    dispositivo = buscar_dispositivo_do_usuario(usuario_id)
    return _serializar_dispositivo(dispositivo)


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
    nova_tarefa = tarefa.model_dump() if hasattr(tarefa, "model_dump") else tarefa.dict()
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
    """Payload para registrar rosto do usuário vindo do Desktop"""
    embedding: list[float] 


class VerificarRostoPayload(BaseModel):
    """Payload para verificar um rosto contra a galeria"""
    imagem_base64: str
    limiar_confianca: float = 0.6


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
    usuario = buscar_usuario(usuario_id)
    empresa_id = usuario.get("empresa_id")

    try:
        rosto_existente = db["rostos_registrados"].find_one({"usuario_id": usuario_id})
        
        if rosto_existente:
            db["rostos_registrados"].update_one(
                {"usuario_id": usuario_id},
                {
                    "$set": {
                        "embedding": payload.embedding,
                        "atualizado_em": datetime.utcnow(),
                    }
                }
            )
            mensagem = "Rosto atualizado com sucesso!"
        else:
            db["rostos_registrados"].insert_one({
                "usuario_id": usuario_id,
                "nome": usuario["nome"],
                "empresa_id": empresa_id,
                "embedding": payload.embedding,
                "criado_em": datetime.utcnow()
            })
            mensagem = "Rosto cadastrado com sucesso!"
        
        return {"mensagem": mensagem}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao salvar no banco: {str(e)}")


if __name__ == "__main__":
    import uvicorn

    porta = int(os.getenv("PORT", "7860"))
    uvicorn.run("main:app", host="0.0.0.0", port=porta)

