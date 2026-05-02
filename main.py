from pydantic import BaseModel
from database import db 
from passlib.context import CryptContext 
from bson.objectid import ObjectId
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv
import jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
security = HTTPBearer()
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from datetime import datetime, timedelta


load_dotenv()


SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("Aviso Crítico: JWT_SECRET_KEY não foi encontrada no arquivo .env!")

ALGORITHM = "HS256"

app = FastAPI(title="API - VERIFIQ OS", description="Motor principal do sistema de gestão e segurança.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],
)
def criar_token(usuario_id: str):
    return jwt.encode({"usuario_id": usuario_id}, SECRET_KEY, algorithm=ALGORITHM)
def validar_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("usuario_id")
    except:
        raise HTTPException(status_code=401, detail="Acesso negado. Crachá (Token) inválido.")
@app.get("/")
def home():
    return {"status": "API online e rodando perfeitamente!"}


class UsuarioCadastro(BaseModel):
    nome: str
    email: str
    senha: str

@app.post("/cadastro", status_code=201)
def cadastrar_usuario(usuario: UsuarioCadastro):
    # 1. Verifica no MongoDB se o email já está cadastrado
    usuario_existente = db["usuarios"].find_one({"email": usuario.email})
    if usuario_existente:
        
        raise HTTPException(status_code=400, detail="Este e-mail já está cadastrado.")

    
    novo_usuario = {
        "nome": usuario.nome,
        "email": usuario.email,
        "senha": gerar_hash_senha(usuario.senha)
    }

    resultado = db["usuarios"].insert_one(novo_usuario)

    return {
        "mensagem": "Usuário cadastrado com sucesso!",
        "id_usuario": str(resultado.inserted_id)
    }

class StatusCamera(BaseModel):
    status: str  

class UsuarioLogin(BaseModel):
    email: str
    senha: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def gerar_hash_senha(senha: str):
    return pwd_context.hash(senha)

def verificar_senha(senha_plana: str, senha_hash: str):
    return pwd_context.verify(senha_plana, senha_hash)

@app.post("/login")
def login(usuario: UsuarioLogin):
    
    usuario_db = db["usuarios"].find_one({"email": usuario.email})
    
    
    if not usuario_db or not verificar_senha(usuario.senha, usuario_db["senha"]):
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")
    id_do_usuario = str(usuario_db["_id"])
    token_jwt = criar_token(id_do_usuario)
    
    return {
        "mensagem": "Login realizado com sucesso!",
        "token": token_jwt,
        "usuario": usuario_db["nome"]
    }
class Tarefa(BaseModel):
    titulo: str
    descricao: str
    status: str = "A Fazer"  # Valor padrão
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
    
    resultado = db["tarefas"].update_one(
        {"_id": ObjectId(tarefa_id), "usuario_id": usuario_id}, 
        {"$set": {"status": atualizacao.status}}
    )
    
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada ou você não tem permissão para alterá-la.")
        
    return {"mensagem": f"Tarefa movida para: {atualizacao.status}"}

@app.put("/tarefas/editar-texto/{tarefa_id}")
def editar_texto(tarefa_id: str, dados: EditarTextoTarefa, usuario_id: str = Depends(validar_token)):
    resultado = db["tarefas"].update_one(
        {"_id": ObjectId(tarefa_id), "usuario_id": usuario_id},
        {"$set": {"titulo": dados.titulo, "descricao": dados.descricao}}
    )
    
    if resultado.matched_count == 0:
        raise HTTPException(status_code=404, detail="Tarefa não encontrada ou sem permissão para editá-la.")
        
    return {"mensagem": "Texto da tarefa atualizado com sucesso!"}

@app.delete("/tarefas/{tarefa_id}")
def deletar_tarefa(tarefa_id: str, usuario_id: str = Depends(validar_token)):

    resultado = db["tarefas"].delete_one(
        {"_id": ObjectId(tarefa_id), "usuario_id": usuario_id}
    )
    
    
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
        "data_criacao": hoje
    }

    resultado = db["relatorios_diarios"].insert_one(novo_relatorio)

    return {
        "mensagem": "Relatório diário salvo com sucesso!",
        "id_relatorio": str(resultado.inserted_id)
    }

class EditarTextoTarefa(BaseModel):
    titulo: str
    descricao: str

class GerenciadorDeConexoes:
    def __init__(self):
        
        self.conexoes_ativas: list[WebSocket] = []

    async def conectar(self, websocket: WebSocket):
        await websocket.accept()
        self.conexoes_ativas.append(websocket)

    def desconectar(self, websocket: WebSocket):
        self.conexoes_ativas.remove(websocket)

    async def enviar_mensagem_todos(self, mensagem: str):
        
        for conexao in self.conexoes_ativas:
            await conexao.send_text(mensagem)

gerenciador_chat = GerenciadorDeConexoes()

@app.websocket("/ws/chat/{nome_usuario}")
async def websocket_chat(websocket: WebSocket, nome_usuario: str):
    
    await gerenciador_chat.conectar(websocket)
    
    try:
        
        await gerenciador_chat.enviar_mensagem_todos(f" {nome_usuario} entrou no chat!")
        
        
        while True:
           
            mensagem_recebida = await websocket.receive_text()
            
            mensagem_formatada = f" {nome_usuario}: {mensagem_recebida}"
            await gerenciador_chat.enviar_mensagem_todos(mensagem_formatada)
            
    except WebSocketDisconnect:
        
        gerenciador_chat.desconectar(websocket)
        await gerenciador_chat.enviar_mensagem_todos(f" {nome_usuario} saiu do chat.")

@app.post("/cameras/status")

async def registrar_status_camera(status: StatusCamera, usuario_id: str = Depends(validar_token)):
    
    resultado = db["status_cameras"].insert_one({
        "usuario_id": usuario_id,
        "status": status.status,
        "timestamp": datetime.utcnow()
    })
    
    db["logs_camera"].insert_one(log_db)

    if req.status == "LIGADA":
        mensagem_alerta = f"[sistema] Alerta: A câmera foi LIGADA pelo usuário {usuario_id[-4:]}! e a varredura de segurança foi iniciada."
    else:
        mensagem_alerta = f"[sistema] Alerta: A câmera foi DESLIGADA pelo usuário {usuario_id[-4:]}! e a varredura de segurança foi interrompida."
    await gerenciador_chat.enviar_mensagem_todos(mensagem_alerta)

    return {
        "mensagem": "Status da câmera registrado com sucesso e usuário notificado no chat!"}

