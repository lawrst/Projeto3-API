"""
Suite de testes para a API VERIFIQ OS (main.py)
Usa pytest + httpx (TestClient do FastAPI) + unittest.mock para simular o MongoDB.
Nenhum banco real é necessário para rodar.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from bson import ObjectId
from fastapi.testclient import TestClient

# ─────────────────────────────────────────────────────────────────────────────
# SETUP: mocka o módulo `database` antes de importar `main`
# ─────────────────────────────────────────────────────────────────────────────

# Cria um db falso completo (cada coleção é um MagicMock)
mock_db = MagicMock()
mock_collections: dict[str, MagicMock] = {}


def get_mock_collection(name: str) -> MagicMock:
    if name not in mock_collections:
        mock_collections[name] = MagicMock(name=f"collection_{name}")
    return mock_collections[name]


mock_db.__getitem__.side_effect = get_mock_collection

import sys
fake_database_module = MagicMock()
fake_database_module.db = mock_db
fake_database_module.client = MagicMock()
sys.modules["database"] = fake_database_module

# Agora importa o app (ele vai usar o mock_db no lugar do MongoDB real)
from main import app, criar_token, gerar_hash_senha, verificar_senha

client = TestClient(app, raise_server_exceptions=False)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def make_object_id() -> str:
    return str(ObjectId())


def usuario_doc(
    usuario_id: str,
    nome: str = "Teste Silva",
    email: str = "teste@empresa.com",
    role: str = "funcionario",
    empresa_id: str = "empresa123",
):
    """Retorna um documento de usuário parecido com o que o MongoDB devolveria."""
    return {
        "_id": ObjectId(usuario_id),
        "nome": nome,
        "email": email,
        "senha": gerar_hash_senha("senha123"),
        "role": role,
        "empresa_id": empresa_id,
    }


def desktop_device_doc(
    device_id: str,
    usuario_id: str,
    monitoring_state: str = "monitoring",
    last_heartbeat_at: datetime | None = None,
):
    return {
        "device_id": device_id,
        "usuario_id": usuario_id,
        "empresa_id": "empresa123",
        "device_name": "VERIFIQ Desktop",
        "hostname": "desktop-local",
        "machine": "x86_64",
        "os_name": "Windows",
        "agent_version": "1.0.0",
        "paired_at": datetime.utcnow() - timedelta(minutes=5),
        "last_heartbeat_at": last_heartbeat_at or (datetime.utcnow() - timedelta(seconds=30)),
        "last_command_at": datetime.utcnow() - timedelta(seconds=20),
        "monitoring_state": monitoring_state,
        "desired_state": monitoring_state,
        "token_version": 1,
        "token_expires_at": datetime.utcnow() + timedelta(hours=4),
    }


def auth_headers(usuario_id: str) -> dict:
    """Gera o header Authorization com JWT válido."""
    token = criar_token(usuario_id)
    return {"Authorization": f"Bearer {token}"}


def reset_mock():
    """Reseta todos os mocks entre os testes."""
    mock_db.reset_mock(return_value=True, side_effect=True)
    for collection in mock_collections.values():
        collection.reset_mock(return_value=True, side_effect=True)
    mock_collections.clear()
    mock_db.__getitem__.side_effect = get_mock_collection


# ─────────────────────────────────────────────────────────────────────────────
# 1. SAÚDE / UTILITÁRIOS
# ─────────────────────────────────────────────────────────────────────────────

class TestHealthAndUtils:

    def setup_method(self):
        reset_mock()

    def test_home_retorna_200(self):
        r = client.get("/")
        assert r.status_code == 200
        assert "online" in r.json()["status"].lower()

    def test_debug_db_retorna_status(self):
        fake_database_module.client.admin.command.return_value = {"ok": 1}
        r = client.get("/debug-db")
        assert r.status_code == 200

    def test_criar_token_e_decodificar(self):
        uid = make_object_id()
        token = criar_token(uid)
        assert isinstance(token, str)
        assert len(token) > 20

    def test_hash_e_verificar_senha(self):
        hash_ = gerar_hash_senha("minhaSenha@123")
        assert verificar_senha("minhaSenha@123", hash_) is True
        assert verificar_senha("senhaErrada", hash_) is False

    def test_verificar_token_valido(self):
        uid = make_object_id()
        doc = usuario_doc(uid)
        mock_db["usuarios"].find_one.return_value = doc
        mock_db["rostos_registrados"].find_one.return_value = None

        r = client.get("/verificar-token", headers=auth_headers(uid))
        assert r.status_code == 200
        data = r.json()
        assert data["valido"] is True
        assert data["usuario_id"] == uid

    def test_verificar_token_invalido_retorna_401(self):
        r = client.get("/verificar-token", headers={"Authorization": "Bearer tokeninvalido"})
        assert r.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# 2. CADASTRO DE USUÁRIO
# ─────────────────────────────────────────────────────────────────────────────

class TestCadastroUsuario:

    def setup_method(self):
        reset_mock()

    def _payload(self, role="admin", email="novo@empresa.com"):
        return {
            "nome": "Novo Usuário",
            "email": email,
            "senha": "senha123",
            "empresa_id": "empresa_abc",
            "role": role,
        }

    def test_primeiro_usuario_admin_sem_token(self):
        mock_db["usuarios"].count_documents.return_value = 0
        mock_db["usuarios"].find_one.return_value = None
        mock_db["usuarios"].insert_one.return_value = MagicMock(
            inserted_id=ObjectId()
        )

        r = client.post("/cadastro", json=self._payload("admin"))
        assert r.status_code == 201
        assert "id_usuario" in r.json()

    def test_primeiro_usuario_deve_ser_admin(self):
        mock_db["usuarios"].count_documents.return_value = 0

        r = client.post("/cadastro", json=self._payload("funcionario"))
        assert r.status_code == 400
        assert "admin" in r.json()["detail"].lower()

    def test_cadastro_sem_token_quando_ja_existe_usuario(self):
        mock_db["usuarios"].count_documents.return_value = 5

        r = client.post("/cadastro", json=self._payload())
        assert r.status_code == 401

    def test_admin_cadastra_funcionario(self):
        admin_id = make_object_id()
        admin = usuario_doc(admin_id, role="admin")

        mock_db["usuarios"].count_documents.return_value = 1
        mock_db["usuarios"].find_one.side_effect = [
            admin,   # busca do admin autenticado
            None,    # e-mail ainda não cadastrado
        ]
        mock_db["usuarios"].insert_one.return_value = MagicMock(
            inserted_id=ObjectId()
        )

        r = client.post(
            "/cadastro",
            json=self._payload("funcionario", email="func@empresa.com"),
            headers=auth_headers(admin_id),
        )
        assert r.status_code == 201

    def test_email_duplicado_retorna_400(self):
        admin_id = make_object_id()
        admin = usuario_doc(admin_id, role="admin")

        mock_db["usuarios"].count_documents.return_value = 1
        mock_db["usuarios"].find_one.side_effect = [
            admin,
            {"email": "novo@empresa.com"},  # e-mail já existe
        ]

        r = client.post(
            "/cadastro",
            json=self._payload(),
            headers=auth_headers(admin_id),
        )
        assert r.status_code == 400
        assert "e-mail" in r.json()["detail"].lower()

    def test_role_invalida_retorna_400(self):
        admin_id = make_object_id()
        admin = usuario_doc(admin_id, role="admin")

        mock_db["usuarios"].count_documents.return_value = 1
        mock_db["usuarios"].find_one.side_effect = [admin, None]

        payload = self._payload()
        payload["role"] = "gerente"  # role inválida
        r = client.post("/cadastro", json=payload, headers=auth_headers(admin_id))
        assert r.status_code == 400
        assert "role" in r.json()["detail"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# 3. LOGIN
# ─────────────────────────────────────────────────────────────────────────────

class TestLogin:

    def setup_method(self):
        reset_mock()

    def test_login_sucesso(self):
        uid = make_object_id()
        doc = usuario_doc(uid)
        mock_db["usuarios"].find_one.return_value = doc
        mock_db["rostos_registrados"].find_one.return_value = None

        r = client.post("/login", json={"email": "teste@empresa.com", "senha": "senha123"})
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        assert data["role"] == "funcionario"

    def test_login_email_errado_retorna_401(self):
        mock_db["usuarios"].find_one.return_value = None

        r = client.post("/login", json={"email": "naoexiste@x.com", "senha": "qualquer"})
        assert r.status_code == 401

    def test_login_senha_errada_retorna_401(self):
        uid = make_object_id()
        doc = usuario_doc(uid)
        mock_db["usuarios"].find_one.return_value = doc

        r = client.post("/login", json={"email": "teste@empresa.com", "senha": "senhaErrada"})
        assert r.status_code == 401

    def test_login_sem_db_retorna_500(self):
        # Simula db = None no módulo main
        with patch("main.db", None):
            r = client.post("/login", json={"email": "a@a.com", "senha": "123"})
            assert r.status_code == 500

    def test_login_enfileira_start_monitoring_quando_dispositivo_pareado(self):
        uid = make_object_id()
        doc = usuario_doc(uid)
        device = desktop_device_doc("device-123", uid, monitoring_state="idle")

        mock_db["usuarios"].find_one.return_value = doc
        mock_db["rostos_registrados"].find_one.return_value = None
        mock_db["desktop_devices"].find_one.side_effect = [device, device]
        mock_db["desktop_device_commands"].find_one.return_value = None
        mock_db["desktop_device_commands"].insert_one.return_value = MagicMock(inserted_id=ObjectId())

        r = client.post("/login", json={"email": "teste@empresa.com", "senha": "senha123"})
        assert r.status_code == 200
        data = r.json()
        assert data["agente_desktop"]["pareado"] is True
        assert mock_db["desktop_device_commands"].insert_one.called


# ─────────────────────────────────────────────────────────────────────────────
# 4. TAREFAS
# ─────────────────────────────────────────────────────────────────────────────

class TestTarefas:

    def setup_method(self):
        reset_mock()
        self.uid = make_object_id()
        self.doc = usuario_doc(self.uid)
        self.headers = auth_headers(self.uid)


# ─────────────────────────────────────────────────────────────────────────────
# 5. DISPOSITIVOS DESKTOP
# ─────────────────────────────────────────────────────────────────────────────

class TestDesktopDevices:

    def setup_method(self):
        reset_mock()
        self.uid = make_object_id()
        self.doc = usuario_doc(self.uid, role="admin")
        self.headers = auth_headers(self.uid)

    def test_status_dispositivo_sem_pareamento(self):
        mock_db["desktop_devices"].find_one.return_value = None

        r = client.get("/desktop/devices/status", headers=self.headers)
        assert r.status_code == 200
        data = r.json()
        assert data["pareado"] is False
        assert data["estado"] == "desconectado"

    def test_registrar_dispositivo_retorna_token(self):
        device_id = "device-abc"
        mock_db["usuarios"].find_one.return_value = self.doc
        mock_db["desktop_devices"].find_one.side_effect = [None, desktop_device_doc(device_id, self.uid)]
        mock_db["desktop_devices"].update_one.return_value = MagicMock()

        r = client.post(
            "/desktop/devices/register",
            json={
                "device_id": device_id,
                "device_name": "Desktop Principal",
                "hostname": "desktop-local",
                "machine": "x86_64",
                "os_name": "Windows",
                "agent_version": "1.2.3",
            },
            headers=self.headers,
        )

        assert r.status_code == 200
        data = r.json()
        assert data["device_id"] == device_id
        assert data["agent_token"]

    def _mock_usuario(self):
        mock_db["usuarios"].find_one.return_value = self.doc

    def test_criar_tarefa(self):
        self._mock_usuario()
        mock_db["tarefas"].insert_one.return_value = MagicMock(inserted_id=ObjectId())

        r = client.post(
            "/tarefas",
            json={"titulo": "Nova tarefa", "descricao": "Detalhe", "usuario_id": self.uid},
            headers=self.headers,
        )
        assert r.status_code == 200
        assert "id" in r.json()

    def test_listar_tarefas(self):
        self._mock_usuario()
        tarefa_id = ObjectId()
        mock_db["tarefas"].find.return_value = [
            {"_id": tarefa_id, "titulo": "T1", "descricao": "D1", "status": "A Fazer", "usuario_id": self.uid}
        ]

        r = client.get("/tarefas", headers=self.headers)
        assert r.status_code == 200
        assert len(r.json()) == 1
        assert r.json()[0]["titulo"] == "T1"

    def test_atualizar_status_tarefa(self):
        self._mock_usuario()
        tarefa_id = make_object_id()
        resultado = MagicMock()
        resultado.matched_count = 1
        mock_db["tarefas"].update_one.return_value = resultado

        r = client.put(
            f"/tarefas/{tarefa_id}",
            json={"status": "Em Progresso"},
            headers=self.headers,
        )
        assert r.status_code == 200

    def test_atualizar_tarefa_inexistente_retorna_404(self):
        self._mock_usuario()
        tarefa_id = make_object_id()
        resultado = MagicMock()
        resultado.matched_count = 0
        mock_db["tarefas"].update_one.return_value = resultado

        r = client.put(
            f"/tarefas/{tarefa_id}",
            json={"status": "Em Progresso"},
            headers=self.headers,
        )
        assert r.status_code == 404

    def test_deletar_tarefa(self):
        self._mock_usuario()
        tarefa_id = make_object_id()
        resultado = MagicMock()
        resultado.deleted_count = 1
        mock_db["tarefas"].delete_one.return_value = resultado

        r = client.delete(f"/tarefas/{tarefa_id}", headers=self.headers)
        assert r.status_code == 200

    def test_deletar_tarefa_inexistente_retorna_404(self):
        self._mock_usuario()
        tarefa_id = make_object_id()
        resultado = MagicMock()
        resultado.deleted_count = 0
        mock_db["tarefas"].delete_one.return_value = resultado

        r = client.delete(f"/tarefas/{tarefa_id}", headers=self.headers)
        assert r.status_code == 404

    def test_tarefa_id_invalido_retorna_400(self):
        self._mock_usuario()
        r = client.put("/tarefas/id-invalido", json={"status": "X"}, headers=self.headers)
        assert r.status_code == 400

    def test_tarefa_sem_token_retorna_403_ou_401(self):
        r = client.get("/tarefas")
        assert r.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────────────────────
# 5. CHATS
# ─────────────────────────────────────────────────────────────────────────────

class TestChats:

    def setup_method(self):
        reset_mock()
        self.admin_id = make_object_id()
        self.admin = usuario_doc(self.admin_id, role="admin")
        self.headers = auth_headers(self.admin_id)

    def _mock_admin(self):
        mock_db["usuarios"].find_one.return_value = self.admin

    def test_criar_chat(self):
        func_id = make_object_id()
        func = usuario_doc(func_id, email="func@empresa.com", role="funcionario")

        mock_db["usuarios"].find_one.side_effect = [
            self.admin,   # validar token → buscar_usuario
            func,         # buscar_usuario do funcionário no loop
        ]
        mock_db["chats"].insert_one.return_value = MagicMock(inserted_id=ObjectId())

        r = client.post(
            "/chats",
            json={"nome_chat": "Geral", "funcionarios_ids": [func_id]},
            headers=self.headers,
        )
        assert r.status_code == 201
        assert "id_chat" in r.json()

    def test_criar_chat_funcionario_outra_empresa_retorna_400(self):
        func_id = make_object_id()
        func_outra_empresa = usuario_doc(func_id, empresa_id="outra_empresa", role="funcionario")

        mock_db["usuarios"].find_one.side_effect = [self.admin, func_outra_empresa]

        r = client.post(
            "/chats",
            json={"nome_chat": "Geral", "funcionarios_ids": [func_id]},
            headers=self.headers,
        )
        assert r.status_code == 400

    def test_listar_chats(self):
        self._mock_admin()
        chat_id = ObjectId()
        mock_db["chats"].find.return_value = [
            {
                "_id": chat_id,
                "nome_chat": "Suporte",
                "empresa_id": "empresa123",
                "admin_id": self.admin_id,
                "participantes_ids": [self.admin_id],
            }
        ]

        r = client.get("/chats", headers=self.headers)
        assert r.status_code == 200
        assert r.json()[0]["nome_chat"] == "Suporte"

    def test_deletar_chat(self):
        self._mock_admin()
        chat_id = make_object_id()
        del_msgs = MagicMock()
        del_msgs.deleted_count = 3
        del_chat = MagicMock()
        del_chat.deleted_count = 1
        mock_db["mensagens_chat"].delete_many.return_value = del_msgs
        mock_db["chats"].delete_one.return_value = del_chat

        r = client.delete(f"/chats/{chat_id}", headers=self.headers)
        assert r.status_code == 200

    def test_deletar_chat_inexistente_retorna_404(self):
        self._mock_admin()
        chat_id = make_object_id()
        mock_db["mensagens_chat"].delete_many.return_value = MagicMock()
        del_chat = MagicMock()
        del_chat.deleted_count = 0
        mock_db["chats"].delete_one.return_value = del_chat

        r = client.delete(f"/chats/{chat_id}", headers=self.headers)
        assert r.status_code == 404

    def test_criar_chat_nao_admin_retorna_403(self):
        func_id = make_object_id()
        func = usuario_doc(func_id, role="funcionario")
        mock_db["usuarios"].find_one.return_value = func

        r = client.post(
            "/chats",
            json={"nome_chat": "Privado", "funcionarios_ids": []},
            headers=auth_headers(func_id),
        )
        assert r.status_code == 403


# ─────────────────────────────────────────────────────────────────────────────
# 6. MENSAGENS DE CHAT
# ─────────────────────────────────────────────────────────────────────────────

class TestMensagensChat:

    def setup_method(self):
        reset_mock()
        self.uid = make_object_id()
        self.chat_id = make_object_id()
        self.headers = auth_headers(self.uid)
        self.chat_doc = {
            "_id": ObjectId(self.chat_id),
            "nome_chat": "Geral",
            "empresa_id": "empresa123",
            "admin_id": self.uid,
            "participantes_ids": [self.uid],
        }

    def _mock_usuario_e_chat(self):
        mock_db["usuarios"].find_one.return_value = usuario_doc(self.uid)
        mock_db["chats"].find_one.return_value = self.chat_doc

    def test_listar_mensagens(self):
        self._mock_usuario_e_chat()
        msg_id = ObjectId()
        from datetime import datetime
        mock_db["mensagens_chat"].find.return_value = MagicMock()
        mock_db["mensagens_chat"].find.return_value.sort.return_value.limit.return_value = [
            {
                "_id": msg_id,
                "chat_id": self.chat_id,
                "usuario_id": self.uid,
                "nome_usuario": "Teste Silva",
                "mensagem": "Olá!",
                "data_envio": datetime.utcnow(),
            }
        ]

        r = client.get(f"/chat/mensagens?chat_id={self.chat_id}", headers=self.headers)
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_listar_mensagens_limite_invalido(self):
        self._mock_usuario_e_chat()

        r = client.get(
            f"/chat/mensagens?chat_id={self.chat_id}&limite=500",
            headers=self.headers,
        )
        assert r.status_code == 400

    def test_usuario_nao_participa_do_chat_retorna_403(self):
        outro_uid = make_object_id()
        mock_db["usuarios"].find_one.return_value = usuario_doc(outro_uid)
        # Chat sem o outro_uid nos participantes
        mock_db["chats"].find_one.return_value = {
            "_id": ObjectId(self.chat_id),
            "participantes_ids": [self.uid],
            "empresa_id": "empresa123",
        }

        r = client.get(
            f"/chat/mensagens?chat_id={self.chat_id}",
            headers=auth_headers(outro_uid),
        )
        assert r.status_code == 403


# ─────────────────────────────────────────────────────────────────────────────
# 7. CÂMERA E ALERTAS
# ─────────────────────────────────────────────────────────────────────────────

class TestCameraEAlertas:

    def setup_method(self):
        reset_mock()
        self.uid = make_object_id()
        self.headers = auth_headers(self.uid)
        mock_db["usuarios"].find_one.return_value = usuario_doc(self.uid)

    def test_registrar_status_camera(self):
        mock_db["camera_status"].insert_one.return_value = MagicMock(inserted_id=ObjectId())

        r = client.post("/cameras/status", json={"status": "LIGADA"}, headers=self.headers)
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_registrar_alerta(self):
        mock_db["alertas"].insert_one.return_value = MagicMock(inserted_id=ObjectId())
        mock_db["security_state"].update_one.return_value = MagicMock()

        payload = {
            "motivo": "rosto_desconhecido",
            "faces_detectadas": 1,
            "score": 0.45,
        }
        r = client.post("/seguranca/alerta", json=payload, headers=self.headers)
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_estado_seguranca(self):
        mock_db["security_state"].find_one.return_value = {
            "empresa_id": "empresa123",
            "bloqueio_ativo": True,
            "motivo": "rosto_desconhecido",
            "ultimo_alerta_em": None,
            "desbloqueado_em": None,
            "desbloqueado_por": None,
        }

        r = client.get("/seguranca/estado", headers=self.headers)
        assert r.status_code == 200
        assert r.json()["bloqueio_ativo"] is True

    def test_desbloquear_seguranca_como_admin(self):
        admin_id = make_object_id()
        mock_db["usuarios"].find_one.return_value = usuario_doc(admin_id, role="admin")
        mock_db["security_state"].update_one.return_value = MagicMock()

        r = client.post(
            "/seguranca/desbloquear",
            json={"observacao": "Verificado manualmente"},
            headers=auth_headers(admin_id),
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_desbloquear_seguranca_como_funcionario_retorna_403(self):
        func_id = make_object_id()
        mock_db["usuarios"].find_one.return_value = usuario_doc(func_id, role="funcionario")

        r = client.post(
            "/seguranca/desbloquear",
            json={},
            headers=auth_headers(func_id),
        )
        assert r.status_code == 403


# ─────────────────────────────────────────────────────────────────────────────
# 8. PONTO
# ─────────────────────────────────────────────────────────────────────────────

class TestPonto:

    def setup_method(self):
        reset_mock()
        self.uid = make_object_id()
        self.headers = auth_headers(self.uid)
        mock_db["usuarios"].find_one.return_value = usuario_doc(self.uid)

    def test_registrar_ponto_entrada(self):
        mock_db["pontos"].insert_one.return_value = MagicMock(inserted_id=ObjectId())

        r = client.post("/ponto", json={"tipo": "entrada"}, headers=self.headers)
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_registrar_ponto_saida(self):
        mock_db["pontos"].insert_one.return_value = MagicMock(inserted_id=ObjectId())

        r = client.post("/ponto", json={"tipo": "saída"}, headers=self.headers)
        assert r.status_code == 200

    def test_registrar_ponto_tipo_invalido(self):
        r = client.post("/ponto", json={"tipo": "almoco"}, headers=self.headers)
        assert r.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────
# 9. RECONHECIMENTO FACIAL
# ─────────────────────────────────────────────────────────────────────────────

class TestReconhecimentoFacial:

    def setup_method(self):
        reset_mock()
        self.uid = make_object_id()
        self.headers = auth_headers(self.uid)
        mock_db["usuarios"].find_one.return_value = usuario_doc(self.uid)

    def test_cadastrar_rosto_novo(self):
        mock_db["rostos_registrados"].find_one.return_value = None
        mock_db["rostos_registrados"].insert_one.return_value = MagicMock(inserted_id=ObjectId())

        embedding = [0.1] * 128
        r = client.post("/rosto/cadastrar", json={"embedding": embedding}, headers=self.headers)
        assert r.status_code == 201
        assert "cadastrado" in r.json()["mensagem"].lower()

    def test_atualizar_rosto_existente(self):
        mock_db["rostos_registrados"].find_one.return_value = {"usuario_id": self.uid}
        mock_db["rostos_registrados"].update_one.return_value = MagicMock()

        embedding = [0.2] * 128
        r = client.post("/rosto/cadastrar", json={"embedding": embedding}, headers=self.headers)
        assert r.status_code == 201
        assert "atualizado" in r.json()["mensagem"].lower()

    def test_estado_rosto_sem_cadastro(self):
        mock_db["rostos_registrados"].find_one.return_value = None

        r = client.get("/rosto/estado", headers=self.headers)
        assert r.status_code == 200
        assert r.json()["tem_rosto"] is False

    def test_estado_rosto_com_cadastro(self):
        mock_db["rostos_registrados"].find_one.return_value = {"usuario_id": self.uid}

        r = client.get("/rosto/estado", headers=self.headers)
        assert r.status_code == 200
        assert r.json()["tem_rosto"] is True

    def test_listar_galeria(self):
        mock_db["rostos_registrados"].find.return_value = [
            {"usuario_id": self.uid, "nome": "Teste Silva", "empresa_id": "empresa123", "embedding": [0.1] * 128}
        ]

        r = client.get("/faces/galeria", headers=self.headers)
        assert r.status_code == 200
        assert len(r.json()["galeria"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 10. RELATÓRIOS DIÁRIOS
# ─────────────────────────────────────────────────────────────────────────────

class TestRelatorios:

    def setup_method(self):
        reset_mock()
        self.uid = make_object_id()
        self.headers = auth_headers(self.uid)
        mock_db["usuarios"].find_one.return_value = usuario_doc(self.uid)

    def test_salvar_relatorio(self):
        mock_db["relatorios_diarios"].insert_one.return_value = MagicMock(inserted_id=ObjectId())

        payload = {
            "resumo_dia": "Dia produtivo",
            "atividades_realizadas": ["Reunião", "Código"],
            "dificuldades": None,
            "proxima_meta": "Finalizar feature X",
        }
        r = client.post("/relatorios-diarios", json=payload, headers=self.headers)
        assert r.status_code == 201
        assert "id_relatorio" in r.json()


# ─────────────────────────────────────────────────────────────────────────────
# 11. FUNCIONÁRIOS (admin)
# ─────────────────────────────────────────────────────────────────────────────

class TestFuncionarios:

    def setup_method(self):
        reset_mock()
        self.admin_id = make_object_id()
        self.admin = usuario_doc(self.admin_id, role="admin")
        self.headers = auth_headers(self.admin_id)

    def test_listar_funcionarios(self):
        func_id = ObjectId()
        mock_db["usuarios"].find_one.return_value = self.admin
        mock_db["usuarios"].find.return_value = [
            {
                "_id": func_id,
                "nome": "Func 1",
                "email": "func1@empresa.com",
                "empresa_id": "empresa123",
                "role": "funcionario",
            }
        ]

        r = client.get("/empresa/funcionarios", headers=self.headers)
        assert r.status_code == 200
        assert r.json()[0]["nome"] == "Func 1"

    def test_listar_funcionarios_como_funcionario_retorna_403(self):
        func_id = make_object_id()
        mock_db["usuarios"].find_one.return_value = usuario_doc(func_id, role="funcionario")

        r = client.get("/empresa/funcionarios", headers=auth_headers(func_id))
        assert r.status_code == 403