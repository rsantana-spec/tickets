import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, make_response, request, send_file, send_from_directory
from flask_cors import CORS

try:
    from fpdf import FPDF
    FPDF_DISPONIBLE = True
except ImportError:
    FPDF_DISPONIBLE = False


# ==========================================
# CONFIGURACIÓN DE ARCHIVOS Y CONSTANTES
# ==========================================
BASE_DIR = Path(__file__).resolve().parent
IS_VERCEL = bool(os.environ.get("VERCEL") or os.environ.get("VERCEL_ENV"))
DATA_DIR = Path("/tmp/taquilla_data") if IS_VERCEL else BASE_DIR

ARCHIVO_USUARIOS = DATA_DIR / "usuarios.txt"
ARCHIVO_EVENTOS = DATA_DIR / "eventos.txt"
ARCHIVO_BOLETOS = DATA_DIR / "boletos.txt"
CARPETA_PDF = DATA_DIR / "boletos_pdf"
SEPARADOR = "|"

SESSION_COOKIE_NAME = "taquilla_session"
SESSION_TTL_SECONDS = 60 * 60 * 8
SESSION_SECRET = os.environ.get("SESSION_SECRET", "taquilla-espresso-vercel-secret-2026")
FOLIO_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
FECHA_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_LOCK_ARCHIVOS = threading.RLock()


# ==========================================
# MODELOS DE DATOS
# ==========================================
@dataclass
class Usuario:
    username: str
    nombre: str
    password_hash: str
    rol: str  # "admin" o "usuario"


@dataclass
class Evento:
    id: str
    nombre: str
    lugar: str
    fecha: str
    horarios: list[str]
    precio: float
    disponibles: int


@dataclass
class Boleto:
    folio: str
    username: str
    nombre_cliente: str
    evento_id: str
    evento_nombre: str
    lugar: str
    fecha: str
    horario: str
    cantidad: int
    total: float
    fecha_compra: str


# ==========================================
# UTILIDADES DE SEGURIDAD Y VALIDACIÓN
# ==========================================
def hashear_password(password: str) -> str:
    """Genera hash scrypt con sal aleatoria compatible con almacenamiento en .txt sin '|'."""
    salt = secrets.token_hex(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )
    return f"scrypt${salt}${dk.hex()}"


def verificar_password(password: str, stored_hash: str) -> bool:
    """Verifica hashes scrypt modernos y mantiene compatibilidad con SHA-256 previo."""
    if stored_hash.startswith("scrypt$"):
        partes = stored_hash.split("$")
        if len(partes) != 3:
            return False
        _, salt, expected_hex = partes
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            n=16384,
            r=8,
            p=1,
            dklen=32,
        )
        return hmac.compare_digest(dk.hex(), expected_hex)

    legacy_sha256 = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy_sha256, stored_hash)


def validar_texto_sin_separador(valor: Any, nombre_campo: str, max_len: int = 120) -> str:
    if not isinstance(valor, str):
        raise ValueError(f"El campo '{nombre_campo}' debe ser texto válido.")
    limpio = valor.strip()
    if not limpio:
        raise ValueError(f"El campo '{nombre_campo}' no puede quedar vacío.")
    if SEPARADOR in limpio or "\n" in limpio or "\r" in limpio:
        raise ValueError(f"No se permite usar el carácter '{SEPARADOR}' ni saltos de línea en '{nombre_campo}'.")
    if len(limpio) > max_len:
        raise ValueError(f"El campo '{nombre_campo}' excede el límite de {max_len} caracteres.")
    return limpio


def validar_entero(valor: Any, nombre_campo: str, minimo: int = 1, maximo: int | None = None) -> int:
    try:
        if isinstance(valor, bool):
            raise ValueError
        numero = int(valor)
    except (TypeError, ValueError):
        raise ValueError(f"El campo '{nombre_campo}' debe ser un número entero válido.")
    if numero < minimo:
        raise ValueError(f"El campo '{nombre_campo}' debe ser mayor o igual a {minimo}.")
    if maximo is not None and numero > maximo:
        raise ValueError(f"El campo '{nombre_campo}' debe ser menor o igual a {maximo}.")
    return numero


def validar_flotante(valor: Any, nombre_campo: str, minimo: float = 0.01) -> float:
    try:
        if isinstance(valor, bool):
            raise ValueError
        numero = float(valor)
    except (TypeError, ValueError):
        raise ValueError(f"El campo '{nombre_campo}' debe ser un monto numérico válido.")
    if numero < minimo:
        raise ValueError(f"El campo '{nombre_campo}' debe ser mayor o igual a {minimo}.")
    return round(numero, 2)


def crear_token_sesion(usuario: Usuario) -> str:
    payload = {
        "username": usuario.username,
        "rol": usuario.rol,
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    sig = hmac.new(
        SESSION_SECRET.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{sig}"


def verificar_token_sesion(token: str) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None
    try:
        payload_b64, sig = token.split(".", 1)
        expected_sig = hmac.new(
            SESSION_SECRET.encode("utf-8"),
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        padding = "=" * (-len(payload_b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8"))
        if int(data.get("exp", 0)) < int(time.time()):
            return None
        return data
    except Exception:
        return None


# ==========================================
# CAPA DE PERSISTENCIA EN ARCHIVOS .TXT
# ==========================================
class RepositorioTxt:
    """Gestiona la lectura y escritura en los archivos .txt manteniendo formato con '|'."""

    @staticmethod
    def inicializar() -> None:
        with _LOCK_ARCHIVOS:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            CARPETA_PDF.mkdir(parents=True, exist_ok=True)

            if IS_VERCEL:
                for nombre_archivo in ("usuarios.txt", "eventos.txt", "boletos.txt"):
                    origen = BASE_DIR / nombre_archivo
                    destino = DATA_DIR / nombre_archivo
                    if origen.exists() and not destino.exists():
                        shutil.copy2(origen, destino)

            if not ARCHIVO_USUARIOS.exists():
                admin_password = os.environ.get("ADMIN_INITIAL_PASSWORD", "admin123")
                admin_default = Usuario(
                    username="admin",
                    nombre="Administrador General",
                    password_hash=hashear_password(admin_password),
                    rol="admin",
                )
                RepositorioTxt.guardar_usuario(admin_default)

            if not ARCHIVO_EVENTOS.exists():
                eventos_iniciales = [
                    Evento(
                        id="EVT-101",
                        nombre="Concierto Filarmónica Nocturna",
                        lugar="Auditorio Telmex",
                        fecha="2026-12-05",
                        horarios=["18:00", "21:00"],
                        precio=650.00,
                        disponibles=120,
                    ),
                    Evento(
                        id="EVT-102",
                        nombre="Obra de Teatro: El Último Acto",
                        lugar="Teatro Diana",
                        fecha="2026-12-12",
                        horarios=["16:30", "19:30", "21:30"],
                        precio=420.00,
                        disponibles=80,
                    ),
                ]
                RepositorioTxt.guardar_todos_eventos(eventos_iniciales)

            if not ARCHIVO_BOLETOS.exists():
                ARCHIVO_BOLETOS.touch()

    @staticmethod
    def cargar_usuarios() -> list[Usuario]:
        with _LOCK_ARCHIVOS:
            usuarios: list[Usuario] = []
            if not ARCHIVO_USUARIOS.exists():
                return usuarios
            with ARCHIVO_USUARIOS.open("r", encoding="utf-8") as f:
                for linea in f:
                    linea = linea.strip()
                    if not linea:
                        continue
                    partes = linea.split(SEPARADOR)
                    if len(partes) == 4:
                        usuarios.append(Usuario(*partes))
            return usuarios

    @staticmethod
    def guardar_usuario(usuario: Usuario) -> None:
        with _LOCK_ARCHIVOS:
            linea = SEPARADOR.join([
                usuario.username,
                usuario.nombre,
                usuario.password_hash,
                usuario.rol,
            ])
            with ARCHIVO_USUARIOS.open("a", encoding="utf-8") as f:
                f.write(linea + "\n")

    @staticmethod
    def cargar_eventos() -> list[Evento]:
        with _LOCK_ARCHIVOS:
            eventos: list[Evento] = []
            if not ARCHIVO_EVENTOS.exists():
                return eventos
            with ARCHIVO_EVENTOS.open("r", encoding="utf-8") as f:
                for linea in f:
                    linea = linea.strip()
                    if not linea:
                        continue
                    partes = linea.split(SEPARADOR)
                    if len(partes) == 7:
                        eventos.append(
                            Evento(
                                id=partes[0],
                                nombre=partes[1],
                                lugar=partes[2],
                                fecha=partes[3],
                                horarios=[h for h in partes[4].split(";") if h],
                                precio=float(partes[5]),
                                disponibles=int(partes[6]),
                            )
                        )
            return eventos

    @staticmethod
    def guardar_todos_eventos(eventos: list[Evento]) -> None:
        with _LOCK_ARCHIVOS:
            with ARCHIVO_EVENTOS.open("w", encoding="utf-8") as f:
                for ev in eventos:
                    linea = SEPARADOR.join([
                        ev.id,
                        ev.nombre,
                        ev.lugar,
                        ev.fecha,
                        ";".join(ev.horarios),
                        f"{ev.precio:.2f}",
                        str(ev.disponibles),
                    ])
                    f.write(linea + "\n")

    @staticmethod
    def cargar_boletos() -> list[Boleto]:
        with _LOCK_ARCHIVOS:
            boletos: list[Boleto] = []
            if not ARCHIVO_BOLETOS.exists():
                return boletos
            with ARCHIVO_BOLETOS.open("r", encoding="utf-8") as f:
                for linea in f:
                    linea = linea.strip()
                    if not linea:
                        continue
                    partes = linea.split(SEPARADOR)
                    if len(partes) == 11:
                        boletos.append(
                            Boleto(
                                folio=partes[0],
                                username=partes[1],
                                nombre_cliente=partes[2],
                                evento_id=partes[3],
                                evento_nombre=partes[4],
                                lugar=partes[5],
                                fecha=partes[6],
                                horario=partes[7],
                                cantidad=int(partes[8]),
                                total=float(partes[9]),
                                fecha_compra=partes[10],
                            )
                        )
            return boletos

    @staticmethod
    def guardar_boleto(boleto: Boleto) -> None:
        with _LOCK_ARCHIVOS:
            linea = SEPARADOR.join([
                boleto.folio,
                boleto.username,
                boleto.nombre_cliente,
                boleto.evento_id,
                boleto.evento_nombre,
                boleto.lugar,
                boleto.fecha,
                boleto.horario,
                str(boleto.cantidad),
                f"{boleto.total:.2f}",
                boleto.fecha_compra,
            ])
            with ARCHIVO_BOLETOS.open("a", encoding="utf-8") as f:
                f.write(linea + "\n")


# ==========================================
# GENERACIÓN DE BOLETOS EN PDF
# ==========================================
def _texto_pdf(texto: str) -> str:
    return texto.encode("latin-1", "replace").decode("latin-1")


class GeneradorBoletoPDF:
    """Construye un archivo PDF con diseño de boleto imprimible."""

    @staticmethod
    def generar(boleto: Boleto) -> Path | None:
        if not FPDF_DISPONIBLE:
            return None

        CARPETA_PDF.mkdir(parents=True, exist_ok=True)
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.add_page()

        # Marco exterior del boleto (Café Espresso #4A3728)
        pdf.set_draw_color(74, 55, 40)
        pdf.set_line_width(0.8)
        pdf.rect(15, 20, 180, 115)

        # Encabezado Espresso (#4A3728)
        pdf.set_fill_color(74, 55, 40)
        pdf.rect(15, 20, 180, 22, style="F")

        pdf.set_xy(20, 25)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(110, 10, _texto_pdf("BOLETO OFICIAL DE ACCESO"))

        pdf.set_xy(130, 25)
        pdf.set_text_color(147, 197, 114)
        pdf.set_font("Courier", "B", 11)
        pdf.cell(60, 10, _texto_pdf(f"FOLIO: {boleto.folio}"), align="R")

        # Cuerpo del boleto - Datos del Evento
        pdf.set_text_color(74, 55, 40)
        pdf.set_xy(20, 48)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(170, 8, _texto_pdf(boleto.evento_nombre.upper()))

        pdf.set_text_color(111, 86, 67)
        pdf.set_xy(20, 58)
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(170, 7, _texto_pdf(f"Recinto / Lugar: {boleto.lugar}"))

        pdf.set_xy(20, 66)
        pdf.cell(85, 7, _texto_pdf(f"Fecha del evento: {boleto.fecha}"))
        pdf.set_xy(105, 66)
        pdf.set_text_color(74, 55, 40)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(85, 7, _texto_pdf(f"Horario: {boleto.horario} hrs"))

        # Línea divisoria
        pdf.set_draw_color(226, 220, 213)
        pdf.set_line_width(0.4)
        pdf.line(20, 78, 190, 78)

        # Datos del comprador y pago
        pdf.set_font("Helvetica", "", 11)
        pdf.set_xy(20, 83)
        pdf.cell(170, 7, _texto_pdf(f"Titular: {boleto.nombre_cliente} (@{boleto.username})"))

        pdf.set_xy(20, 91)
        pdf.cell(85, 7, _texto_pdf(f"Cantidad de accesos: {boleto.cantidad}"))
        pdf.set_xy(105, 91)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(85, 7, _texto_pdf(f"Total pagado: ${boleto.total:,.2f} MXN"))

        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(111, 86, 67)
        pdf.set_xy(20, 100)
        pdf.cell(170, 6, _texto_pdf(f"Fecha de emision: {boleto.fecha_compra} | ID Evento: {boleto.evento_id}"))

        # Pie de verificación (Verde Pistache suave #EDF5E8)
        pdf.set_fill_color(237, 245, 232)
        pdf.rect(15, 113, 180, 22, style="F")
        pdf.set_text_color(74, 55, 40)
        pdf.set_font("Courier", "B", 10)
        pdf.set_xy(20, 117)
        pdf.cell(
            170,
            6,
            _texto_pdf(f"|||| || | |||| ||| | ||||  {boleto.folio}-{boleto.evento_id}  |||| || | |||| ||| | ||||"),
            align="C",
        )
        pdf.set_font("Helvetica", "", 8)
        pdf.set_xy(20, 124)
        pdf.cell(
            170,
            5,
            _texto_pdf("Presenta este documento impreso o digital en el acceso principal."),
            align="C",
        )

        ruta_salida = (CARPETA_PDF / f"boleto_{boleto.folio}.pdf").resolve()
        if ruta_salida.parent != CARPETA_PDF.resolve():
            raise ValueError("Ruta de PDF inválida.")
        pdf.output(str(ruta_salida))
        return ruta_salida


# ==========================================
# APLICACIÓN WEB FLASK
# ==========================================
app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://127.0.0.1:5000",
                "http://localhost:5000",
                "http://127.0.0.1:3000",
                "http://localhost:3000",
            ]
        }
    },
    supports_credentials=True,
)

RepositorioTxt.inicializar()


def obtener_usuario_autenticado() -> Usuario | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
    if not token:
        return None
    datos = verificar_token_sesion(token)
    if not datos:
        return None
    username = datos.get("username")
    for u in RepositorioTxt.cargar_usuarios():
        if u.username == username:
            return u
    return None


def requerir_sesion(solo_admin: bool = False):
    def decorador(fn):
        @wraps(fn)
        def envoltura(*args, **kwargs):
            usuario = obtener_usuario_autenticado()
            if not usuario:
                return jsonify({"error": "Debes iniciar sesión para continuar."}), 401
            if solo_admin and usuario.rol != "admin":
                return jsonify({"error": "Acceso restringido a administradores."}), 403
            return fn(usuario, *args, **kwargs)
        return envoltura
    return decorador


def establecer_cookie_sesion(respuesta, usuario: Usuario):
    token = crear_token_sesion(usuario)
    es_https = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
    respuesta.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=es_https,
        samesite="None" if es_https else "Lax",
        path="/",
    )
    return token


@app.get("/")
def servir_inicio():
    return send_from_directory(str(BASE_DIR), "index.html")


@app.post("/api/login")
def api_login():
    datos = request.get_json(silent=True) or {}
    try:
        username = validar_texto_sin_separador(datos.get("username"), "usuario", max_len=50)
        password = validar_texto_sin_separador(datos.get("password"), "contraseña", max_len=120)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    for usuario in RepositorioTxt.cargar_usuarios():
        if usuario.username == username and verificar_password(password, usuario.password_hash):
            payload = {
                "username": usuario.username,
                "nombre": usuario.nombre,
                "rol": usuario.rol,
            }
            resp = make_response(jsonify(payload), 200)
            token = establecer_cookie_sesion(resp, usuario)
            resp.headers["X-Session-Token"] = token
            return resp

    return jsonify({"error": "Usuario o contraseña incorrectos."}), 401


@app.post("/api/register")
def api_register():
    datos = request.get_json(silent=True) or {}
    try:
        username = validar_texto_sin_separador(datos.get("username"), "usuario", max_len=40)
        nombre = validar_texto_sin_separador(datos.get("nombre"), "nombre completo", max_len=90)
        password = validar_texto_sin_separador(datos.get("password"), "contraseña", max_len=120)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    if " " in username:
        return jsonify({"error": "El nombre de usuario no puede contener espacios."}), 400
    if len(password) < 4:
        return jsonify({"error": "La contraseña debe tener al menos 4 caracteres."}), 400

    with _LOCK_ARCHIVOS:
        usuarios = RepositorioTxt.cargar_usuarios()
        if any(u.username.lower() == username.lower() for u in usuarios):
            return jsonify({"error": "Ese nombre de usuario ya está registrado."}), 409

        nuevo_usuario = Usuario(
            username=username,
            nombre=nombre,
            password_hash=hashear_password(password),
            rol="usuario",
        )
        RepositorioTxt.guardar_usuario(nuevo_usuario)

    payload = {
        "username": nuevo_usuario.username,
        "nombre": nuevo_usuario.nombre,
        "rol": nuevo_usuario.rol,
    }
    resp = make_response(jsonify(payload), 201)
    token = establecer_cookie_sesion(resp, nuevo_usuario)
    resp.headers["X-Session-Token"] = token
    return resp


@app.post("/api/logout")
def api_logout():
    resp = make_response(jsonify({"mensaje": "Sesión cerrada."}), 200)
    es_https = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
    resp.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        secure=es_https,
        samesite="None" if es_https else "Lax",
    )
    return resp


@app.get("/api/me")
def api_me():
    usuario = obtener_usuario_autenticado()
    if not usuario:
        return jsonify({"error": "No autenticado."}), 401
    return jsonify({
        "username": usuario.username,
        "nombre": usuario.nombre,
        "rol": usuario.rol,
    }), 200


@app.get("/api/eventos")
def api_eventos():
    eventos = RepositorioTxt.cargar_eventos()
    return jsonify([asdict(ev) for ev in eventos]), 200


@app.post("/api/comprar")
@requerir_sesion(solo_admin=False)
def api_comprar(usuario: Usuario):
    datos = request.get_json(silent=True) or {}
    try:
        evento_id = validar_texto_sin_separador(datos.get("evento_id"), "evento_id", max_len=32)
        horario = validar_texto_sin_separador(datos.get("horario"), "horario", max_len=20)
        cantidad = validar_entero(datos.get("cantidad"), "cantidad", minimo=1)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    with _LOCK_ARCHIVOS:
        eventos = RepositorioTxt.cargar_eventos()
        evento = next((ev for ev in eventos if ev.id == evento_id), None)
        if not evento:
            return jsonify({"error": "El evento seleccionado no existe."}), 404
        if evento.disponibles <= 0:
            return jsonify({"error": "Los boletos para este evento están agotados."}), 409
        if horario not in evento.horarios:
            return jsonify({"error": "El horario seleccionado no es válido para este evento."}), 400
        if cantidad > evento.disponibles:
            return jsonify({"error": f"Solo quedan {evento.disponibles} boletos disponibles."}), 409

        evento.disponibles -= cantidad
        RepositorioTxt.guardar_todos_eventos(eventos)

        folio = uuid.uuid4().hex[:8].upper()
        total = round(cantidad * evento.precio, 2)
        boleto = Boleto(
            folio=folio,
            username=usuario.username,
            nombre_cliente=usuario.nombre,
            evento_id=evento.id,
            evento_nombre=evento.nombre,
            lugar=evento.lugar,
            fecha=evento.fecha,
            horario=horario,
            cantidad=cantidad,
            total=total,
            fecha_compra=datetime.now().strftime("%Y-%m-%d %H:%M"),
        )
        RepositorioTxt.guardar_boleto(boleto)

    GeneradorBoletoPDF.generar(boleto)

    return jsonify({
        "mensaje": f"Compra confirmada. Folio {boleto.folio}.",
        "boleto": asdict(boleto),
        "disponibles_restantes": evento.disponibles,
    }), 201


@app.get("/api/mis-boletos/<username>")
@requerir_sesion(solo_admin=False)
def api_mis_boletos(usuario: Usuario, username: str):
    if SEPARADOR in username:
        return jsonify({"error": f"No se permite el carácter '{SEPARADOR}'."}), 400
    if usuario.username != username and usuario.rol != "admin":
        return jsonify({"error": "No tienes permiso para consultar estos boletos."}), 403

    boletos = [asdict(b) for b in RepositorioTxt.cargar_boletos() if b.username == username]
    boletos.reverse()
    return jsonify(boletos), 200


@app.get("/api/boletos/<folio>/pdf")
@requerir_sesion(solo_admin=False)
def api_descargar_pdf(usuario: Usuario, folio: str):
    if not FOLIO_REGEX.match(folio):
        return jsonify({"error": "Folio inválido."}), 400

    boletos = RepositorioTxt.cargar_boletos()
    boleto = next((b for b in boletos if b.folio == folio), None)
    if not boleto:
        return jsonify({"error": "Boleto no encontrado."}), 404
    if boleto.username != usuario.username and usuario.rol != "admin":
        return jsonify({"error": "No tienes permiso para descargar este boleto."}), 403

    ruta_pdf = (CARPETA_PDF / f"boleto_{boleto.folio}.pdf").resolve()
    if ruta_pdf.parent != CARPETA_PDF.resolve():
        return jsonify({"error": "Ruta inválida."}), 400

    if not ruta_pdf.exists():
        generada = GeneradorBoletoPDF.generar(boleto)
        if not generada or not generada.exists():
            return jsonify({"error": "No se pudo generar el PDF. Verifica que fpdf2 esté instalado."}), 500
        ruta_pdf = generada

    descargar = request.args.get("download", "1") == "1"
    return send_file(
        str(ruta_pdf),
        mimetype="application/pdf",
        as_attachment=descargar,
        download_name=f"boleto_{boleto.folio}.pdf",
    )


@app.post("/api/admin/eventos")
@requerir_sesion(solo_admin=True)
def api_admin_crear_evento(usuario: Usuario):
    datos = request.get_json(silent=True) or {}
    try:
        nombre = validar_texto_sin_separador(datos.get("nombre"), "nombre del evento", max_len=100)
        lugar = validar_texto_sin_separador(datos.get("lugar"), "lugar / recinto", max_len=100)
        fecha = validar_texto_sin_separador(datos.get("fecha"), "fecha", max_len=20)
        if not FECHA_REGEX.match(fecha):
            raise ValueError("La fecha debe tener formato YYYY-MM-DD.")

        raw_horarios = datos.get("horarios")
        if isinstance(raw_horarios, list):
            lista_horarios = [validar_texto_sin_separador(str(h), "horario", max_len=15) for h in raw_horarios if str(h).strip()]
        elif isinstance(raw_horarios, str):
            validar_texto_sin_separador(raw_horarios, "horarios", max_len=120)
            lista_horarios = [h.strip() for h in raw_horarios.split(",") if h.strip()]
        else:
            raise ValueError("Debes ingresar al menos un horario válido.")

        if not lista_horarios:
            raise ValueError("Debes ingresar al menos un horario válido.")
        for h in lista_horarios:
            if ";" in h or SEPARADOR in h:
                raise ValueError("Los horarios no pueden contener ';' ni '|'.")

        precio = validar_flotante(datos.get("precio"), "precio", minimo=1.0)
        disponibles = validar_entero(datos.get("disponibles"), "boletos disponibles", minimo=1)
    except ValueError as err:
        return jsonify({"error": str(err)}), 400

    with _LOCK_ARCHIVOS:
        eventos = RepositorioTxt.cargar_eventos()
        nuevo_id = f"EVT-{101 + len(eventos)}"
        ids_existentes = {ev.id for ev in eventos}
        contador = 101 + len(eventos)
        while nuevo_id in ids_existentes:
            contador += 1
            nuevo_id = f"EVT-{contador}"

        nuevo_evento = Evento(
            id=nuevo_id,
            nombre=nombre,
            lugar=lugar,
            fecha=fecha,
            horarios=lista_horarios,
            precio=precio,
            disponibles=disponibles,
        )
        eventos.append(nuevo_evento)
        RepositorioTxt.guardar_todos_eventos(eventos)

    return jsonify({
        "mensaje": f"Evento '{nombre}' registrado con ID {nuevo_id}.",
        "evento": asdict(nuevo_evento),
    }), 201


@app.get("/api/admin/ventas")
@requerir_sesion(solo_admin=True)
def api_admin_ventas(usuario: Usuario):
    boletos = RepositorioTxt.cargar_boletos()
    total_recaudado = round(sum(b.total for b in boletos), 2)
    total_boletos = sum(b.cantidad for b in boletos)
    lista = [asdict(b) for b in reversed(boletos)]
    return jsonify({
        "boletos": lista,
        "total_recaudado": total_recaudado,
        "total_boletos": total_boletos,
    }), 200


if __name__ == "__main__":
    RepositorioTxt.inicializar()
    app.run(host="0.0.0.0", port=5000, debug=False)
