import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import express, { Request, Response, NextFunction } from 'express';
import PDFDocument from 'pdfkit';
import { createServer as createViteServer } from 'vite';

const BASE_DIR = process.cwd();
const ARCHIVO_USUARIOS = path.join(BASE_DIR, 'usuarios.txt');
const ARCHIVO_EVENTOS = path.join(BASE_DIR, 'eventos.txt');
const ARCHIVO_BOLETOS = path.join(BASE_DIR, 'boletos.txt');
const CARPETA_PDF = path.join(BASE_DIR, 'boletos_pdf');
const SEPARADOR = '|';

const SESSION_COOKIE_NAME = 'taquilla_session';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const FOLIO_REGEX = /^[A-Za-z0-9_-]{1,32}$/;
const FECHA_REGEX = /^\d{4}-\d{2}-\d{2}$/;

interface Usuario {
  username: string;
  nombre: string;
  password_hash: string;
  rol: 'admin' | 'usuario';
}

interface Evento {
  id: string;
  nombre: string;
  lugar: string;
  fecha: string;
  horarios: string[];
  precio: number;
  disponibles: number;
}

interface Boleto {
  folio: string;
  username: string;
  nombre_cliente: string;
  evento_id: string;
  evento_nombre: string;
  lugar: string;
  fecha: string;
  horario: string;
  cantidad: number;
  total: number;
  fecha_compra: string;
}

interface AuthenticatedRequest extends Request {
  usuario?: Usuario;
}

function hashearPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const dk = crypto.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt}$${dk.toString('hex')}`;
}

function verificarPassword(password: string, storedHash: string): boolean {
  if (storedHash.startsWith('scrypt$')) {
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;
    const [, salt, expectedHex] = parts;
    const dk = crypto.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
    const expectedBuf = Buffer.from(expectedHex, 'hex');
    if (dk.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(dk, expectedBuf);
  }
  const legacySha = crypto.createHash('sha256').update(password, 'utf8').digest('hex');
  const a = Buffer.from(legacySha, 'utf8');
  const b = Buffer.from(storedHash, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function validarTextoSinSeparador(valor: unknown, nombreCampo: string, maxLen = 120): string {
  if (typeof valor !== 'string') {
    throw new Error(`El campo '${nombreCampo}' debe ser texto válido.`);
  }
  const limpio = valor.trim();
  if (!limpio) {
    throw new Error(`El campo '${nombreCampo}' no puede quedar vacío.`);
  }
  if (limpio.includes(SEPARADOR) || limpio.includes('\n') || limpio.includes('\r')) {
    throw new Error(`No se permite usar el carácter '${SEPARADOR}' ni saltos de línea en '${nombreCampo}'.`);
  }
  if (limpio.length > maxLen) {
    throw new Error(`El campo '${nombreCampo}' excede el límite de ${maxLen} caracteres.`);
  }
  return limpio;
}

function validarEntero(valor: unknown, nombreCampo: string, minimo = 1, maximo?: number): number {
  if (typeof valor === 'boolean' || valor === null || valor === undefined || valor === '') {
    throw new Error(`El campo '${nombreCampo}' debe ser un número entero válido.`);
  }
  const numero = Number(valor);
  if (!Number.isInteger(numero)) {
    throw new Error(`El campo '${nombreCampo}' debe ser un número entero válido.`);
  }
  if (numero < minimo) {
    throw new Error(`El campo '${nombreCampo}' debe ser mayor o igual a ${minimo}.`);
  }
  if (maximo !== undefined && numero > maximo) {
    throw new Error(`El campo '${nombreCampo}' debe ser menor o igual a ${maximo}.`);
  }
  return numero;
}

function validarFlotante(valor: unknown, nombreCampo: string, minimo = 0.01): number {
  if (typeof valor === 'boolean' || valor === null || valor === undefined || valor === '') {
    throw new Error(`El campo '${nombreCampo}' debe ser un monto numérico válido.`);
  }
  const numero = Number(valor);
  if (!Number.isFinite(numero)) {
    throw new Error(`El campo '${nombreCampo}' debe ser un monto numérico válido.`);
  }
  if (numero < minimo) {
    throw new Error(`El campo '${nombreCampo}' debe ser mayor o igual a ${minimo}.`);
  }
  return Math.round(numero * 100) / 100;
}

function crearTokenSesion(usuario: Usuario): string {
  const payload = {
    username: usuario.username,
    rol: usuario.rol,
    exp: Date.now() + SESSION_TTL_MS,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payloadB64).digest('hex');
  return `${payloadB64}.${sig}`;
}

function verificarTokenSesion(token: string): { username: string; rol: string; exp: number } | null {
  if (!token || !token.includes('.')) return null;
  try {
    const dotIdx = token.indexOf('.');
    const payloadB64 = token.slice(0, dotIdx);
    const sig = token.slice(dotIdx + 1);
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payloadB64).digest('hex');
    const sigBuf = Buffer.from(sig, 'utf8');
    const expBuf = Buffer.from(expectedSig, 'utf8');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    const parsed = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (typeof parsed.exp !== 'number' || parsed.exp < Date.now()) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    result[key] = val;
  }
  return result;
}

class RepositorioTxt {
  static inicializar(): void {
    fs.mkdirSync(CARPETA_PDF, { recursive: true });

    if (!fs.existsSync(ARCHIVO_USUARIOS)) {
      const adminPassword = process.env.ADMIN_INITIAL_PASSWORD || 'admin123';
      const adminDefault: Usuario = {
        username: 'admin',
        nombre: 'Administrador General',
        password_hash: hashearPassword(adminPassword),
        rol: 'admin',
      };
      RepositorioTxt.guardarUsuario(adminDefault);
    }

    if (!fs.existsSync(ARCHIVO_EVENTOS)) {
      const eventosIniciales: Evento[] = [
        {
          id: 'EVT-101',
          nombre: 'Concierto Filarmónica Nocturna',
          lugar: 'Auditorio Telmex',
          fecha: '2026-12-05',
          horarios: ['18:00', '21:00'],
          precio: 650.0,
          disponibles: 120,
        },
        {
          id: 'EVT-102',
          nombre: 'Obra de Teatro: El Último Acto',
          lugar: 'Teatro Diana',
          fecha: '2026-12-12',
          horarios: ['16:30', '19:30', '21:30'],
          precio: 420.0,
          disponibles: 80,
        },
      ];
      RepositorioTxt.guardarTodosEventos(eventosIniciales);
    }

    if (!fs.existsSync(ARCHIVO_BOLETOS)) {
      fs.writeFileSync(ARCHIVO_BOLETOS, '', 'utf8');
    }
  }

  static cargarUsuarios(): Usuario[] {
    if (!fs.existsSync(ARCHIVO_USUARIOS)) return [];
    const lines = fs.readFileSync(ARCHIVO_USUARIOS, 'utf8').split(/\r?\n/);
    const usuarios: Usuario[] = [];
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      const partes = line.split(SEPARADOR);
      if (partes.length === 4) {
        usuarios.push({
          username: partes[0],
          nombre: partes[1],
          password_hash: partes[2],
          rol: partes[3] === 'admin' ? 'admin' : 'usuario',
        });
      }
    }
    return usuarios;
  }

  static guardarUsuario(usuario: Usuario): void {
    const linea = [usuario.username, usuario.nombre, usuario.password_hash, usuario.rol].join(SEPARADOR);
    fs.appendFileSync(ARCHIVO_USUARIOS, linea + '\n', 'utf8');
  }

  static cargarEventos(): Evento[] {
    if (!fs.existsSync(ARCHIVO_EVENTOS)) return [];
    const lines = fs.readFileSync(ARCHIVO_EVENTOS, 'utf8').split(/\r?\n/);
    const eventos: Evento[] = [];
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      const partes = line.split(SEPARADOR);
      if (partes.length === 7) {
        eventos.push({
          id: partes[0],
          nombre: partes[1],
          lugar: partes[2],
          fecha: partes[3],
          horarios: partes[4].split(';').filter(Boolean),
          precio: parseFloat(partes[5]),
          disponibles: parseInt(partes[6], 10),
        });
      }
    }
    return eventos;
  }

  static guardarTodosEventos(eventos: Evento[]): void {
    const content = eventos
      .map((ev) =>
        [
          ev.id,
          ev.nombre,
          ev.lugar,
          ev.fecha,
          ev.horarios.join(';'),
          ev.precio.toFixed(2),
          String(ev.disponibles),
        ].join(SEPARADOR)
      )
      .join('\n');
    fs.writeFileSync(ARCHIVO_EVENTOS, content ? content + '\n' : '', 'utf8');
  }

  static cargarBoletos(): Boleto[] {
    if (!fs.existsSync(ARCHIVO_BOLETOS)) return [];
    const lines = fs.readFileSync(ARCHIVO_BOLETOS, 'utf8').split(/\r?\n/);
    const boletos: Boleto[] = [];
    for (const raw of lines) {
      const line = raw.trim();
      if (!line) continue;
      const partes = line.split(SEPARADOR);
      if (partes.length === 11) {
        boletos.push({
          folio: partes[0],
          username: partes[1],
          nombre_cliente: partes[2],
          evento_id: partes[3],
          evento_nombre: partes[4],
          lugar: partes[5],
          fecha: partes[6],
          horario: partes[7],
          cantidad: parseInt(partes[8], 10),
          total: parseFloat(partes[9]),
          fecha_compra: partes[10],
        });
      }
    }
    return boletos;
  }

  static guardarBoleto(boleto: Boleto): void {
    const linea = [
      boleto.folio,
      boleto.username,
      boleto.nombre_cliente,
      boleto.evento_id,
      boleto.evento_nombre,
      boleto.lugar,
      boleto.fecha,
      boleto.horario,
      String(boleto.cantidad),
      boleto.total.toFixed(2),
      boleto.fecha_compra,
    ].join(SEPARADOR);
    fs.appendFileSync(ARCHIVO_BOLETOS, linea + '\n', 'utf8');
  }
}

class GeneradorBoletoPDF {
  static async generar(boleto: Boleto): Promise<string> {
    fs.mkdirSync(CARPETA_PDF, { recursive: true });
    const baseDir = path.resolve(CARPETA_PDF);
    const rutaSalida = path.resolve(baseDir, `boleto_${boleto.folio}.pdf`);
    if (!rutaSalida.startsWith(baseDir + path.sep)) {
      throw new Error('Ruta de PDF inválida.');
    }

    await new Promise<void>((resolve, reject) => {
      const doc = new PDFDocument({ size: 'A4', margin: 40 });
      const stream = fs.createWriteStream(rutaSalida);
      doc.pipe(stream);

      const left = 42;
      const top = 56;
      const width = 510;
      const height = 326;

      doc.lineWidth(2).strokeColor('#4A3728').rect(left, top, width, height).stroke();
      doc.fillColor('#4A3728').rect(left, top, width, 62).fill();

      doc.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(15).text('BOLETO OFICIAL DE ACCESO', left + 16, top + 22);
      doc.fillColor('#93C572').font('Courier-Bold').fontSize(12).text(`FOLIO: ${boleto.folio}`, left + 310, top + 23, {
        width: 184,
        align: 'right',
      });

      doc.fillColor('#4A3728').font('Helvetica-Bold').fontSize(15).text(boleto.evento_nombre.toUpperCase(), left + 16, top + 82, {
        width: width - 32,
      });

      doc.fillColor('#6F5643').font('Helvetica').fontSize(11).text(`Recinto / Lugar: ${boleto.lugar}`, left + 16, top + 114);
      doc.text(`Fecha del evento: ${boleto.fecha}`, left + 16, top + 136);
      doc.fillColor('#4A3728').font('Helvetica-Bold').text(`Horario: ${boleto.horario} hrs`, left + 270, top + 136);

      doc.lineWidth(1).strokeColor('#E2DCD5').moveTo(left + 16, top + 166).lineTo(left + width - 16, top + 166).stroke();

      doc.fillColor('#4A3728').font('Helvetica').fontSize(11).text(`Titular: ${boleto.nombre_cliente} (@${boleto.username})`, left + 16, top + 182);
      doc.text(`Cantidad de accesos: ${boleto.cantidad}`, left + 16, top + 204);
      doc.font('Helvetica-Bold').fontSize(12).text(`Total pagado: $${boleto.total.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} MXN`, left + 270, top + 203);

      doc.fillColor('#6F5643').font('Helvetica-Oblique').fontSize(9).text(`Fecha de emisión: ${boleto.fecha_compra} | ID Evento: ${boleto.evento_id}`, left + 16, top + 230);

      doc.fillColor('#EDF5E8').rect(left + 1, top + 264, width - 2, 61).fill();
      doc.fillColor('#4A3728').font('Courier-Bold').fontSize(10).text(`|||| || | |||| ||| | ||||  ${boleto.folio}-${boleto.evento_id}  |||| || | |||| ||| | ||||`, left + 16, top + 280, {
        width: width - 32,
        align: 'center',
      });
      doc.font('Helvetica').fontSize(8.5).text('Presenta este documento impreso o digital en el acceso principal.', left + 16, top + 298, {
        width: width - 32,
        align: 'center',
      });

      doc.end();
      stream.on('finish', () => resolve());
      stream.on('error', reject);
    });

    return rutaSalida;
  }
}

function obtenerUsuarioAutenticado(req: Request): Usuario | null {
  const cookies = parseCookies(req.headers.cookie);
  let token = cookies[SESSION_COOKIE_NAME];
  if (!token) {
    const auth = req.headers.authorization || '';
    if (auth.startsWith('Bearer ')) {
      token = auth.slice(7).trim();
    }
  }
  if (!token) return null;
  const datos = verificarTokenSesion(token);
  if (!datos) return null;
  const usuarios = RepositorioTxt.cargarUsuarios();
  return usuarios.find((u) => u.username === datos.username) || null;
}

function requerirSesion(soloAdmin = false) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const usuario = obtenerUsuarioAutenticado(req);
    if (!usuario) {
      res.status(401).json({ error: 'Debes iniciar sesión para continuar.' });
      return;
    }
    if (soloAdmin && usuario.rol !== 'admin') {
      res.status(403).json({ error: 'Acceso restringido a administradores.' });
      return;
    }
    req.usuario = usuario;
    next();
  };
}

function establecerCookieSesion(req: Request, res: Response, usuario: Usuario): string {
  const token = crearTokenSesion(usuario);
  const esHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const cookieParts = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    'Path=/',
    'HttpOnly',
    esHttps ? 'SameSite=None' : 'SameSite=Lax',
  ];
  if (esHttps) {
    cookieParts.push('Secure', 'Partitioned');
  }
  res.setHeader('Set-Cookie', cookieParts.join('; '));
  return token;
}

function formatearFechaHoraNow(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}`;
}

async function startServer() {
  RepositorioTxt.inicializar();
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());

  app.post('/api/login', (req, res) => {
    try {
      const username = validarTextoSinSeparador(req.body?.username, 'usuario', 50);
      const password = validarTextoSinSeparador(req.body?.password, 'contraseña', 120);
      const usuario = RepositorioTxt.cargarUsuarios().find(
        (u) => u.username === username && verificarPassword(password, u.password_hash)
      );
      if (!usuario) {
        res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
        return;
      }
      const token = establecerCookieSesion(req, res, usuario);
      res.setHeader('X-Session-Token', token);
      res.status(200).json({
        username: usuario.username,
        nombre: usuario.nombre,
        rol: usuario.rol,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Datos inválidos.' });
    }
  });

  app.post('/api/register', (req, res) => {
    try {
      const username = validarTextoSinSeparador(req.body?.username, 'usuario', 40);
      const nombre = validarTextoSinSeparador(req.body?.nombre, 'nombre completo', 90);
      const password = validarTextoSinSeparador(req.body?.password, 'contraseña', 120);

      if (username.includes(' ')) {
        res.status(400).json({ error: 'El nombre de usuario no puede contener espacios.' });
        return;
      }
      if (password.length < 4) {
        res.status(400).json({ error: 'La contraseña debe tener al menos 4 caracteres.' });
        return;
      }

      const usuarios = RepositorioTxt.cargarUsuarios();
      if (usuarios.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
        res.status(409).json({ error: 'Ese nombre de usuario ya está registrado.' });
        return;
      }

      const nuevoUsuario: Usuario = {
        username,
        nombre,
        password_hash: hashearPassword(password),
        rol: 'usuario',
      };
      RepositorioTxt.guardarUsuario(nuevoUsuario);

      const token = establecerCookieSesion(req, res, nuevoUsuario);
      res.setHeader('X-Session-Token', token);
      res.status(201).json({
        username: nuevoUsuario.username,
        nombre: nuevoUsuario.nombre,
        rol: nuevoUsuario.rol,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Datos inválidos.' });
    }
  });

  app.post('/api/logout', (req, res) => {
    const esHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
    const cookieParts = [
      `${SESSION_COOKIE_NAME}=`,
      'Max-Age=0',
      'Path=/',
      'HttpOnly',
      esHttps ? 'SameSite=None' : 'SameSite=Lax',
    ];
    if (esHttps) cookieParts.push('Secure', 'Partitioned');
    res.setHeader('Set-Cookie', cookieParts.join('; '));
    res.status(200).json({ mensaje: 'Sesión cerrada.' });
  });

  app.get('/api/me', (req, res) => {
    const usuario = obtenerUsuarioAutenticado(req);
    if (!usuario) {
      res.status(401).json({ error: 'No autenticado.' });
      return;
    }
    res.status(200).json({
      username: usuario.username,
      nombre: usuario.nombre,
      rol: usuario.rol,
    });
  });

  app.get('/api/eventos', (_req, res) => {
    res.status(200).json(RepositorioTxt.cargarEventos());
  });

  app.post('/api/comprar', requerirSesion(false), async (req: AuthenticatedRequest, res) => {
    try {
      const usuario = req.usuario!;
      const eventoId = validarTextoSinSeparador(req.body?.evento_id, 'evento_id', 32);
      const horario = validarTextoSinSeparador(req.body?.horario, 'horario', 20);
      const cantidad = validarEntero(req.body?.cantidad, 'cantidad', 1);

      const eventos = RepositorioTxt.cargarEventos();
      const evento = eventos.find((ev) => ev.id === eventoId);
      if (!evento) {
        res.status(404).json({ error: 'El evento seleccionado no existe.' });
        return;
      }
      if (evento.disponibles <= 0) {
        res.status(409).json({ error: 'Los boletos para este evento están agotados.' });
        return;
      }
      if (!evento.horarios.includes(horario)) {
        res.status(400).json({ error: 'El horario seleccionado no es válido para este evento.' });
        return;
      }
      if (cantidad > evento.disponibles) {
        res.status(409).json({ error: `Solo quedan ${evento.disponibles} boletos disponibles.` });
        return;
      }

      evento.disponibles -= cantidad;
      RepositorioTxt.guardarTodosEventos(eventos);

      const folio = crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase();
      const total = Math.round(cantidad * evento.precio * 100) / 100;
      const boleto: Boleto = {
        folio,
        username: usuario.username,
        nombre_cliente: usuario.nombre,
        evento_id: evento.id,
        evento_nombre: evento.nombre,
        lugar: evento.lugar,
        fecha: evento.fecha,
        horario,
        cantidad,
        total,
        fecha_compra: formatearFechaHoraNow(),
      };
      RepositorioTxt.guardarBoleto(boleto);
      await GeneradorBoletoPDF.generar(boleto);

      res.status(201).json({
        mensaje: `Compra confirmada. Folio ${boleto.folio}.`,
        boleto,
        disponibles_restantes: evento.disponibles,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Error al procesar la compra.' });
    }
  });

  app.get('/api/mis-boletos/:username', requerirSesion(false), (req: AuthenticatedRequest, res) => {
    const usuario = req.usuario!;
    const targetUsername = req.params.username;
    if (targetUsername.includes(SEPARADOR)) {
      res.status(400).json({ error: `No se permite el carácter '${SEPARADOR}'.` });
      return;
    }
    if (usuario.username !== targetUsername && usuario.rol !== 'admin') {
      res.status(403).json({ error: 'No tienes permiso para consultar estos boletos.' });
      return;
    }
    const boletos = RepositorioTxt.cargarBoletos().filter((b) => b.username === targetUsername).reverse();
    res.status(200).json(boletos);
  });

  app.get('/api/boletos/:folio/pdf', requerirSesion(false), async (req: AuthenticatedRequest, res) => {
    const usuario = req.usuario!;
    const folio = req.params.folio;
    if (!FOLIO_REGEX.test(folio)) {
      res.status(400).json({ error: 'Folio inválido.' });
      return;
    }
    const boleto = RepositorioTxt.cargarBoletos().find((b) => b.folio === folio);
    if (!boleto) {
      res.status(404).json({ error: 'Boleto no encontrado.' });
      return;
    }
    if (boleto.username !== usuario.username && usuario.rol !== 'admin') {
      res.status(403).json({ error: 'No tienes permiso para descargar este boleto.' });
      return;
    }

    const baseDir = path.resolve(CARPETA_PDF);
    const rutaPdf = path.resolve(baseDir, `boleto_${boleto.folio}.pdf`);
    if (!rutaPdf.startsWith(baseDir + path.sep)) {
      res.status(400).json({ error: 'Ruta inválida.' });
      return;
    }
    if (!fs.existsSync(rutaPdf)) {
      await GeneradorBoletoPDF.generar(boleto);
    }

    const descargar = req.query.download !== '0';
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `${descargar ? 'attachment' : 'inline'}; filename="boleto_${boleto.folio}.pdf"`
    );
    res.sendFile(rutaPdf);
  });

  app.post('/api/admin/eventos', requerirSesion(true), (req: AuthenticatedRequest, res) => {
    try {
      const nombre = validarTextoSinSeparador(req.body?.nombre, 'nombre del evento', 100);
      const lugar = validarTextoSinSeparador(req.body?.lugar, 'lugar / recinto', 100);
      const fecha = validarTextoSinSeparador(req.body?.fecha, 'fecha', 20);
      if (!FECHA_REGEX.test(fecha)) {
        throw new Error('La fecha debe tener formato YYYY-MM-DD.');
      }

      const rawHorarios = req.body?.horarios;
      let listaHorarios: string[] = [];
      if (Array.isArray(rawHorarios)) {
        listaHorarios = rawHorarios
          .map((h) => validarTextoSinSeparador(String(h), 'horario', 15))
          .filter(Boolean);
      } else if (typeof rawHorarios === 'string') {
        validarTextoSinSeparador(rawHorarios, 'horarios', 120);
        listaHorarios = rawHorarios
          .split(',')
          .map((h) => h.trim())
          .filter(Boolean);
      } else {
        throw new Error('Debes ingresar al menos un horario válido.');
      }

      if (listaHorarios.length === 0) {
        throw new Error('Debes ingresar al menos un horario válido.');
      }
      for (const h of listaHorarios) {
        if (h.includes(';') || h.includes(SEPARADOR)) {
          throw new Error("Los horarios no pueden contener ';' ni '|'.");
        }
      }

      const precio = validarFlotante(req.body?.precio, 'precio', 1);
      const disponibles = validarEntero(req.body?.disponibles, 'boletos disponibles', 1);

      const eventos = RepositorioTxt.cargarEventos();
      const idsExistentes = new Set(eventos.map((e) => e.id));
      let contador = 101 + eventos.length;
      let nuevoId = `EVT-${contador}`;
      while (idsExistentes.has(nuevoId)) {
        contador += 1;
        nuevoId = `EVT-${contador}`;
      }

      const nuevoEvento: Evento = {
        id: nuevoId,
        nombre,
        lugar,
        fecha,
        horarios: listaHorarios,
        precio,
        disponibles,
      };
      eventos.push(nuevoEvento);
      RepositorioTxt.guardarTodosEventos(eventos);

      res.status(201).json({
        mensaje: `Evento '${nombre}' registrado con ID ${nuevoId}.`,
        evento: nuevoEvento,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Datos inválidos.' });
    }
  });

  app.get('/api/admin/ventas', requerirSesion(true), (_req, res) => {
    const boletos = RepositorioTxt.cargarBoletos();
    const totalRecaudado = Math.round(boletos.reduce((acc, b) => acc + b.total, 0) * 100) / 100;
    const totalBoletos = boletos.reduce((acc, b) => acc + b.cantidad, 0);
    res.status(200).json({
      boletos: [...boletos].reverse(),
      total_recaudado: totalRecaudado,
      total_boletos: totalBoletos,
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.join(BASE_DIR, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor Taquilla Espresso activo en http://0.0.0.0:${PORT}`);
  });
}

startServer();
