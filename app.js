const SESSION_STORAGE_KEY = 'taquilla_espresso_session';
const FORBIDDEN_CHAR = '|';

const state = {
  user: null,
  sessionToken: null,
  activeView: 'cartelera',
  eventos: [],
  misBoletos: [],
  ventasAdmin: { boletos: [], total_recaudado: 0, total_boletos: 0 },
  filtroDisponibilidad: 'todos',
  busquedaEventos: '',
  busquedaVentas: '',
  selectedHorarios: {},
  compraActiva: {
    evento: null,
    horario: '',
    cantidad: 1,
    ultimoBoleto: null,
  },
  pendingCompraEventId: null,
};

const el = {
  navLinks: document.querySelectorAll('.nav-link'),
  navCartelera: document.getElementById('nav-cartelera'),
  navMisBoletos: document.getElementById('nav-mis-boletos'),
  navAdmin: document.getElementById('nav-admin'),
  brandLink: document.getElementById('brand-link'),

  userGreeting: document.getElementById('user-greeting'),
  btnOpenAuth: document.getElementById('btn-open-auth'),
  btnLogout: document.getElementById('btn-logout'),

  viewCartelera: document.getElementById('view-cartelera'),
  viewMisBoletos: document.getElementById('view-mis-boletos'),
  viewAdmin: document.getElementById('view-admin'),

  searchEventos: document.getElementById('search-eventos'),
  filterTodos: document.getElementById('filter-todos'),
  filterDisponibles: document.getElementById('filter-disponibles'),
  eventosGrid: document.getElementById('eventos-grid'),

  misBoletosContainer: document.getElementById('mis-boletos-container'),
  btnRefreshBoletos: document.getElementById('btn-refresh-boletos'),

  btnRefreshAdmin: document.getElementById('btn-refresh-admin'),
  kpiEventos: document.getElementById('kpi-eventos'),
  kpiBoletos: document.getElementById('kpi-boletos'),
  kpiRecaudado: document.getElementById('kpi-recaudado'),
  formAdminEvento: document.getElementById('form-admin-evento'),
  searchVentas: document.getElementById('search-ventas'),
  adminVentasTbody: document.getElementById('admin-ventas-tbody'),

  authModal: document.getElementById('auth-modal'),
  btnCloseAuth: document.getElementById('btn-close-auth'),
  tabLogin: document.getElementById('tab-login'),
  tabRegister: document.getElementById('tab-register'),
  formLogin: document.getElementById('form-login'),
  formRegister: document.getElementById('form-register'),
  loginUsername: document.getElementById('login-username'),
  loginPassword: document.getElementById('login-password'),
  regUsername: document.getElementById('reg-username'),
  regNombre: document.getElementById('reg-nombre'),
  regPassword: document.getElementById('reg-password'),

  compraModal: document.getElementById('compra-modal'),
  btnCloseCompra: document.getElementById('btn-close-compra'),
  compraStepForm: document.getElementById('compra-step-form'),
  compraStepSuccess: document.getElementById('compra-step-success'),
  compraEventoId: document.getElementById('compra-evento-id'),
  compraEventoNombre: document.getElementById('compra-evento-nombre'),
  compraEventoMeta: document.getElementById('compra-evento-meta'),
  compraHorariosList: document.getElementById('compra-horarios-list'),
  compraCantidad: document.getElementById('compra-cantidad'),
  btnQtyMinus: document.getElementById('btn-qty-minus'),
  btnQtyPlus: document.getElementById('btn-qty-plus'),
  compraDisponibles: document.getElementById('compra-disponibles'),
  compraDesglose: document.getElementById('compra-desglose'),
  compraTotal: document.getElementById('compra-total'),
  btnCancelCompra: document.getElementById('btn-cancel-compra'),
  btnConfirmCompra: document.getElementById('btn-confirm-compra'),
  successFolio: document.getElementById('success-folio'),
  successReceiptDetails: document.getElementById('success-receipt-details'),
  btnGoMisBoletos: document.getElementById('btn-go-mis-boletos'),
  btnDownloadNewPdf: document.getElementById('btn-download-new-pdf'),

  toastContainer: document.getElementById('toast-container'),
};

function formatCurrency(amount) {
  return `$${Number(amount).toLocaleString('es-MX', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })} MXN`;
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type === 'success' ? 'toast-success' : type === 'error' ? 'toast-error' : ''}`;
  toast.setAttribute('role', 'status');

  const textSpan = document.createElement('span');
  textSpan.textContent = message;

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'toast-close';
  closeBtn.setAttribute('aria-label', 'Cerrar notificación');
  closeBtn.textContent = '×';
  closeBtn.addEventListener('click', () => toast.remove());

  toast.append(textSpan, closeBtn);
  el.toastContainer.appendChild(toast);

  window.setTimeout(() => {
    if (toast.isConnected) {
      toast.remove();
    }
  }, 4200);
}

function containsPipe(value) {
  return typeof value === 'string' && value.includes(FORBIDDEN_CHAR);
}

function attachPipeGuard(input) {
  input.addEventListener('keydown', (event) => {
    if (event.key === FORBIDDEN_CHAR) {
      event.preventDefault();
      showToast('El carácter "|" no está permitido en los campos de texto.', 'error');
    }
  });

  input.addEventListener('input', () => {
    if (input.value.includes(FORBIDDEN_CHAR)) {
      input.value = input.value.replaceAll(FORBIDDEN_CHAR, '');
      showToast('Se eliminó el carácter "|" porque no está permitido.', 'error');
    }
  });
}

async function apiFetch(url, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (state.sessionToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${state.sessionToken}`);
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });

  const tokenHeader = response.headers.get('X-Session-Token');
  if (tokenHeader) {
    state.sessionToken = tokenHeader;
  }

  return response;
}

function saveSessionUser(user) {
  state.user = user;
  if (user) {
    sessionStorage.setItem(
      SESSION_STORAGE_KEY,
      JSON.stringify({
        username: user.username,
        nombre: user.nombre,
        rol: user.rol,
      })
    );
  } else {
    state.sessionToken = null;
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
  }
  updateAuthUI();
}

function updateAuthUI() {
  const isLogged = Boolean(state.user);
  const isAdmin = isLogged && state.user.rol === 'admin';

  el.navAdmin.classList.toggle('hidden', !isAdmin);
  el.btnOpenAuth.classList.toggle('hidden', isLogged);
  el.btnLogout.classList.toggle('hidden', !isLogged);
  el.userGreeting.classList.toggle('hidden', !isLogged);

  if (isLogged) {
    const rolLabel = isAdmin ? 'Admin' : 'Usuario';
    el.userGreeting.textContent = `${state.user.nombre} (${rolLabel})`;
  } else {
    el.userGreeting.textContent = '';
    if (state.activeView === 'admin') {
      switchView('cartelera');
    }
  }
}

function switchView(viewName) {
  if (viewName === 'admin' && state.user?.rol !== 'admin') {
    showToast('Acceso exclusivo para administradores.', 'error');
    viewName = 'cartelera';
  }

  state.activeView = viewName;

  el.navLinks.forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.view === viewName);
  });

  el.viewCartelera.classList.toggle('hidden', viewName !== 'cartelera');
  el.viewMisBoletos.classList.toggle('hidden', viewName !== 'mis-boletos');
  el.viewAdmin.classList.toggle('hidden', viewName !== 'admin');

  if (viewName === 'cartelera') {
    cargarEventos();
  } else if (viewName === 'mis-boletos') {
    cargarMisBoletos();
  } else if (viewName === 'admin') {
    cargarDatosAdmin();
  }
}

function openAuthModal(tab = 'login') {
  setAuthTab(tab);
  el.authModal.classList.remove('hidden');
  if (tab === 'login') {
    el.loginUsername.focus();
  } else {
    el.regUsername.focus();
  }
}

function closeAuthModal() {
  el.authModal.classList.add('hidden');
}

function setAuthTab(tab) {
  const isLogin = tab === 'login';
  el.tabLogin.classList.toggle('active', isLogin);
  el.tabRegister.classList.toggle('active', !isLogin);
  el.tabLogin.setAttribute('aria-selected', String(isLogin));
  el.tabRegister.setAttribute('aria-selected', String(!isLogin));
  el.formLogin.classList.toggle('hidden', !isLogin);
  el.formRegister.classList.toggle('hidden', isLogin);
}

async function handleLoginSubmit(event) {
  event.preventDefault();
  const username = el.loginUsername.value.trim();
  const password = el.loginPassword.value;

  if (!username || !password) {
    showToast('Completa usuario y contraseña.', 'error');
    return;
  }
  if (containsPipe(username) || containsPipe(password)) {
    showToast('No se permite el carácter "|".', 'error');
    return;
  }

  try {
    const res = await apiFetch('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'No se pudo iniciar sesión.', 'error');
      return;
    }

    saveSessionUser(data);
    el.formLogin.reset();
    closeAuthModal();
    showToast(`Bienvenido/a, ${data.nombre}.`, 'success');

    if (state.pendingCompraEventId) {
      const pendingId = state.pendingCompraEventId;
      state.pendingCompraEventId = null;
      const ev = state.eventos.find((item) => item.id === pendingId);
      if (ev && ev.disponibles > 0) {
        openCompraModal(ev);
      }
    } else if (state.activeView === 'mis-boletos') {
      cargarMisBoletos();
    } else if (state.activeView === 'admin' && data.rol === 'admin') {
      cargarDatosAdmin();
    }
  } catch {
    showToast('Error de conexión con el servidor.', 'error');
  }
}

async function handleRegisterSubmit(event) {
  event.preventDefault();
  const username = el.regUsername.value.trim();
  const nombre = el.regNombre.value.trim();
  const password = el.regPassword.value;

  if (!username || !nombre || !password) {
    showToast('Todos los campos de registro son obligatorios.', 'error');
    return;
  }
  if (containsPipe(username) || containsPipe(nombre) || containsPipe(password)) {
    showToast('No se permite el carácter "|" en ningún campo.', 'error');
    return;
  }
  if (username.includes(' ')) {
    showToast('El nombre de usuario no puede tener espacios.', 'error');
    return;
  }
  if (password.length < 4) {
    showToast('La contraseña debe tener al menos 4 caracteres.', 'error');
    return;
  }

  try {
    const res = await apiFetch('/api/register', {
      method: 'POST',
      body: JSON.stringify({ username, nombre, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'No se pudo completar el registro.', 'error');
      return;
    }

    saveSessionUser(data);
    el.formRegister.reset();
    closeAuthModal();
    showToast(`Cuenta '${data.username}' creada correctamente.`, 'success');

    if (state.pendingCompraEventId) {
      const pendingId = state.pendingCompraEventId;
      state.pendingCompraEventId = null;
      const ev = state.eventos.find((item) => item.id === pendingId);
      if (ev && ev.disponibles > 0) {
        openCompraModal(ev);
      }
    } else if (state.activeView === 'mis-boletos') {
      cargarMisBoletos();
    }
  } catch {
    showToast('Error de conexión con el servidor.', 'error');
  }
}

async function handleLogout() {
  try {
    await apiFetch('/api/logout', { method: 'POST' });
  } catch {
    // Limpieza local aun si la red falla
  }
  saveSessionUser(null);
  state.misBoletos = [];
  if (state.activeView === 'mis-boletos') {
    renderMisBoletos();
  }
  showToast('Sesión cerrada.', 'info');
}

async function cargarEventos() {
  try {
    const res = await apiFetch('/api/eventos');
    if (!res.ok) {
      throw new Error('Error al cargar eventos');
    }
    state.eventos = await res.json();
    renderEventos();
  } catch {
    showToast('No se pudo cargar la cartelera de eventos.', 'error');
  }
}

function renderEventos() {
  el.eventosGrid.replaceChildren();
  const query = state.busquedaEventos.trim().toLowerCase();

  const filtrados = state.eventos.filter((ev) => {
    if (state.filtroDisponibilidad === 'disponibles' && ev.disponibles <= 0) {
      return false;
    }
    if (!query) return true;
    return (
      ev.nombre.toLowerCase().includes(query) ||
      ev.lugar.toLowerCase().includes(query) ||
      ev.id.toLowerCase().includes(query)
    );
  });

  if (filtrados.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.style.gridColumn = '1 / -1';

    const title = document.createElement('h2');
    title.textContent = 'Sin eventos coincidentes';

    const desc = document.createElement('p');
    desc.textContent = 'Prueba con otro término de búsqueda o cambia el filtro de disponibilidad.';

    empty.append(title, desc);
    el.eventosGrid.appendChild(empty);
    return;
  }

  for (const ev of filtrados) {
    const agotado = ev.disponibles <= 0;
    const selectedHorario =
      state.selectedHorarios[ev.id] && ev.horarios.includes(state.selectedHorarios[ev.id])
        ? state.selectedHorarios[ev.id]
        : ev.horarios[0] || '';
    state.selectedHorarios[ev.id] = selectedHorario;

    const card = document.createElement('article');
    card.className = 'event-card';

    const topRow = document.createElement('div');
    topRow.className = 'event-card-top';

    const metaLine = document.createElement('span');
    metaLine.className = 'event-meta-line tabular-nums';
    metaLine.textContent = `${ev.id} · ${ev.fecha}`;

    const badge = document.createElement('span');
    badge.className = `status-badge ${agotado ? 'status-soldout' : 'status-available'} tabular-nums`;
    badge.textContent = agotado ? 'AGOTADO' : `${ev.disponibles} disponibles`;

    topRow.append(metaLine, badge);

    const headerBody = document.createElement('div');
    const titleEl = document.createElement('h2');
    titleEl.className = 'event-title';
    titleEl.textContent = ev.nombre;

    const venueEl = document.createElement('p');
    venueEl.className = 'event-venue';
    venueEl.textContent = ev.lugar;
    headerBody.append(titleEl, venueEl);

    const horariosBlock = document.createElement('div');
    horariosBlock.className = 'horarios-block';

    const horariosLabel = document.createElement('span');
    horariosLabel.className = 'horarios-label';
    horariosLabel.textContent = 'Horarios disponibles';

    const horariosGroup = document.createElement('div');
    horariosGroup.className = 'horarios-group';

    for (const h of ev.horarios) {
      const pill = document.createElement('button');
      pill.type = 'button';
      pill.className = `schedule-pill ${h === selectedHorario ? 'selected' : ''}`;
      pill.textContent = `${h} hrs`;
      pill.disabled = agotado;
      pill.addEventListener('click', () => {
        state.selectedHorarios[ev.id] = h;
        horariosGroup.querySelectorAll('.schedule-pill').forEach((p) => p.classList.remove('selected'));
        pill.classList.add('selected');
      });
      horariosGroup.appendChild(pill);
    }

    horariosBlock.append(horariosLabel, horariosGroup);

    const footer = document.createElement('div');
    footer.className = 'event-card-footer';

    const priceGroup = document.createElement('div');
    priceGroup.className = 'event-price-group';

    const priceCaption = document.createElement('span');
    priceCaption.className = 'price-caption';
    priceCaption.textContent = 'Precio por acceso';

    const priceValue = document.createElement('strong');
    priceValue.className = 'event-price tabular-nums';
    priceValue.textContent = formatCurrency(ev.precio);

    priceGroup.append(priceCaption, priceValue);

    const buyBtn = document.createElement('button');
    buyBtn.type = 'button';
    buyBtn.className = 'btn btn-primary';
    buyBtn.disabled = agotado;
    buyBtn.textContent = agotado ? 'Agotado' : 'Comprar boletos';
    buyBtn.addEventListener('click', () => {
      if (!state.user) {
        state.pendingCompraEventId = ev.id;
        showToast('Inicia sesión o regístrate para comprar tus boletos.', 'info');
        openAuthModal('login');
        return;
      }
      openCompraModal(ev);
    });

    footer.append(priceGroup, buyBtn);
    card.append(topRow, headerBody, horariosBlock, footer);
    el.eventosGrid.appendChild(card);
  }
}

function openCompraModal(evento) {
  const horarioInicial =
    state.selectedHorarios[evento.id] && evento.horarios.includes(state.selectedHorarios[evento.id])
      ? state.selectedHorarios[evento.id]
      : evento.horarios[0] || '';

  state.compraActiva = {
    evento,
    horario: horarioInicial,
    cantidad: 1,
    ultimoBoleto: null,
  };

  el.compraStepForm.classList.remove('hidden');
  el.compraStepSuccess.classList.add('hidden');

  el.compraEventoId.textContent = `${evento.id} · ${evento.fecha}`;
  el.compraEventoNombre.textContent = evento.nombre;
  el.compraEventoMeta.textContent = `${evento.lugar} — ${formatCurrency(evento.precio)} por boleto`;
  el.compraDisponibles.textContent = String(evento.disponibles);

  el.compraCantidad.max = String(evento.disponibles);
  el.compraCantidad.value = '1';

  el.compraHorariosList.replaceChildren();
  for (const h of evento.horarios) {
    const pill = document.createElement('button');
    pill.type = 'button';
    pill.className = `schedule-pill ${h === horarioInicial ? 'selected' : ''}`;
    pill.textContent = `${h} hrs`;
    pill.addEventListener('click', () => {
      state.compraActiva.horario = h;
      state.selectedHorarios[evento.id] = h;
      el.compraHorariosList.querySelectorAll('.schedule-pill').forEach((p) => p.classList.remove('selected'));
      pill.classList.add('selected');
    });
    el.compraHorariosList.appendChild(pill);
  }

  updateCompraTotals();
  el.compraModal.classList.remove('hidden');
}

function closeCompraModal() {
  el.compraModal.classList.add('hidden');
}

function updateCompraTotals() {
  const { evento } = state.compraActiva;
  if (!evento) return;

  let qty = parseInt(el.compraCantidad.value, 10);
  if (Number.isNaN(qty) || qty < 1) qty = 1;
  if (qty > evento.disponibles) qty = evento.disponibles;

  state.compraActiva.cantidad = qty;
  el.compraCantidad.value = String(qty);

  const total = qty * evento.precio;
  el.compraDesglose.textContent = `${qty} × ${formatCurrency(evento.precio)}`;
  el.compraTotal.textContent = formatCurrency(total);
}

async function handleConfirmCompra() {
  const { evento, horario, cantidad } = state.compraActiva;
  if (!evento || !horario) {
    showToast('Selecciona un horario válido.', 'error');
    return;
  }

  el.btnConfirmCompra.disabled = true;
  el.btnConfirmCompra.textContent = 'Procesando...';

  try {
    const res = await apiFetch('/api/comprar', {
      method: 'POST',
      body: JSON.stringify({
        evento_id: evento.id,
        horario,
        cantidad,
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      if (res.status === 401) {
        closeCompraModal();
        saveSessionUser(null);
        openAuthModal('login');
      }
      showToast(data.error || 'No se pudo completar la compra.', 'error');
      return;
    }

    const boleto = data.boleto;
    state.compraActiva.ultimoBoleto = boleto;

    await cargarEventos();

    el.compraStepForm.classList.add('hidden');
    el.compraStepSuccess.classList.remove('hidden');
    el.successFolio.textContent = `Folio: ${boleto.folio}`;

    el.successReceiptDetails.replaceChildren();
    const pairs = [
      ['Evento', boleto.evento_nombre],
      ['Recinto', boleto.lugar],
      ['Fecha y horario', `${boleto.fecha} · ${boleto.horario} hrs`],
      ['Titular', `${boleto.nombre_cliente} (@${boleto.username})`],
      ['Accesos', `${boleto.cantidad} boleto(s)`],
      ['Total pagado', formatCurrency(boleto.total)],
    ];

    for (const [label, val] of pairs) {
      const item = document.createElement('div');
      item.className = 'receipt-item';
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = val;
      item.append(dt, dd);
      el.successReceiptDetails.appendChild(item);
    }

    showToast(`Compra confirmada. Folio ${boleto.folio}.`, 'success');
  } catch {
    showToast('Error de conexión al procesar la compra.', 'error');
  } finally {
    el.btnConfirmCompra.disabled = false;
    el.btnConfirmCompra.textContent = 'Confirmar compra';
  }
}

async function descargarBoletoPDF(folio) {
  try {
    const res = await apiFetch(`/api/boletos/${encodeURIComponent(folio)}/pdf?download=1`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToast(err.error || 'No se pudo descargar el PDF del boleto.', 'error');
      return;
    }

    const blob = await res.blob();
    const blobUrl = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = `boleto_${folio}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
    showToast(`Descargando boleto_${folio}.pdf`, 'success');
  } catch {
    showToast('Error al descargar el archivo PDF.', 'error');
  }
}

async function cargarMisBoletos() {
  if (!state.user) {
    renderMisBoletos();
    return;
  }

  try {
    const res = await apiFetch(`/api/mis-boletos/${encodeURIComponent(state.user.username)}`);
    if (!res.ok) {
      if (res.status === 401) {
        saveSessionUser(null);
        renderMisBoletos();
        return;
      }
      throw new Error('Error al consultar boletos');
    }
    state.misBoletos = await res.json();
    renderMisBoletos();
  } catch {
    showToast('No se pudieron cargar tus boletos.', 'error');
  }
}

function renderMisBoletos() {
  el.misBoletosContainer.replaceChildren();

  if (!state.user) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';

    const title = document.createElement('h2');
    title.textContent = 'Inicia sesión para ver tus boletos';

    const desc = document.createElement('p');
    desc.textContent = 'Tus boletos adquiridos y sus comprobantes en PDF están vinculados a tu cuenta.';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-primary';
    btn.textContent = 'Iniciar sesión';
    btn.addEventListener('click', () => openAuthModal('login'));

    empty.append(title, desc, btn);
    el.misBoletosContainer.appendChild(empty);
    return;
  }

  if (state.misBoletos.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';

    const title = document.createElement('h2');
    title.textContent = 'Aún no tienes boletos registrados';

    const desc = document.createElement('p');
    desc.textContent = 'Explora la cartelera de eventos para adquirir tus primeros accesos.';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-primary';
    btn.textContent = 'Explorar cartelera';
    btn.addEventListener('click', () => switchView('cartelera'));

    empty.append(title, desc, btn);
    el.misBoletosContainer.appendChild(empty);
    return;
  }

  const grid = document.createElement('div');
  grid.className = 'boletos-grid';

  for (const b of state.misBoletos) {
    const stub = document.createElement('article');
    stub.className = 'ticket-stub';

    const header = document.createElement('div');
    header.className = 'ticket-stub-header';

    const folio = document.createElement('span');
    folio.className = 'ticket-folio';
    folio.textContent = `FOLIO ${b.folio}`;

    const evId = document.createElement('span');
    evId.className = 'ticket-event-id';
    evId.textContent = b.evento_id;

    header.append(folio, evId);

    const body = document.createElement('div');
    body.className = 'ticket-stub-body';

    const title = document.createElement('h2');
    title.className = 'ticket-title';
    title.textContent = b.evento_nombre;

    const details = document.createElement('div');
    details.className = 'ticket-details-grid';

    const fields = [
      ['Recinto', b.lugar],
      ['Fecha y horario', `${b.fecha} · ${b.horario} hrs`],
      ['Titular', b.nombre_cliente],
      ['Cantidad', `${b.cantidad} acceso(s)`],
    ];

    for (const [label, val] of fields) {
      const item = document.createElement('div');
      item.className = 'ticket-detail-item';
      const lbl = document.createElement('span');
      lbl.className = 'ticket-detail-label';
      lbl.textContent = label;
      const v = document.createElement('span');
      v.className = 'ticket-detail-value';
      v.textContent = val;
      item.append(lbl, v);
      details.appendChild(item);
    }

    body.append(title, details);

    const perforation = document.createElement('div');
    perforation.className = 'ticket-perforation';

    const totalWrap = document.createElement('div');
    totalWrap.className = 'event-price-group';
    const totalCaption = document.createElement('span');
    totalCaption.className = 'price-caption';
    totalCaption.textContent = `Emitido ${b.fecha_compra}`;
    const totalVal = document.createElement('strong');
    totalVal.className = 'event-price tabular-nums';
    totalVal.textContent = formatCurrency(b.total);
    totalWrap.append(totalCaption, totalVal);

    const pdfBtn = document.createElement('button');
    pdfBtn.type = 'button';
    pdfBtn.className = 'btn btn-primary';
    pdfBtn.textContent = 'Descargar PDF';
    pdfBtn.addEventListener('click', () => descargarBoletoPDF(b.folio));

    perforation.append(totalWrap, pdfBtn);
    stub.append(header, body, perforation);
    grid.appendChild(stub);
  }

  el.misBoletosContainer.appendChild(grid);
}

async function cargarDatosAdmin() {
  if (state.user?.rol !== 'admin') return;

  try {
    const [resEventos, resVentas] = await Promise.all([
      apiFetch('/api/eventos'),
      apiFetch('/api/admin/ventas'),
    ]);

    if (resVentas.status === 401 || resVentas.status === 403) {
      showToast('Sesión de administrador requerida.', 'error');
      saveSessionUser(null);
      switchView('cartelera');
      return;
    }

    if (resEventos.ok) {
      state.eventos = await resEventos.json();
    }
    if (resVentas.ok) {
      state.ventasAdmin = await resVentas.json();
    }
    renderAdminPanel();
  } catch {
    showToast('No se pudo cargar el reporte administrativo.', 'error');
  }
}

function renderAdminPanel() {
  el.kpiEventos.textContent = String(state.eventos.length);
  el.kpiBoletos.textContent = String(state.ventasAdmin.total_boletos || 0);
  el.kpiRecaudado.textContent = formatCurrency(state.ventasAdmin.total_recaudado || 0);

  el.adminVentasTbody.replaceChildren();
  const query = state.busquedaVentas.trim().toLowerCase();
  const boletos = (state.ventasAdmin.boletos || []).filter((b) => {
    if (!query) return true;
    return (
      b.folio.toLowerCase().includes(query) ||
      b.evento_nombre.toLowerCase().includes(query) ||
      b.username.toLowerCase().includes(query) ||
      b.nombre_cliente.toLowerCase().includes(query)
    );
  });

  if (boletos.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.style.textAlign = 'center';
    td.style.padding = '28px 12px';
    td.style.color = '#6F5643';
    td.textContent = 'No hay ventas registradas que coincidan con el filtro.';
    tr.appendChild(td);
    el.adminVentasTbody.appendChild(tr);
    return;
  }

  for (const b of boletos) {
    const tr = document.createElement('tr');

    const tdFolio = document.createElement('td');
    tdFolio.className = 'mono-cell';
    tdFolio.textContent = b.folio;

    const tdEvento = document.createElement('td');
    tdEvento.textContent = b.evento_nombre;

    const tdHorario = document.createElement('td');
    tdHorario.className = 'mono-cell';
    tdHorario.textContent = `${b.fecha} ${b.horario}`;

    const tdCliente = document.createElement('td');
    tdCliente.textContent = b.username;

    const tdCant = document.createElement('td');
    tdCant.className = 'num-col';
    tdCant.textContent = String(b.cantidad);

    const tdTotal = document.createElement('td');
    tdTotal.className = 'num-col';
    tdTotal.textContent = formatCurrency(b.total);

    const tdAction = document.createElement('td');
    tdAction.className = 'action-col';
    const btnPdf = document.createElement('button');
    btnPdf.type = 'button';
    btnPdf.className = 'btn btn-secondary btn-compact';
    btnPdf.textContent = 'PDF';
    btnPdf.addEventListener('click', () => descargarBoletoPDF(b.folio));
    tdAction.appendChild(btnPdf);

    tr.append(tdFolio, tdEvento, tdHorario, tdCliente, tdCant, tdTotal, tdAction);
    el.adminVentasTbody.appendChild(tr);
  }
}

async function handleAdminCreateEvent(event) {
  event.preventDefault();
  const form = el.formAdminEvento;
  const nombre = form.nombre.value.trim();
  const lugar = form.lugar.value.trim();
  const fecha = form.fecha.value.trim();
  const horarios = form.horarios.value.trim();
  const precio = form.precio.value;
  const disponibles = form.disponibles.value;

  if (!nombre || !lugar || !fecha || !horarios || !precio || !disponibles) {
    showToast('Completa todos los campos para registrar el evento.', 'error');
    return;
  }
  if ([nombre, lugar, fecha, horarios].some(containsPipe)) {
    showToast('Ningún campo puede contener el carácter "|".', 'error');
    return;
  }

  try {
    const res = await apiFetch('/api/admin/eventos', {
      method: 'POST',
      body: JSON.stringify({
        nombre,
        lugar,
        fecha,
        horarios,
        precio: Number(precio),
        disponibles: Number(disponibles),
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      showToast(data.error || 'No se pudo registrar el evento.', 'error');
      return;
    }

    form.reset();
    showToast(data.mensaje || 'Evento registrado.', 'success');
    await cargarDatosAdmin();
  } catch {
    showToast('Error de conexión al guardar el evento.', 'error');
  }
}

async function restoreSession() {
  const raw = sessionStorage.getItem(SESSION_STORAGE_KEY);
  if (raw) {
    try {
      const cached = JSON.parse(raw);
      if (cached && cached.username) {
        state.user = cached;
        updateAuthUI();
      }
    } catch {
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }
  }

  try {
    const res = await apiFetch('/api/me');
    if (res.ok) {
      const serverUser = await res.json();
      saveSessionUser(serverUser);
    } else if (res.status === 401) {
      saveSessionUser(null);
    }
  } catch {
    // Mantiene estado local si la verificación falla temporalmente
  }
}

function bindEvents() {
  document.querySelectorAll('.no-pipe').forEach(attachPipeGuard);

  el.brandLink.addEventListener('click', (e) => {
    e.preventDefault();
    switchView('cartelera');
  });

  el.navLinks.forEach((btn) => {
    btn.addEventListener('click', () => {
      switchView(btn.dataset.view);
    });
  });

  el.btnOpenAuth.addEventListener('click', () => openAuthModal('login'));
  el.btnCloseAuth.addEventListener('click', closeAuthModal);
  el.btnLogout.addEventListener('click', handleLogout);

  el.tabLogin.addEventListener('click', () => setAuthTab('login'));
  el.tabRegister.addEventListener('click', () => setAuthTab('register'));
  el.formLogin.addEventListener('submit', handleLoginSubmit);
  el.formRegister.addEventListener('submit', handleRegisterSubmit);

  el.authModal.addEventListener('click', (e) => {
    if (e.target === el.authModal) closeAuthModal();
  });

  el.searchEventos.addEventListener('input', () => {
    state.busquedaEventos = el.searchEventos.value;
    renderEventos();
  });

  [el.filterTodos, el.filterDisponibles].forEach((btn) => {
    btn.addEventListener('click', () => {
      state.filtroDisponibilidad = btn.dataset.filter;
      el.filterTodos.classList.toggle('active', state.filtroDisponibilidad === 'todos');
      el.filterDisponibles.classList.toggle('active', state.filtroDisponibilidad === 'disponibles');
      renderEventos();
    });
  });

  el.btnCloseCompra.addEventListener('click', closeCompraModal);
  el.btnCancelCompra.addEventListener('click', closeCompraModal);
  el.compraModal.addEventListener('click', (e) => {
    if (e.target === el.compraModal) closeCompraModal();
  });

  el.btnQtyMinus.addEventListener('click', () => {
    const current = parseInt(el.compraCantidad.value, 10) || 1;
    el.compraCantidad.value = String(Math.max(1, current - 1));
    updateCompraTotals();
  });

  el.btnQtyPlus.addEventListener('click', () => {
    const current = parseInt(el.compraCantidad.value, 10) || 1;
    const max = state.compraActiva.evento?.disponibles || 1;
    el.compraCantidad.value = String(Math.min(max, current + 1));
    updateCompraTotals();
  });

  el.compraCantidad.addEventListener('input', updateCompraTotals);
  el.btnConfirmCompra.addEventListener('click', handleConfirmCompra);

  el.btnDownloadNewPdf.addEventListener('click', () => {
    const folio = state.compraActiva.ultimoBoleto?.folio;
    if (folio) descargarBoletoPDF(folio);
  });

  el.btnGoMisBoletos.addEventListener('click', () => {
    closeCompraModal();
    switchView('mis-boletos');
  });

  el.btnRefreshBoletos.addEventListener('click', cargarMisBoletos);
  el.btnRefreshAdmin.addEventListener('click', cargarDatosAdmin);
  el.formAdminEvento.addEventListener('submit', handleAdminCreateEvent);

  el.searchVentas.addEventListener('input', () => {
    state.busquedaVentas = el.searchVentas.value;
    renderAdminPanel();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeAuthModal();
      closeCompraModal();
    }
  });
}

async function init() {
  bindEvents();
  await restoreSession();
  await cargarEventos();
}

init();
