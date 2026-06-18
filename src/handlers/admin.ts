import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { normalizeDomain, normalizeLocalPart } from '../email.js'
import type { IdentityInput, IdentityRepository, IdentityVisibility } from '../types.js'

const cookieName = 'nmail_admin_session'
const sessionMaxAgeSeconds = 60 * 60 * 12
const duplicateConstraint = 'identities_unique_name'

interface IdentityParams {
  id: string
}

interface IdentityQuery {
  search?: string
}

interface LoginBody {
  password?: string
}

export function registerAdminRoutes(app: FastifyInstance, repo: IdentityRepository, adminPassword: string): void {
  const auth = (request: FastifyRequest, reply: FastifyReply, done: (error?: Error) => void) => {
    if (!isAuthenticated(request, adminPassword)) {
      reply.code(401).send({ error: 'unauthorized' })
      return
    }

    done()
  }

  app.get('/admin', async (_request, reply) => {
    reply.type('text/html; charset=utf-8').send(adminPage)
  })

  app.post('/admin/login', async (request: FastifyRequest<{ Body: LoginBody }>, reply) => {
    const password = request.body?.password ?? ''
    if (!constantTimeEqual(password, adminPassword)) {
      return reply.code(401).send({ error: 'invalid_password' })
    }

    reply.header('set-cookie', sessionCookie(createSession(adminPassword)))
    return reply.send({ ok: true })
  })

  app.post('/admin/logout', async (_request, reply) => {
    reply.header('set-cookie', clearSessionCookie())
    return reply.send({ ok: true })
  })

  app.get('/admin/api/identities', { preHandler: auth }, async (request: FastifyRequest<{ Querystring: IdentityQuery }>, reply) => {
    if (!repo.listIdentities) return reply.code(501).send({ error: 'admin_repository_unavailable' })

    const identities = await repo.listIdentities(request.query.search)
    return reply.send({ identities })
  })

  app.post('/admin/api/identities', { preHandler: auth }, async (request, reply) => {
    if (!repo.createIdentity) return reply.code(501).send({ error: 'admin_repository_unavailable' })

    const parsed = parseIdentityInput(request.body)
    if (!parsed.ok) return reply.code(400).send({ error: 'invalid_identity', message: parsed.message })

    try {
      const identity = await repo.createIdentity(parsed.identity)
      return reply.code(201).send({ identity })
    } catch (error) {
      return handleAdminError(error, reply)
    }
  })

  app.put('/admin/api/identities/:id', { preHandler: auth }, async (request: FastifyRequest<{ Params: IdentityParams }>, reply) => {
    if (!repo.updateIdentity) return reply.code(501).send({ error: 'admin_repository_unavailable' })

    const parsed = parseIdentityInput(request.body)
    if (!parsed.ok) return reply.code(400).send({ error: 'invalid_identity', message: parsed.message })

    try {
      const identity = await repo.updateIdentity(request.params.id, parsed.identity)
      if (!identity) return reply.code(404).send({ error: 'identity_not_found' })
      return reply.send({ identity })
    } catch (error) {
      return handleAdminError(error, reply)
    }
  })

  app.post(
    '/admin/api/identities/:id/deactivate',
    { preHandler: auth },
    async (request: FastifyRequest<{ Params: IdentityParams }>, reply) => setIdentityActive(repo, request.params.id, false, reply),
  )

  app.post(
    '/admin/api/identities/:id/activate',
    { preHandler: auth },
    async (request: FastifyRequest<{ Params: IdentityParams }>, reply) => setIdentityActive(repo, request.params.id, true, reply),
  )

  app.delete('/admin/api/identities/:id', { preHandler: auth }, async (request: FastifyRequest<{ Params: IdentityParams }>, reply) => {
    if (!repo.deleteIdentity) return reply.code(501).send({ error: 'admin_repository_unavailable' })

    const deleted = await repo.deleteIdentity(request.params.id)
    if (!deleted) return reply.code(404).send({ error: 'identity_not_found' })

    return reply.code(204).send()
  })
}

async function setIdentityActive(repo: IdentityRepository, id: string, active: boolean, reply: FastifyReply) {
  if (!repo.setIdentityActive) return reply.code(501).send({ error: 'admin_repository_unavailable' })

  const identity = await repo.setIdentityActive(id, active)
  if (!identity) return reply.code(404).send({ error: 'identity_not_found' })

  return reply.send({ identity })
}

type ParsedIdentityInput = { ok: true; identity: IdentityInput } | { ok: false; message: string }

function parseIdentityInput(value: unknown): ParsedIdentityInput {
  if (!value || typeof value !== 'object') return invalid('Identity payload is required')

  const input = value as Record<string, unknown>
  const domain = normalizeDomain(String(input.domain ?? ''))
  const localPart = normalizeLocalPart(String(input.localPart ?? ''))
  const pubkey = String(input.pubkey ?? '').trim().toLowerCase()
  const visibility = input.visibility
  const mailEnabled = input.mailEnabled
  const active = input.active
  const relays = parseRelays(input.relays)

  if (!domain) return invalid('Domain is required')
  if (!localPart) return invalid('Local part is required')
  if (!/^[0-9a-f]{64}$/.test(pubkey)) return invalid('Pubkey must be 64 lowercase hexadecimal characters')
  if (visibility !== 'public' && visibility !== 'private') return invalid('Visibility must be public or private')
  if (typeof mailEnabled !== 'boolean') return invalid('Mail enabled must be a boolean')
  if (typeof active !== 'boolean') return invalid('Active must be a boolean')
  if (!relays.ok) return invalid(relays.message)

  return {
    ok: true,
    identity: {
      domain,
      localPart,
      pubkey,
      relays: relays.relays,
      visibility: visibility satisfies IdentityVisibility,
      mailEnabled,
      active,
    },
  }
}

function parseRelays(value: unknown): { ok: true; relays: string[] } | { ok: false; message: string } {
  const relays = Array.isArray(value)
    ? value
    : typeof value === 'string'
      ? value
          .split(/\r?\n|,/)
          .map((relay) => relay.trim())
          .filter(Boolean)
      : null

  if (!relays) return { ok: false, message: 'Relays must be an array or text list' }

  const cleanRelays = []
  for (const relay of relays) {
    if (typeof relay !== 'string') return { ok: false, message: 'Relays must contain only strings' }

    const cleanRelay = relay.trim()
    if (!cleanRelay) continue

    try {
      const url = new URL(cleanRelay)
      if (url.protocol !== 'wss:' && url.protocol !== 'ws:') {
        return { ok: false, message: 'Relays must use ws:// or wss://' }
      }
    } catch {
      return { ok: false, message: 'Relays must be valid URLs' }
    }

    cleanRelays.push(cleanRelay)
  }

  return { ok: true, relays: cleanRelays }
}

function invalid(message: string): ParsedIdentityInput {
  return { ok: false, message }
}

function handleAdminError(error: unknown, reply: FastifyReply) {
  if (isPgDuplicateIdentityError(error)) {
    return reply.code(409).send({ error: 'identity_already_exists', message: 'An identity already exists for this domain and local part' })
  }

  throw error
}

function isPgDuplicateIdentityError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false

  const pgError = error as { code?: unknown; constraint?: unknown }
  return pgError.code === '23505' && pgError.constraint === duplicateConstraint
}

function createSession(adminPassword: string): string {
  const expiresAt = Math.floor(Date.now() / 1000) + sessionMaxAgeSeconds
  const nonce = randomBytes(16).toString('base64url')
  const payload = `${expiresAt}.${nonce}`
  return `${payload}.${sign(payload, adminPassword)}`
}

function isAuthenticated(request: FastifyRequest, adminPassword: string): boolean {
  const token = readCookie(request.headers.cookie, cookieName)
  if (!token) return false

  const parts = token.split('.')
  if (parts.length !== 3) return false

  const [expiresAtRaw, nonce, signature] = parts
  if (!expiresAtRaw || !nonce || !signature) return false

  const expiresAt = Number(expiresAtRaw)
  if (!Number.isInteger(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000)) return false

  const payload = `${expiresAtRaw}.${nonce}`
  return constantTimeEqual(signature, sign(payload, adminPassword))
}

function sign(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url')
}

function constantTimeEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual)
  const expectedBuffer = Buffer.from(expected)
  return actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer)
}

function readCookie(cookieHeader: string | undefined, name: string): string {
  if (!cookieHeader) return ''

  for (const cookie of cookieHeader.split(';')) {
    const [rawName, ...rawValue] = cookie.trim().split('=')
    if (rawName === name) return rawValue.join('=')
  }

  return ''
}

function sessionCookie(token: string): string {
  return `${cookieName}=${token}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=${sessionMaxAgeSeconds}`
}

function clearSessionCookie(): string {
  return `${cookieName}=; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=0`
}

const adminPage = String.raw`<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>nmail admin</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --surface: #ffffff;
      --surface-strong: #eef1f5;
      --text: #17202a;
      --muted: #667085;
      --border: #d8dee8;
      --accent: #146c94;
      --accent-strong: #0d506f;
      --danger: #b42318;
      --ok: #067647;
      --shadow: 0 12px 32px rgba(19, 32, 45, 0.08);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    button, input, select, textarea {
      font: inherit;
    }

    button {
      min-height: 36px;
      border: 1px solid transparent;
      border-radius: 6px;
      padding: 0 12px;
      background: var(--accent);
      color: #fff;
      cursor: pointer;
    }

    button:hover { background: var(--accent-strong); }
    button.secondary { background: var(--surface); color: var(--text); border-color: var(--border); }
    button.secondary:hover { background: var(--surface-strong); }
    button.danger { background: var(--danger); }
    button.ghost { background: transparent; color: var(--accent); padding-inline: 4px; }
    button:disabled { opacity: 0.55; cursor: not-allowed; }

    input, select, textarea {
      width: 100%;
      min-height: 38px;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 10px;
      background: #fff;
      color: var(--text);
    }

    textarea {
      min-height: 88px;
      resize: vertical;
    }

    label {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 600;
    }

    .shell {
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
    }

    .brand-mark {
      width: 28px;
      height: 28px;
      border-radius: 6px;
      display: grid;
      place-items: center;
      background: var(--accent);
      color: #fff;
      font-size: 14px;
    }

    main {
      width: min(1280px, 100%);
      margin: 0 auto;
      padding: 20px;
    }

    .login {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 20px;
    }

    .login-panel {
      width: min(420px, 100%);
      padding: 24px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--shadow);
    }

    .login-panel h1 {
      margin: 0 0 18px;
      font-size: 24px;
    }

    .toolbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 16px;
    }

    .search {
      width: min(420px, 100%);
    }

    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 380px;
      gap: 16px;
      align-items: start;
    }

    .panel {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .panel-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
    }

    .panel-head h2 {
      margin: 0;
      font-size: 16px;
    }

    .form {
      display: grid;
      gap: 12px;
      padding: 16px;
    }

    .form-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    .checks {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }

    .check {
      width: auto;
      display: inline-flex;
      grid-template-columns: none;
      align-items: center;
      gap: 8px;
      color: var(--text);
      font-weight: 500;
    }

    .check input {
      width: 16px;
      min-height: 16px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }

    th, td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }

    th {
      background: var(--surface-strong);
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    td.actions {
      width: 190px;
    }

    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      overflow-wrap: anywhere;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      border-radius: 999px;
      padding: 0 8px;
      background: var(--surface-strong);
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }

    .badge.ok { color: var(--ok); }
    .badge.off { color: var(--danger); }

    .row-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .message {
      min-height: 22px;
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 14px;
    }

    .message.error { color: var(--danger); }
    .message.ok { color: var(--ok); }

    .hidden { display: none; }

    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      .toolbar { align-items: stretch; flex-direction: column; }
      .search { width: 100%; }
      table, thead, tbody, tr, th, td { display: block; }
      thead { display: none; }
      tr { border-bottom: 1px solid var(--border); }
      td { border-bottom: 0; }
      td::before {
        content: attr(data-label);
        display: block;
        margin-bottom: 4px;
        color: var(--muted);
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
      }
    }
  </style>
</head>
<body>
  <div id="login" class="login hidden">
    <form id="login-form" class="login-panel">
      <h1>nmail admin</h1>
      <label>Password
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </label>
      <p id="login-message" class="message"></p>
      <button type="submit">Sign in</button>
    </form>
  </div>

  <div id="app" class="shell hidden">
    <header class="topbar">
      <div class="brand"><span class="brand-mark">nm</span><span>nmail admin</span></div>
      <button id="logout" class="secondary" type="button">Sign out</button>
    </header>

    <main>
      <div class="toolbar">
        <input id="search" class="search" type="search" placeholder="Search domain, user, pubkey">
        <button id="new-identity" type="button">New identity</button>
      </div>

      <div class="layout">
        <section class="panel">
          <div class="panel-head">
            <h2>Identities</h2>
            <span id="count" class="badge">0</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Address</th>
                <th>Pubkey</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </section>

        <aside class="panel">
          <div class="panel-head">
            <h2 id="form-title">New identity</h2>
            <button id="reset-form" class="ghost" type="button">Reset</button>
          </div>
          <form id="identity-form" class="form">
            <input id="identity-id" type="hidden">
            <div class="form-grid">
              <label>Domain
                <input id="domain" required placeholder="nmail.li">
              </label>
              <label>User
                <input id="localPart" required placeholder="alice">
              </label>
            </div>
            <label>Pubkey
              <input id="pubkey" class="mono" required maxlength="64" minlength="64">
            </label>
            <label>Relays
              <textarea id="relays" class="mono" placeholder="wss://relay.nmail.li"></textarea>
            </label>
            <label>Visibility
              <select id="visibility">
                <option value="public">public</option>
                <option value="private">private</option>
              </select>
            </label>
            <div class="checks">
              <label class="check"><input id="mailEnabled" type="checkbox" checked> Mail enabled</label>
              <label class="check"><input id="active" type="checkbox" checked> Active</label>
            </div>
            <p id="form-message" class="message"></p>
            <button type="submit">Save</button>
          </form>
        </aside>
      </div>
    </main>
  </div>

  <script>
    const loginView = document.querySelector('#login');
    const appView = document.querySelector('#app');
    const loginForm = document.querySelector('#login-form');
    const loginMessage = document.querySelector('#login-message');
    const identityForm = document.querySelector('#identity-form');
    const rows = document.querySelector('#rows');
    const count = document.querySelector('#count');
    const search = document.querySelector('#search');
    const formMessage = document.querySelector('#form-message');
    const formTitle = document.querySelector('#form-title');
    let identities = [];
    let searchTimer;

    function showLogin() {
      appView.classList.add('hidden');
      loginView.classList.remove('hidden');
    }

    function showApp() {
      loginView.classList.add('hidden');
      appView.classList.remove('hidden');
    }

    async function request(path, options = {}) {
      const headers = { ...(options.headers || {}) };
      if (options.body !== undefined) headers['content-type'] = 'application/json';

      const response = await fetch(path, {
        headers,
        ...options,
      });

      if (response.status === 401) {
        showLogin();
        throw new Error('Unauthorized');
      }

      if (response.status === 204) return null;

      const data = await response.json();
      if (!response.ok) throw new Error(data.message || data.error || 'Erreur');
      return data;
    }

    async function loadIdentities() {
      const query = search.value.trim();
      const data = await request('/admin/api/identities' + (query ? '?search=' + encodeURIComponent(query) : ''));
      identities = data.identities;
      count.textContent = String(identities.length);
      rows.innerHTML = identities.map(renderRow).join('');
    }

    function renderRow(identity) {
      const address = escapeHtml(identity.localPart + '@' + identity.domain);
      const status = [
        identity.active ? '<span class="badge ok">active</span>' : '<span class="badge off">inactive</span>',
        identity.mailEnabled ? '<span class="badge ok">mail</span>' : '<span class="badge off">mail off</span>',
        '<span class="badge">' + escapeHtml(identity.visibility) + '</span>',
      ].join(' ');
      return '<tr>' +
        '<td data-label="Address"><strong>' + address + '</strong><br><span class="mono">#' + escapeHtml(identity.id) + '</span></td>' +
        '<td data-label="Pubkey" class="mono">' + escapeHtml(identity.pubkey) + '</td>' +
        '<td data-label="Status">' + status + '</td>' +
        '<td data-label="Actions" class="actions"><div class="row-actions">' +
          '<button class="secondary" type="button" data-action="edit" data-id="' + escapeHtml(identity.id) + '">Edit</button>' +
          '<button class="secondary" type="button" data-action="' + (identity.active ? 'deactivate' : 'activate') + '" data-id="' + escapeHtml(identity.id) + '">' + (identity.active ? 'Deactivate' : 'Activate') + '</button>' +
          '<button class="danger" type="button" data-action="delete" data-id="' + escapeHtml(identity.id) + '">Delete</button>' +
        '</div></td>' +
      '</tr>';
    }

    function readForm() {
      return {
        domain: document.querySelector('#domain').value,
        localPart: document.querySelector('#localPart').value,
        pubkey: document.querySelector('#pubkey').value,
        relays: document.querySelector('#relays').value.split(/\\r?\\n|,/).map((relay) => relay.trim()).filter(Boolean),
        visibility: document.querySelector('#visibility').value,
        mailEnabled: document.querySelector('#mailEnabled').checked,
        active: document.querySelector('#active').checked,
      };
    }

    function fillForm(identity) {
      document.querySelector('#identity-id').value = identity.id || '';
      document.querySelector('#domain').value = identity.domain || '';
      document.querySelector('#localPart').value = identity.localPart || '';
      document.querySelector('#pubkey').value = identity.pubkey || '';
      document.querySelector('#relays').value = (identity.relays || []).join('\\n');
      document.querySelector('#visibility').value = identity.visibility || 'public';
      document.querySelector('#mailEnabled').checked = identity.mailEnabled !== false;
      document.querySelector('#active').checked = identity.active !== false;
      formTitle.textContent = identity.id ? 'Edit identity' : 'New identity';
      formMessage.textContent = '';
      formMessage.className = 'message';
    }

    function resetForm() {
      fillForm({ visibility: 'public', mailEnabled: true, active: true, relays: [] });
    }

    function setMessage(element, message, type) {
      element.textContent = message;
      element.className = 'message ' + (type || '');
    }

    function escapeHtml(value) {
      return String(value).replace(/[&<>"']/g, (char) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[char]));
    }

    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      try {
        await request('/admin/login', {
          method: 'POST',
          body: JSON.stringify({ password: document.querySelector('#password').value }),
        });
        document.querySelector('#password').value = '';
        showApp();
        await loadIdentities();
      } catch (error) {
        setMessage(loginMessage, error.message, 'error');
      }
    });

    identityForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const id = document.querySelector('#identity-id').value;
      try {
        await request(id ? '/admin/api/identities/' + encodeURIComponent(id) : '/admin/api/identities', {
          method: id ? 'PUT' : 'POST',
          body: JSON.stringify(readForm()),
        });
        setMessage(formMessage, 'Saved', 'ok');
        resetForm();
        await loadIdentities();
      } catch (error) {
        setMessage(formMessage, error.message, 'error');
      }
    });

    rows.addEventListener('click', async (event) => {
      const button = event.target.closest('button[data-action]');
      if (!button) return;

      const identity = identities.find((item) => item.id === button.dataset.id);
      if (!identity) return;

      if (button.dataset.action === 'edit') {
        fillForm(identity);
        return;
      }

      try {
        if (button.dataset.action === 'delete') {
          if (!confirm('Permanently delete ' + identity.localPart + '@' + identity.domain + '?')) return;
          await request('/admin/api/identities/' + encodeURIComponent(identity.id), { method: 'DELETE' });
        } else {
          await request('/admin/api/identities/' + encodeURIComponent(identity.id) + '/' + button.dataset.action, { method: 'POST' });
        }
        await loadIdentities();
      } catch (error) {
        alert(error.message);
      }
    });

    document.querySelector('#reset-form').addEventListener('click', resetForm);
    document.querySelector('#new-identity').addEventListener('click', resetForm);
    document.querySelector('#logout').addEventListener('click', async () => {
      await fetch('/admin/logout', { method: 'POST' });
      showLogin();
    });
    search.addEventListener('input', () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => loadIdentities().catch(() => {}), 180);
    });

    resetForm();
    loadIdentities().then(showApp).catch(showLogin);
  </script>
</body>
</html>`
