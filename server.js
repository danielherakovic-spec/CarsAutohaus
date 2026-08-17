const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const dns = require('node:dns/promises');
const net = require('node:net');

const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'autovalue-pro.json');
const SESSION_TTL_MS = 14 * 24 * 60 * 60 * 1000;
const sessions = new Map();
const eventClients = new Set();
let writeQueue = Promise.resolve();

function emptyDatabase() {
  return {
    schemaVersion: 1,
    initialized: false,
    users: [],
    state: {
      version: 1,
      vehicles: [],
      tasks: [],
      updatedAt: new Date().toISOString(),
      lastModifiedBy: null,
    },
  };
}

async function readDatabase() {
  try {
    const content = await fs.readFile(DATA_FILE, 'utf8');
    const database = JSON.parse(content);
    return { ...emptyDatabase(), ...database, state: { ...emptyDatabase().state, ...database.state } };
  } catch (error) {
    if (error.code !== 'ENOENT') console.error('Datenspeicher konnte nicht gelesen werden:', error);
    const database = emptyDatabase();
    await writeDatabase(database);
    return database;
  }
}

function writeDatabase(database) {
  const snapshot = JSON.stringify(database, null, 2);
  writeQueue = writeQueue.catch(() => {}).then(async () => {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const temporaryFile = `${DATA_FILE}.tmp`;
    await fs.writeFile(temporaryFile, snapshot, 'utf8');
    await fs.rename(temporaryFile, DATA_FILE);
  });
  return writeQueue;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, savedHash] = String(storedHash).split(':');
  if (!salt || !savedHash) return false;
  const candidate = crypto.scryptSync(password, salt, 64);
  const saved = Buffer.from(savedHash, 'hex');
  return saved.length === candidate.length && crypto.timingSafeEqual(saved, candidate);
}

function json(response, status, body) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  response.end(JSON.stringify(body));
}

function safeUser(user) {
  return { id: user.id, name: user.name, role: user.role };
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
  return token;
}

async function getAuthenticatedUser(request, database) {
  const authorization = request.headers.authorization || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : new URL(request.url, 'http://localhost').searchParams.get('token');
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (token) sessions.delete(token);
    return null;
  }
  return database.users.find((user) => user.id === session.userId) || null;
}

function entityTime(entity) {
  return Date.parse(entity?.deletedAt || entity?.updatedAt || entity?.createdAt || 0) || 0;
}

function mergeEntities(current = [], incoming = []) {
  const byId = new Map();
  for (const item of current) if (item?.id) byId.set(item.id, item);
  for (const item of incoming) {
    if (!item?.id) continue;
    const existing = byId.get(item.id);
    if (!existing || entityTime(item) >= entityTime(existing)) byId.set(item.id, item);
  }
  return [...byId.values()];
}

function mergeState(current, incoming, userName) {
  return {
    version: Number(current.version || 0) + 1,
    vehicles: mergeEntities(current.vehicles, incoming?.vehicles),
    tasks: mergeEntities(current.tasks, incoming?.tasks),
    updatedAt: new Date().toISOString(),
    lastModifiedBy: userName,
  };
}

function broadcastState(state) {
  const message = `event: state\ndata: ${JSON.stringify({ state })}\n\n`;
  for (const client of eventClients) {
    try { client.write(message); } catch { eventClients.delete(client); }
  }
}

function parseBody(request) {
  return new Promise((resolve, reject) => {
    let data = '';
    request.on('data', (chunk) => {
      data += chunk;
      if (data.length > 5 * 1024 * 1024) request.destroy();
    });
    request.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch { reject(new Error('Ungültige JSON-Daten.')); }
    });
    request.on('error', reject);
  });
}

function contentType(file) {
  return {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.webmanifest': 'application/manifest+json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.css': 'text/css; charset=utf-8',
  }[path.extname(file)] || 'application/octet-stream';
}

function decodeHtml(value = '') {
  return String(value)
    .replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&nbsp;/gi, ' ')
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)))
    .replace(/\s+/g, ' ').trim();
}

function textOnly(value = '') {
  return decodeHtml(String(value).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' '));
}

function isPrivateAddress(address) {
  if (net.isIP(address) === 4) {
    const [first, second] = address.split('.').map(Number);
    return first === 0 || first === 10 || first === 127 || first >= 224 ||
      (first === 169 && second === 254) || (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168);
  }
  const normalized = String(address).toLowerCase();
  return normalized === '::1' || normalized === '::' || normalized.startsWith('fe80:') || normalized.startsWith('fc') || normalized.startsWith('fd');
}

async function validatePublicUrl(rawUrl) {
  let url;
  try { url = new URL(String(rawUrl || '').trim()); } catch { throw new Error('Bitte eine vollständige Inserat-URL eingeben.'); }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || (url.port && !['80', '443'].includes(url.port))) throw new Error('Erlaubt sind nur öffentliche HTTP(S)-Inserat-Links.');
  if (['localhost', 'localhost.localdomain'].includes(url.hostname.toLowerCase()) || net.isIP(url.hostname) && isPrivateAddress(url.hostname)) throw new Error('Lokale oder private Netzwerkadressen können nicht importiert werden.');
  const addresses = await dns.lookup(url.hostname, { all: true });
  if (!addresses.length || addresses.some((entry) => isPrivateAddress(entry.address))) throw new Error('Diese Adresse ist nicht öffentlich erreichbar.');
  return url;
}

async function readPublicListing(url) {
  let currentUrl = url;
  for (let redirects = 0; redirects < 5; redirects += 1) {
    await validatePublicUrl(currentUrl);
    const response = await fetch(currentUrl, {
      redirect: 'manual',
      headers: { 'User-Agent': 'AutoValuePro/1.0 (+vehicle listing import)', Accept: 'text/html,application/xhtml+xml' },
      signal: AbortSignal.timeout(12000),
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) throw new Error('Die Inserat-Seite enthält eine ungültige Weiterleitung.');
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }
    if (!response.ok) throw new Error(`Die Inserat-Seite antwortet mit Fehler ${response.status}.`);
    if (!String(response.headers.get('content-type') || '').includes('html')) throw new Error('Der Link verweist nicht auf eine lesbare HTML-Inseratseite.');
    const declaredLength = Number(response.headers.get('content-length') || 0);
    if (declaredLength > 3 * 1024 * 1024) throw new Error('Die Inserat-Seite ist zu groß für den automatischen Import.');
    const reader = response.body?.getReader();
    if (!reader) throw new Error('Die Inserat-Seite konnte nicht gelesen werden.');
    const chunks = []; let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > 3 * 1024 * 1024) { reader.cancel(); throw new Error('Die Inserat-Seite ist zu groß für den automatischen Import.'); }
      chunks.push(value);
    }
    return { html: new TextDecoder().decode(Buffer.concat(chunks)), url: currentUrl };
  }
  throw new Error('Zu viele Weiterleitungen beim Öffnen des Inserats.');
}

function parseAttributes(tag) {
  const attributes = {};
  for (const match of tag.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)) attributes[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? '';
  return attributes;
}

function metadataFromHtml(html) {
  const metadata = {};
  for (const match of html.matchAll(/<meta\b[^>]*>/gi)) {
    const attributes = parseAttributes(match[0]);
    const key = String(attributes.property || attributes.name || '').toLowerCase();
    if (key && attributes.content && !metadata[key]) metadata[key] = decodeHtml(attributes.content);
  }
  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1];
  if (title) metadata.title = textOnly(title);
  return metadata;
}

function jsonLdObjects(html) {
  const objects = [];
  for (const match of html.matchAll(/<script\b[^>]*type\s*=\s*(?:"application\/ld\+json"|'application\/ld\+json'|application\/ld\+json)[^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      const parsed = JSON.parse(match[1].trim().replace(/^<!--|-->$/g, ''));
      const walk = (value) => {
        if (Array.isArray(value)) return value.forEach(walk);
        if (!value || typeof value !== 'object') return;
        objects.push(value);
        Object.values(value).forEach(walk);
      };
      walk(parsed);
    } catch { /* Invalid structured metadata is simply ignored. */ }
  }
  return objects;
}

function applicationObjects(html) {
  const objects = jsonLdObjects(html);
  for (const match of html.matchAll(/<script\b[^>]*(?:id\s*=\s*(?:"__NEXT_DATA__"|'__NEXT_DATA__'|__NEXT_DATA__)|type\s*=\s*(?:"application\/json"|'application\/json'|application\/json))[^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      const parsed = JSON.parse(match[1].trim());
      const walk = (value) => {
        if (Array.isArray(value)) return value.forEach(walk);
        if (!value || typeof value !== 'object') return;
        objects.push(value);
        Object.values(value).forEach(walk);
      };
      walk(parsed);
    } catch { /* The page may contain unrelated application data. */ }
  }
  return objects;
}

function firstValue(...values) {
  for (const value of values.flat(Infinity)) {
    if (value === undefined || value === null || value === '') continue;
    if (typeof value === 'object' && 'value' in value) return firstValue(value.value);
    if (typeof value === 'object' && 'name' in value) return firstValue(value.name);
    return value;
  }
  return '';
}

function numberFrom(value) {
  const normalized = String(value ?? '').replace(/[^0-9,.-]/g, '').replace(/\.(?=\d{3}(?:\D|$))/g, '').replace(',', '.');
  const result = Number(normalized);
  return Number.isFinite(result) ? result : 0;
}

function matchValue(html, expression) {
  const match = html.match(expression);
  return match ? decodeHtml(match[1]) : '';
}

function candidateScore(candidate) {
  const keys = Object.keys(candidate || {}).map((key) => key.toLowerCase());
  let score = 0;
  if (keys.some((key) => ['brand', 'make', 'manufacturer'].includes(key))) score += 3;
  if (keys.some((key) => ['model', 'modeldescription', 'vehiclemodel'].includes(key))) score += 3;
  if (keys.some((key) => ['mileage', 'mileagefromodometer', 'kilometerstand'].includes(key))) score += 2;
  if (keys.some((key) => ['price', 'offers', 'offer'].includes(key))) score += 2;
  if (keys.some((key) => ['firstregistration', 'productiondate', 'year'].includes(key))) score += 1;
  return score;
}

function imageFrom(value) {
  const candidate = Array.isArray(value) ? value[0] : value;
  return firstValue(candidate?.url, candidate?.src, candidate?.href, candidate);
}

function psFromPower(value, unit = '') {
  const numeric = numberFrom(firstValue(value));
  return /kw|kilowatt/i.test(String(unit || '')) ? Math.round(numeric * 1.35962) : numeric;
}

function extractVehicle(html, sourceUrl) {
  const metadata = metadataFromHtml(html);
  const candidates = applicationObjects(html);
  const vehicle = [...candidates].sort((left, right) => candidateScore(right) - candidateScore(left))[0] || {};
  const offers = Array.isArray(vehicle.offers) ? vehicle.offers[0] : (vehicle.offers || {});
  const name = firstValue(vehicle.name, vehicle.title, vehicle.headline, metadata['og:title'], metadata.title);
  const titleParts = String(name).replace(/\s*[|–-]\s*(mobile\.de|autoscout24|kleinanzeigen|gebrauchtwagen)[^|–-]*$/i, '').trim().split(/\s+/);
  const mileage = firstValue(vehicle.mileageFromOdometer, vehicle.mileage, vehicle.mileageInKm, vehicle.odometer, vehicle.kilometerstand, metadata['vehicle:mileage'], matchValue(html, /(?:Kilometerstand|Laufleistung|Mileage)[^0-9]{0,40}([0-9.\s]{2,12})\s*km/i));
  const power = firstValue(vehicle.vehicleEngine?.enginePower, vehicle.enginePower, vehicle.power, vehicle.powerInKw, vehicle.leistung, matchValue(html, /(?:Leistung|Power)[^0-9]{0,40}(\d{2,4})\s*PS/i), matchValue(html, /\b(\d{2,4})\s*PS\b/i));
  const powerUnit = firstValue(vehicle.vehicleEngine?.enginePower?.unitCode, vehicle.vehicleEngine?.enginePower?.unitText, vehicle.enginePower?.unitCode, vehicle.power?.unit, vehicle.powerUnit);
  const price = firstValue(offers.price, offers.amount, vehicle.price?.amount, vehicle.price?.gross, vehicle.price, vehicle.priceAmount, metadata['product:price:amount'], metadata['og:price:amount'], matchValue(html, /(?:Preis|Price)[^€]{0,45}([0-9.\s]{2,12})\s*(?:€|EUR)/i), matchValue(html, /([0-9.\s]{2,12})\s*(?:€|EUR)/i));
  const production = firstValue(vehicle.productionDate, vehicle.dateVehicleFirstRegistered, vehicle.firstRegistration, vehicle.firstRegistrationDate, vehicle.releaseDate, vehicle.year, matchValue(html, /(?:Erstzulassung|Baujahr|EZ)[^0-9]{0,30}((?:\d{1,2}[.\/-])?\d{4})/i));
  const year = Number(String(production).match(/(19|20)\d{2}/)?.[0] || 0);
  const image = firstValue(imageFrom(vehicle.image), imageFrom(vehicle.images), imageFrom(vehicle.media), metadata['og:image']);
  const brand = firstValue(vehicle.brand, vehicle.make, vehicle.manufacturer, vehicle.manufacturerName, metadata['vehicle:make']);
  const model = firstValue(vehicle.model, vehicle.vehicleModel, vehicle.modelDescription, vehicle.modelName, metadata['vehicle:model']);
  const equipmentText = firstValue(vehicle.description, metadata.description, metadata['og:description']);
  const warnings = [];
  const result = {
    brand: textOnly(brand || titleParts[0] || ''),
    model: textOnly(model || titleParts.slice(1, 3).join(' ') || ''),
    year,
    mileage: numberFrom(mileage),
    ps: psFromPower(power, powerUnit),
    askingPrice: numberFrom(price),
    fuel: textOnly(firstValue(vehicle.fuelType, vehicle.fuel, vehicle.vehicleEngine?.fuelType, metadata['vehicle:fuel'])) ,
    gearbox: textOnly(firstValue(vehicle.vehicleTransmission, vehicle.transmission, vehicle.gearbox, vehicle.transmissionType, metadata['vehicle:transmission'])),
    color: textOnly(firstValue(vehicle.color, vehicle.exteriorColor, metadata['vehicle:color'])),
    body: textOnly(firstValue(vehicle.bodyType, vehicle.body, vehicle.vehicleConfiguration, metadata['vehicle:body'])),
    photo: typeof image === 'string' && /^https?:\/\//i.test(image) ? image : '',
    notes: `Aus Inserat importiert${equipmentText ? `: ${textOnly(equipmentText).slice(0, 700)}` : ''}`,
    sourceUrl,
    importedAt: new Date().toISOString(),
  };
  if (!result.brand || !result.model) warnings.push('Marke oder Modell konnten nicht sicher erkannt werden. Bitte prüfen.');
  if (!result.askingPrice) warnings.push('Kein Preis gefunden. Bitte manuell ergänzen.');
  if (!result.mileage) warnings.push('Kein Kilometerstand gefunden. Bitte manuell ergänzen.');
  return { vehicle: result, warnings };
}

async function handleApi(request, response, database) {
  const url = new URL(request.url, 'http://localhost');
  const route = url.pathname;

  if (request.method === 'GET' && route === '/api/health') {
    return json(response, 200, { ok: true, version: database.state.version, timestamp: new Date().toISOString() });
  }

  if (request.method === 'GET' && route === '/api/bootstrap') {
    return json(response, 200, { initialized: database.initialized, users: database.users.map(safeUser) });
  }

  if (request.method === 'POST' && route === '/api/setup') {
    if (database.initialized) return json(response, 409, { error: 'Die zwei Benutzerkonten wurden bereits eingerichtet.' });
    const body = await parseBody(request);
    const users = Array.isArray(body.users) ? body.users : [];
    if (users.length !== 2) return json(response, 400, { error: 'Bitte genau zwei Benutzer anlegen.' });
    const names = users.map((user) => String(user.name || '').trim());
    const passwords = users.map((user) => String(user.password || ''));
    if (names.some((name) => name.length < 2) || new Set(names.map((name) => name.toLowerCase())).size !== 2) return json(response, 400, { error: 'Bitte zwei unterschiedliche Namen mit mindestens zwei Zeichen eingeben.' });
    if (passwords.some((password) => password.length < 8)) return json(response, 400, { error: 'Jedes Passwort muss mindestens 8 Zeichen lang sein.' });
    database.users = users.map((user, index) => ({
      id: crypto.randomUUID(),
      name: names[index],
      role: index === 0 ? 'Administrator' : 'Mitarbeiter',
      passwordHash: hashPassword(passwords[index]),
      createdAt: new Date().toISOString(),
    }));
    database.initialized = true;
    database.state.lastModifiedBy = names[0];
    await writeDatabase(database);
    return json(response, 201, { users: database.users.map(safeUser) });
  }

  if (request.method === 'POST' && route === '/api/login') {
    const body = await parseBody(request);
    const name = String(body.name || '').trim();
    const password = String(body.password || '');
    const user = database.users.find((entry) => entry.name.toLowerCase() === name.toLowerCase());
    if (!user || !verifyPassword(password, user.passwordHash)) return json(response, 401, { error: 'Name oder Passwort ist nicht korrekt.' });
    const token = createSession(user);
    return json(response, 200, { token, user: safeUser(user), state: database.state });
  }

  const user = await getAuthenticatedUser(request, database);
  if (!user) return json(response, 401, { error: 'Bitte erneut anmelden.' });

  if (request.method === 'GET' && route === '/api/session') return json(response, 200, { user: safeUser(user), state: database.state });

  if (request.method === 'GET' && route === '/api/events') {
    response.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    });
    response.write(`event: state\ndata: ${JSON.stringify({ state: database.state })}\n\n`);
    eventClients.add(response);
    request.on('close', () => eventClients.delete(response));
    return;
  }

  if (request.method === 'GET' && route === '/api/state') return json(response, 200, { state: database.state });

  if (request.method === 'POST' && route === '/api/import-listing') {
    try {
      const body = await parseBody(request);
      const listingUrl = await validatePublicUrl(body.url);
      const listing = await readPublicListing(listingUrl.toString());
      const imported = extractVehicle(listing.html, listing.url);
      return json(response, 200, imported);
    } catch (error) {
      return json(response, 400, { error: error.message || 'Das Inserat konnte nicht importiert werden.' });
    }
  }

  if (request.method === 'PUT' && route === '/api/state') {
    const body = await parseBody(request);
    if (!body.state || !Array.isArray(body.state.vehicles) || !Array.isArray(body.state.tasks)) return json(response, 400, { error: 'Ungültiger Datenstand.' });
    database.state = mergeState(database.state, body.state, user.name);
    await writeDatabase(database);
    broadcastState(database.state);
    return json(response, 200, { state: database.state });
  }

  if (request.method === 'POST' && route === '/api/logout') {
    const token = (request.headers.authorization || '').replace(/^Bearer\s+/i, '');
    sessions.delete(token);
    return json(response, 200, { ok: true });
  }

  return json(response, 404, { error: 'Schnittstelle nicht gefunden.' });
}

async function createAppServer() {
  const database = await readDatabase();
  return http.createServer(async (request, response) => {
    try {
      if (request.url.startsWith('/api/')) return await handleApi(request, response, database);

      const urlPath = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
      const requested = urlPath === '/' ? 'index.html' : urlPath.slice(1);
      const file = path.resolve(ROOT, requested);
      if (!file.startsWith(`${ROOT}${path.sep}`)) {
        response.writeHead(403); response.end('Forbidden'); return;
      }
      const content = await fs.readFile(file);
      response.writeHead(200, { 'Content-Type': contentType(file), 'Cache-Control': 'no-store' });
      response.end(content);
    } catch (error) {
      if (error.code === 'ENOENT') { response.writeHead(404); response.end('Nicht gefunden'); return; }
      console.error(error);
      json(response, 500, { error: 'Interner Serverfehler.' });
    }
  });
}

if (require.main === module) {
  createAppServer().then((server) => server.listen(PORT, HOST, () => {
    console.log(`AutoValue Pro läuft auf http://localhost:${PORT}`);
  }));
}

module.exports = { createAppServer, emptyDatabase, mergeState, extractVehicle, validatePublicUrl, readPublicListing };
