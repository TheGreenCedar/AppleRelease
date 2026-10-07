/** Verify the complete existing App installation before any Apple credential use. */
import { sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';

class VerificationError extends Error {
  constructor(category, publicDetails) { super(category); this.category = category; this.publicDetails = publicDetails; }
}
function require(condition, category) {
  if (!condition) throw new VerificationError(category);
}
function exactPermissions(permissions) {
  return permissions && Object.keys(permissions).sort().join(',') === 'actions,metadata'
    && permissions.actions === 'read' && permissions.metadata === 'read';
}

function publicAppConfiguration(app) {
  // These fields are public GitHub enum names/levels, never headers or credentials.
  const permissions = {};
  let malformedNames = 0;
  const safeName = name => typeof name === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(name)
    && !/^gh[opsur]_/.test(name);
  for (const [name, value] of Object.entries(app.permissions ?? {})) {
    if (!safeName(name)) { malformedNames++; continue; }
    permissions[name] = ['read', 'write', 'admin', 'none'].includes(value) ? value : '[unrecognized-level]';
  }
  const events = Array.isArray(app.events)
    ? app.events.map(name => safeName(name) ? name : '[unrecognized-event]') : ['[invalid-event-list]'];
  return { requested_permissions: permissions, subscribed_events: events,
    missing_required_permissions: ['actions', 'metadata'].filter(name => !Object.hasOwn(permissions, name)),
    unexpected_permission_names: Object.keys(permissions).filter(name => !['actions', 'metadata'].includes(name)),
    incorrect_required_levels: ['actions', 'metadata'].filter(name => Object.hasOwn(permissions, name) && permissions[name] !== 'read'),
    malformed_permission_names: malformedNames };
}

export async function verifyInstallation({ appId, privateKey, fetchImpl = fetch }) {
  require(/^[1-9][0-9]*$/.test(appId ?? '') && Boolean(privateKey), 'missing-app-configuration');
  const now = Math.floor(Date.now() / 1000);
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const payload = `${encode({ alg: 'RS256', typ: 'JWT' })}.${encode({ iat: now - 60, exp: now + 540, iss: appId })}`;
  let jwt;
  try { jwt = `${payload}.${sign('RSA-SHA256', Buffer.from(payload), privateKey).toString('base64url')}`; }
  catch { throw new VerificationError('app-key-format'); }
  async function request(path, credential, { method = 'GET', body } = {}) {
    // Fixed GitHub endpoints only; credentials never follow a redirect.
    require(/^\/(?:app(?:\/installations(?:\?per_page=100|\/[0-9]+\/access_tokens)?)?|installation\/(?:repositories\?per_page=100|token))$/.test(path), 'unexpected-endpoint');
    let response;
    try {
      response = await fetchImpl(`https://api.github.com${path}`, {
        method, redirect: 'manual', signal: AbortSignal.timeout(60000),
        headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${credential}`,
          'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch { throw new VerificationError('github-transport'); }
    require(response.ok, `github-http-${response.status}`);
    require(!response.headers.get('link')?.includes('rel="next"'), 'unexpected-pagination');
    if (response.status === 204) return null;
    try { return await response.json(); }
    catch { throw new VerificationError('invalid-github-response'); }
  }
  const app = await request('/app', jwt);
  require(String(app.id) === appId && app.owner?.login === 'TheGreenCedar', 'app-identity-mismatch');
  if (!(exactPermissions(app.permissions) && Array.isArray(app.events) && app.events.length === 0))
    throw new VerificationError('app-excess-permissions-or-events', publicAppConfiguration(app));
  const installations = await request('/app/installations?per_page=100', jwt);
  require(Array.isArray(installations) && installations.length === 1, 'expected-one-installation');
  const installation = installations[0];
  require(installation.app_id === app.id && installation.account?.login === 'TheGreenCedar'
    && installation.target_type === 'User', 'installation-owner-mismatch');
  require(installation.repository_selection === 'selected' && exactPermissions(installation.permissions)
    && installation.suspended_at === null, 'installation-scope-or-permissions');
  require(Number.isSafeInteger(installation.id) && installation.id > 0, 'invalid-installation-id');
  let token;
  try {
    // Omit repository filtering so this lists the actual full selected installation.
    // The temporary token can read metadata/actions only and is always revoked below.
    const issued = await request(`/app/installations/${installation.id}/access_tokens`, jwt,
      { method: 'POST', body: { permissions: { actions: 'read', metadata: 'read' } } });
    token = issued.token;
    require(typeof token === 'string' && token.length > 0 && exactPermissions(issued.permissions), 'unexpected-verification-token');
    const repositories = await request('/installation/repositories?per_page=100', token);
    require(repositories.total_count === 1 && repositories.repositories?.length === 1, 'installation-must-cover-speakerdesk-only');
    const repository = repositories.repositories[0];
    require(repository.id === 1406057260 && repository.full_name === 'TheGreenCedar/Speakerdesk'
      && typeof repository.private === 'boolean', 'installation-repository-mismatch');
    return { app_id: app.id, slug: app.slug, installation_id: installation.id,
      permissions: { actions: 'read', metadata: 'read' }, repository_selection: 'selected',
      repositories: ['TheGreenCedar/Speakerdesk'], private_repository: repository.private };
  } finally {
    if (token) await request('/installation/token', token, { method: 'DELETE' });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await verifyInstallation({ appId: process.env.APP_ID, privateKey: process.env.APP_KEY });
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    const category = error instanceof VerificationError ? error.category : 'unexpected-error';
    console.error(`GitHub App verification stopped [${category}]. No key, JWT, token, or raw API response was printed.`);
    if (error instanceof VerificationError && error.publicDetails)
      console.error(`Public App configuration: ${JSON.stringify(error.publicDetails)}`);
    process.exitCode = 1;
  }
}
