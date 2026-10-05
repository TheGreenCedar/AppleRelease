/** Verify the complete existing App installation before any Apple credential use. */
import { sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';

class VerificationError extends Error {
  constructor(category) { super(category); this.category = category; }
}
function require(condition, category) {
  if (!condition) throw new VerificationError(category);
}
function exactPermissions(permissions) {
  return permissions && Object.keys(permissions).sort().join(',') === 'actions,metadata'
    && permissions.actions === 'read' && permissions.metadata === 'read';
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
  require(exactPermissions(app.permissions) && Array.isArray(app.events) && app.events.length === 0, 'app-excess-permissions-or-events');
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
      && repository.private === true, 'installation-repository-mismatch');
    return { app_id: app.id, slug: app.slug, installation_id: installation.id,
      permissions: { actions: 'read', metadata: 'read' }, repository_selection: 'selected',
      repositories: ['TheGreenCedar/Speakerdesk'], private_repository: true };
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
    process.exitCode = 1;
  }
}
