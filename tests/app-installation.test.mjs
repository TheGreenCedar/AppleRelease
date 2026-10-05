import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { verifyInstallation } from '../scripts/verify_app_installation.mjs';

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateKey = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
const permissions = { actions: 'read', metadata: 'read' };
function fixture(change = () => {}, badResponse) {
  const state = { app: { id: 5200652, slug: 'synthetic-app', owner: { login: 'TheGreenCedar' }, permissions, events: [] },
    installations: [{ id: 123, app_id: 5200652, account: { login: 'TheGreenCedar' }, target_type: 'User', repository_selection: 'selected', permissions, suspended_at: null }],
    repositories: { total_count: 1, repositories: [{ id: 1406057260, full_name: 'TheGreenCedar/Speakerdesk', private: true }] } };
  change(state);
  const calls = [];
  const fetchImpl = async (url, options) => {
    const path = url.replace('https://api.github.com', '');
    calls.push({ path, method: options.method });
    assert.equal(options.redirect, 'manual');
    const credential = options.headers.Authorization.slice(7);
    if (path.startsWith('/app')) {
      const [header, payload, signature] = credential.split('.');
      assert.ok(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), pair.publicKey, Buffer.from(signature, 'base64url')));
      const claims = JSON.parse(Buffer.from(payload, 'base64url'));
      assert.equal(claims.iss, '5200652');
      assert.ok(claims.exp - claims.iat <= 600);
    } else assert.equal(credential, 'synthetic-token-never-log');
    if (badResponse?.path === path) return badResponse.response;
    let result;
    if (path === '/app') result = state.app;
    else if (path === '/app/installations?per_page=100') result = state.installations;
    else if (path === '/app/installations/123/access_tokens') {
      assert.deepEqual(JSON.parse(options.body), { permissions });
      result = { token: 'synthetic-token-never-log', permissions };
    } else if (path === '/installation/repositories?per_page=100') result = state.repositories;
    else if (path === '/installation/token') assert.equal(options.method, 'DELETE');
    else assert.fail('unexpected endpoint');
    return { ok: true, status: path === '/installation/token' ? 204 : 200, headers: new Headers(), json: async () => result };
  };
  return { calls, options: { appId: '5200652', privateKey, fetchImpl } };
}

test('real synthetic JWT verifies exact full installation and revokes temporary token', async () => {
  const setup = fixture();
  const result = await verifyInstallation(setup.options);
  assert.deepEqual(result.repositories, ['TheGreenCedar/Speakerdesk']);
  assert.equal(setup.calls.at(-1).method, 'DELETE');
});
for (const [name, change, category] of [
  ['App write permission', s => s.app.permissions = { ...permissions, contents: 'write' }, 'app-excess-permissions-or-events'],
  ['App event subscription', s => s.app.events = ['push'], 'app-excess-permissions-or-events'],
  ['wrong App ID', s => s.app.id = 1, 'app-identity-mismatch'],
  ['zero installations', s => s.installations = [], 'expected-one-installation'],
  ['extra installation', s => s.installations.push(s.installations[0]), 'expected-one-installation'],
  ['all-repository installation', s => s.installations[0].repository_selection = 'all', 'installation-scope-or-permissions'],
  ['installation write permission', s => s.installations[0].permissions = { ...permissions, actions: 'write' }, 'installation-scope-or-permissions'],
  ['suspended installation', s => s.installations[0].suspended_at = '2026-01-01', 'installation-scope-or-permissions'],
  ['foreign owner', s => s.installations[0].account.login = 'foreign', 'installation-owner-mismatch'],
  ['extra selected repository', s => s.repositories.total_count = 2, 'installation-must-cover-speakerdesk-only'],
  ['wrong repository', s => s.repositories.repositories[0].id = 1, 'installation-repository-mismatch'],
]) test(`rejects ${name}`, async () => {
  const setup = fixture(change);
  await assert.rejects(verifyInstallation(setup.options), { message: category });
  if (setup.calls.some(call => call.path.endsWith('/access_tokens'))) assert.equal(setup.calls.at(-1).method, 'DELETE');
  else assert.ok(!setup.calls.some(call => call.path.includes('/installation/')));
});

test('rejects redirects without including response bodies', async () => {
  const setup = fixture(() => {}, { path: '/app', response: { ok: false, status: 302, text: async () => 'PRIVATE_SENTINEL' } });
  await assert.rejects(verifyInstallation(setup.options), { message: 'github-http-302' });
  assert.equal(setup.calls.length, 1);
});
test('revokes verification token after repository API failure', async () => {
  const setup = fixture(() => {}, { path: '/installation/repositories?per_page=100', response: { ok: false, status: 403 } });
  await assert.rejects(verifyInstallation(setup.options), { message: 'github-http-403' });
  assert.equal(setup.calls.at(-1).method, 'DELETE');
});
test('bad key errors contain no key material', async () => {
  await assert.rejects(verifyInstallation({ appId: '5200652', privateKey: 'PRIVATE_SENTINEL' }), { message: 'app-key-format' });
});

test('reports exact excess permission and default event without opening installation', async () => {
  const setup = fixture(s => { s.app.permissions = { ...permissions, contents: 'read' }; s.app.events = ['push']; });
  await assert.rejects(verifyInstallation(setup.options), error => {
    assert.equal(error.category, 'app-excess-permissions-or-events');
    assert.deepEqual(error.publicDetails.unexpected_permission_names, ['contents']);
    assert.deepEqual(error.publicDetails.requested_permissions, { ...permissions, contents: 'read' });
    assert.deepEqual(error.publicDetails.subscribed_events, ['push']);
    assert.deepEqual(error.publicDetails.missing_required_permissions, []);
    return true;
  });
  assert.equal(setup.calls.length, 1);
});
test('distinguishes missing automatic metadata from extra access', async () => {
  const setup = fixture(s => { s.app.permissions = { actions: 'read' }; });
  await assert.rejects(verifyInstallation(setup.options), error => {
    assert.deepEqual(error.publicDetails.missing_required_permissions, ['metadata']);
    assert.deepEqual(error.publicDetails.unexpected_permission_names, []);
    assert.deepEqual(error.publicDetails.subscribed_events, []);
    return true;
  });
});
test('diagnostics never print non-enum values or credential-shaped names', async () => {
  const setup = fixture(s => {
    s.app.permissions = { actions: 'PRIVATE_VALUE_SENTINEL', metadata: 'read', PRIVATE_KEY_SENTINEL: 'PRIVATE_VALUE_SENTINEL' };
    s.app.events = ['PRIVATE_KEY_SENTINEL', 'ghs_syntheticprivatetoken'];
    s.app.private_key = 'PRIVATE_KEY_SENTINEL';
  });
  await assert.rejects(verifyInstallation(setup.options), error => {
    const serialized = JSON.stringify(error.publicDetails);
    assert.ok(!serialized.includes('PRIVATE_'));
    assert.ok(!serialized.includes('ghs_syntheticprivatetoken'));
    assert.deepEqual(error.publicDetails.incorrect_required_levels, ['actions']);
    return true;
  });
});
