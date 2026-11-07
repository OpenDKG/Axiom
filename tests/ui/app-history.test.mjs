// SPDX-License-Identifier: GPL-3.0-or-later
// Runs the real wwwroot/app.js in a stub DOM to pin the History page behaviour that a browser
// audit caught: out-of-order responses, UTC rendering and the paging controls.
// No dependencies; run with `node --test tests/ui`.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';

const source = fs.readFileSync(
  path.join(import.meta.dirname, '../../src/Axiom.Desktop.Linux/wwwroot/app.js'),
  'utf8');

function createPage() {
  const elements = new Map();
  const make = (id) => {
    const element = {
      id,
      value: '',
      textContent: '',
      innerHTML: '',
      className: '',
      checked: false,
      disabled: false,
      hidden: false,
      listeners: {},
      addEventListener(type, handler) { this.listeners[type] = handler; },
      click() { this.listeners.click?.({ target: this }); },
      change() { this.listeners.change?.({ target: this }); },
    };
    elements.set(id, element);
    return element;
  };
  for (const id of ['service-state', 'auth-note', 'overview-cards', 'limitations', 'about-list',
    'nav', 'conn-count', 'conn-filter', 'conn-new-only', 'connections-body', 'history-body',
    'history-info', 'history-db', 'history-search', 'history-hours', 'history-run', 'history-next',
    'history-prev', 'history-export', 'firewall-summary', 'firewall-note', 'firewall-body',
    'privacy-summary', 'privacy-note', 'ai-enabled', 'ai-endpoint', 'ai-model', 'ai-redact', 'ai-key',
    'ai-key-save', 'ai-key-delete', 'ai-status', 'ai-save', 'ai-analyze', 'ai-output', 'reputation-key',
    'reputation-key-save', 'reputation-key-delete', 'reputation-status', 'reputation-path',
    'reputation-run', 'reputation-output', 'autostart-enabled']) {
    make(id);
  }
  elements.get('history-hours').value = '24';

  const requests = [];
  const context = {
    URLSearchParams, Date, Error, Number, JSON, isNaN,
    location: { hash: '', pathname: '/', reload() {} },
    history: { replaceState() {} },
    sessionStorage: { getItem: () => 'token' },
    window: { addEventListener() {} },
    document: { getElementById: (id) => elements.get(id), querySelectorAll: () => [] },
    setInterval() {},
    fetch: (url) => {
      if (String(url).startsWith('/api/history?')) {
        return new Promise((resolve) => requests.push({ url, resolve }));
      }
      return Promise.resolve({
        status: 503,
        ok: false,
        json: async () => ({ error: 'service_unavailable', message: 'offline' }),
      });
    },
  };
  vm.runInNewContext(source, context, { filename: 'app.js' });
  return { elements, requests };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test('an older history response never overwrites the newer selection', async () => {
  const { elements, requests } = createPage();
  elements.get('history-run').click();
  await flush();
  assert.equal(requests.length, 1);

  elements.get('history-hours').value = '1';
  elements.get('history-hours').change();
  await flush();
  assert.equal(requests.length, 2);

  const respond = (index, count, databasePath) => requests[index].resolve({
    status: 200,
    ok: true,
    json: async () => ({ totalCount: count, databasePath, rows: [] }),
  });

  respond(1, 10, 'new 1h');
  await flush();
  assert.equal(elements.get('history-db').textContent, 'new 1h');

  respond(0, 500, 'stale 24h');
  await flush();
  assert.equal(elements.get('history-db').textContent, 'new 1h');
  assert.equal(elements.get('history-info').textContent, '0 of 10');
  assert.equal(elements.get('history-next').disabled, true);
});

test('paging controls follow the offset and the total', async () => {
  const { elements, requests } = createPage();
  elements.get('history-run').click();
  await flush();
  requests[0].resolve({
    status: 200, ok: true,
    json: async () => ({ totalCount: 250, databasePath: 'db', rows: [{ firstSeenUtc: '2026-11-07T02:00:00Z' }] }),
  });
  await flush();
  assert.equal(elements.get('history-prev').disabled, true);
  assert.equal(elements.get('history-next').disabled, false);

  elements.get('history-next').click();
  await flush();
  assert.match(requests[1].url, /offset=200/);
  requests[1].resolve({
    status: 200, ok: true,
    json: async () => ({ totalCount: 250, databasePath: 'db', rows: [{ firstSeenUtc: '2026-11-07T02:00:00Z' }] }),
  });
  await flush();
  assert.equal(elements.get('history-prev').disabled, false);
  assert.equal(elements.get('history-next').disabled, true);
  assert.equal(elements.get('history-info').textContent, '201-201 of 250');
});

test('history timestamps are rendered in UTC, not the viewer zone', async () => {
  const { elements, requests } = createPage();
  elements.get('history-run').click();
  await flush();
  requests[0].resolve({
    status: 200, ok: true,
    json: async () => ({
      totalCount: 1, databasePath: 'db',
      rows: [{ appDisplayName: 'x', firstSeenUtc: '2026-11-07T02:03:04.5Z', lastSeenUtc: '2026-11-07T05:06:07Z' }],
    }),
  });
  await flush();
  const html = elements.get('history-body').innerHTML;
  assert.match(html, /2026-11-07 02:03:04/);
  assert.match(html, /2026-11-07 05:06:07/);
});

test('an expired token produces explicit guidance instead of "unauthorized"', async () => {
  const { elements, requests } = createPage();
  elements.get('history-run').click();
  await flush();
  requests[0].resolve({ status: 401, ok: false, json: async () => ({ error: 'unauthorized' }) });
  await flush();
  assert.match(elements.get('history-body').innerHTML, /Session token missing or expired/);
});
