import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { randomUUID } from 'node:crypto';
import esbuild from 'esbuild';
import { createReplicaState } from '../src/mobile/reducer.js';

const bundle = await esbuild.build({ entryPoints: ['src/mobile/view.js'], bundle: true, write: false, format: 'cjs', platform: 'node', external: ['obsidian'] });
const module = { exports: {} };
const notices = [];
vm.runInNewContext(bundle.outputFiles[0].text, {
  module, exports: module.exports, crypto: { randomUUID },
  require: () => ({ ItemView: class {}, Notice: class { constructor(message) { notices.push(message); } } })
});
const View = module.exports.ClaudianRemoteMobileView;
function view() {
  const instance = Object.create(View.prototype);
  instance.replica = { state: createReplicaState({
    transport: { status: 'connected' }, presence: { mac: { status: 'online', sessionId: 'mac', connectionGeneration: 1 } },
    capabilities: { semantic_stream: true, history_list: true, history_select: true },
    activeConversationId: 'current', conversations: { current: { id: 'current', turnOrder: [], turns: {} } }
  }), selectConversationForViewing: () => false };
  // View actions start after compatibility was confirmed by the reducer.
  instance.replica.state.compatibility = { writable: true, reason: 'ready' };
  instance.replica.state.compatibilityMode = false;
  instance.composer = { input: { value: '', blur() {} }, clear() { this.input.value = ''; }, setDraft(text) { this.input.value = text; } };
  instance.attachments = { references: () => [] };
  instance.attachmentDeliveries = new Set();
  return instance;
}

test('online history selection requests uncached conversations from the Mac', async () => {
  const instance = view();
  const calls = [];
  instance.send = async (type, payload) => { calls.push([type, payload.conversation_id]); return {}; };
  instance.setHistoryOpen = (open) => calls.push(['drawer', open]);
  await instance.selectHistory('uncached');
  assert.deepEqual(calls, [['history.select', 'uncached'], ['drawer', false]]);
});

test('opening history blurs the inline input and settings opens the plugin directly', async () => {
  const instance = view();
  const calls = [];
  instance.composer.input.blur = () => calls.push('blur');
  instance.setHistoryOpen = () => calls.push('history');
  instance.loadHistory = async () => calls.push('load');
  instance.setActiveSurface = () => calls.push('close');
  instance.plugin = { openConnectionSettings: () => { calls.push('settings', 'claudian-remote'); } };
  instance.app = { setting: { open: () => calls.push('settings'), openTabById: (id) => calls.push(id) } };
  await instance.openHistory();
  instance.openSettings();
  assert.deepEqual(calls, ['blur', 'history', 'load', 'blur', 'close', 'settings', 'claudian-remote']);
});

test('rejected inline send preserves text typed while waiting, and restores only once', async () => {
  const instance = view();
  instance.send = async (_type, _payload, text, { deliveryId }) => {
    instance.replica.state.commands[deliveryId] = { text, preserveDraft: true };
    instance.composer.input.value = 'next draft';
    return null;
  };
  await instance.sendMessage('failed draft', false);
  assert.equal(instance.composer.input.value, 'failed draft\n\nnext draft');
  const id = Object.keys(instance.replica.state.commands)[0];
  assert.equal(instance.replica.state.commands[id].draftRestored, true);
  instance.restoreFailedDraft('failed draft', id);
  assert.equal(instance.composer.input.value, 'failed draft\n\nnext draft');
});
