const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../assets/livekit_desktop_driver.js'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
async function scenario({ rejectConnect = false, rejectKey = false } = {}) {
  const events = [], calls = [], handlers = new Map(), attached = [];
  let room;
  class Provider {
    async setKey(key, identity, index) {
      calls.push(['key', identity, index, Array.from(key)]);
      if (rejectKey) throw new Error('private failure');
    }
  }
  class Room {
    constructor(options) {
      room = this;
      assert.ok(options.e2ee.keyProvider instanceof Provider);
      this.remoteParticipants = new Map([['verified', { identity: 'verified-sender' }]]);
      this.localParticipant = {
        setMicrophoneEnabled: async value => calls.push(['audio', value]),
        setCameraEnabled: async value => calls.push(['video', value]),
        setScreenShareEnabled: async value => calls.push(['screen', value]),
      };
    }
    on(kind, callback) { handlers.set(kind, callback); }
    async connect(url, token) {
      calls.push(['connect', url, token]);
      if (rejectConnect) throw new Error('private token diagnostic');
    }
    async setE2EEEnabled(value) { calls.push(['e2ee', value]); }
    async disconnect() { calls.push(['disconnect']); }
  }
  const window = {
    isSecureContext: true,
    LivekitClient: { Room, ExternalE2EEKeyProvider: Provider, RoomEvent: { ParticipantConnected: 'participant', Disconnected: 'disconnected', TrackSubscribed: 'track' } },
    ipc: { postMessage: value => events.push(JSON.parse(value)) },
  };
  vm.runInNewContext(source, { window, document: { getElementById: id => id === 'remote-media' ? { appendChild: value => attached.push(value) } : null }, Uint8Array, Worker: undefined });
  assert.deepEqual(events, [{ event: 'ready' }]);
  window.__inksonMediaReceive({ cmd: 'init', config: { connectUrl: 'wss://media.example/', backendToken: 'private-token', audio: true, video: true, localIdentity: 'local-sender', frameKey: Array(32).fill(7) } });
  await tick(); await tick();
  return { events, calls, room, handlers, attached, command: value => window.__inksonMediaReceive(value) };
}
(async () => {
  const failed = await scenario({ rejectConnect: true });
  assert.ok(failed.events.some(value => value.event === 'failed'));
  assert.ok(!failed.events.some(value => value.event === 'connected'));
  assert.ok(!JSON.stringify(failed.events).includes('private'));
  const keyFailure = await scenario({ rejectKey: true });
  assert.ok(!keyFailure.events.some(value => value.event === 'connected'));
  assert.ok(!keyFailure.calls.some(value => value[0] === 'audio' || value[0] === 'video'));
  assert.ok(keyFailure.calls.some(value => value[0] === 'disconnect'));
  const success = await scenario();
  const position = kind => success.calls.findIndex(value => value[0] === kind);
  assert.ok(position('connect') < position('key'));
  assert.ok(position('key') < position('e2ee'));
  assert.ok(position('e2ee') < position('audio'));
  assert.ok(position('e2ee') < position('video'));
  assert.deepEqual(success.calls.find(value => value[0] === 'key').slice(1, 3), ['local-sender', 0]);
  assert.ok(success.events.some(value => value.event === 'participant' && value.identity === 'verified-sender'));
  assert.ok(success.events.some(value => value.event === 'connected'));
  success.handlers.get('track')({ attach: () => ({ identity: 'unverified' }) }, null, { identity: 'unverified' });
  success.handlers.get('track')({ attach: () => ({ identity: 'remote-sender' }) }, null, { identity: 'remote-sender' });
  assert.deepEqual(success.attached, []);
  success.command({ cmd: 'set_e2ee_key', identity: 'remote-sender', key: Array(32).fill(9), keyIndex: 3 });
  success.command({ cmd: 'set_muted', kind: 'audio', muted: true });
  success.command({ cmd: 'set_screen', enabled: true });
  await tick(); await tick();
  assert.ok(success.calls.some(value => value[0] === 'key' && value[1] === 'remote-sender' && value[2] === 3));
  assert.ok(success.calls.some(value => value[0] === 'audio' && value[1] === false));
  assert.ok(success.calls.some(value => value[0] === 'screen' && value[1] === true));
  assert.equal(success.attached.length, 1);
  assert.equal(success.attached[0].identity, 'remote-sender');
  success.command({ cmd: 'leave' });
  await tick(); await tick();
  assert.ok(success.calls.some(value => value[0] === 'disconnect'));
  assert.ok(success.events.some(value => value.event === 'left'));
  console.log('Native driver connection, sender-key ordering, controls, failure, and leave checks passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
