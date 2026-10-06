const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const sandbox = { module: { exports: {} } };
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../src/views/chat/timeline_window.js'), 'utf8'), sandbox);
const { TimelineLayout } = sandbox.module.exports;

test('ten thousand variable-height rows have exact logarithmic offsets and bounded windows', () => {
  const keys = Array.from({length: 10000}, (_, i) => `message-${i}`);
  const heights = new Map(keys.map((key, i) => [key, 36 + (i % 23) * 19]));
  const layout = new TimelineLayout(keys, heights);
  let offset = 0;
  for (let i = 0; i < keys.length; i++) {
    assert.equal(layout.prefix(i), offset);
    assert.equal(layout.at(offset), i);
    assert.equal(layout.at(offset + heights.get(keys[i]) - 1), i);
    const window = layout.window(offset, 800);
    assert.ok(window.start <= i && window.end > i);
    assert.ok(window.end - window.start <= 120);
    assert.equal(window.top, layout.prefix(window.start));
    offset += heights.get(keys[i]) + 12;
  }
  assert.equal(layout.total(), offset - 12);
});

test('late image expansion corrects offsets without rebuilding message history', () => {
  const layout = new TimelineLayout(Array.from({length: 10000}, (_, i) => `${i}`));
  const oldTop = layout.prefix(5000);
  assert.equal(layout.measure(100, 1120), true);
  assert.equal(layout.prefix(5000), oldTop + 1000);
  assert.equal(layout.at(oldTop + 1000), 5000);
  assert.equal(layout.measure(100, 1120), false);
  assert.equal(layout.measure(100, NaN), false);
  assert.equal(layout.measure(10001, 99), false);
});

test('tiny rows and large viewports cannot create an unbounded DOM slice', () => {
  const keys = Array.from({length: 10000}, (_, i) => `${i}`);
  const layout = new TimelineLayout(keys, new Map(keys.map(key => [key, 1])));
  for (const top of [0, 13000, 65000, 129000]) {
    const window = layout.window(top, 10000);
    assert.ok(window.end - window.start <= 120);
    assert.ok(window.start <= layout.at(top) && window.end > layout.at(top));
  }
  const empty = new TimelineLayout();
  assert.deepEqual(JSON.parse(JSON.stringify(empty.window(0, 800))), { start: 0, end: 0, top: 0, total: 0 });
});

test('measured heights survive append and reorder by identity', () => {
  const heights = new Map();
  const first = new TimelineLayout(['a', 'b', 'c'], heights);
  first.measure(1, 500);
  const next = new TimelineLayout(['new', 'c', 'b', 'a'], heights);
  assert.equal(next.prefix(3) - next.prefix(2), 512);
  assert.equal(next.at(next.prefix(2) + 250), 2);
});

test('bridge settles after scrolling ten thousand rows, tracks follow intent, and releases observers', async () => {
  let receiver, nodes = [], sent = [], frames = new Map(), nextFrame = 0, observers = [], prefix = 20;
  const queue = [];
  const deliver = value => receiver ? (receiver(value), receiver = null) : queue.push(value);
  const list = { style: {height: '0px'}, querySelectorAll: () => nodes,
    getBoundingClientRect: () => ({top: prefix - feed.scrollTop}) };
  const feed = {isConnected: true, clientHeight: 800, scrollTop: 0, listeners: new Map(),
    querySelector: () => list, getBoundingClientRect: () => ({top: 0}),
    get scrollHeight() { return prefix + parseFloat(list.style.height); },
    addEventListener(name, fn) { this.listeners.set(name, fn); },
    removeEventListener(name) { this.listeners.delete(name); } };
  class Observer {
    constructor(callback) {this.callback = callback; this.targets = new Set(); observers.push(this);}
    observe(target) {this.targets.add(target);}
    unobserve(target) {this.targets.delete(target);}
    disconnect() {this.targets.clear(); this.disconnected = true;}
  }
  const context = {module: {exports: {}}, document: {getElementById: () => feed},
    ResizeObserver: Observer, MutationObserver: Observer,
    requestAnimationFrame(fn) { const id = ++nextFrame; frames.set(id, fn); return id; },
    cancelAnimationFrame(id) { frames.delete(id); },
    dioxus: {
      recv: () => queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve => receiver = resolve),
      send(value) {
        sent.push(value);
        assert.ok(value.end - value.start <= 120);
        nodes = Array.from({length: value.end - value.start}, (_, i) => ({
          dataset: {virtualIndex: `${value.start+i}`, messageId: `row-${value.start+i}`},
          getBoundingClientRect: () => ({height: 120}),
        }));
        deliver({ack: true});
        observers[1].callback();
      },
    },
  };
  deliver({feed_id: 'test', follows_latest: true});
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../src/views/chat/timeline_window.js'), 'utf8'), context);
  const settle = async () => {
    for (let i = 0; i < 30; i++) {
      await new Promise(resolve => setImmediate(resolve));
      if (!frames.size) return;
      const pending = [...frames.values()]; frames.clear(); pending.forEach(fn => fn());
    }
    assert.fail('virtual bridge did not settle');
  };
  await settle();
  deliver({generation: 1, keys: Array.from({length: 10000}, (_, i) => `row-${i}`), focus: ''});
  await settle();
  assert.equal(sent.at(-1).end, 10000);
  prefix += 1000;
  observers[1].callback();
  await settle();
  assert.equal(feed.scrollTop, feed.scrollHeight);
  feed.scrollTop = 660000 + prefix;
  feed.listeners.get('scroll')();
  await settle();
  assert.ok(sent.at(-1).start <= 5000 && sent.at(-1).end > 5000);
  const readerTop = feed.scrollTop;
  prefix += 1000;
  observers[1].callback();
  await settle();
  assert.equal(feed.scrollTop, readerTop + 1000);
  deliver({generation: 2, keys: [], focus: 'row-100'});
  await settle();
  deliver({generation: 3, keys: Array.from({length: 10000}, (_, i) => `row-${i}`), focus: 'row-100'});
  await settle();
  assert.ok(sent.at(-1).start <= 100 && sent.at(-1).end > 100);
  const unchanged = sent.length;
  for (let i = 0; i < 20; i++) observers[1].callback();
  await settle();
  assert.equal(sent.length, unchanged);
  assert.ok(observers[0].targets.size <= 121);
  deliver({dispose: true});
  await settle();
  assert.ok(observers.every(observer => observer.disconnected && observer.targets.size === 0));
  assert.equal(feed.listeners.size, 0);
  assert.equal(frames.size, 0);
});
