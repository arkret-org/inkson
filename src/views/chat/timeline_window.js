// Variable-height presentation index. It contains no message content or authority.
class TimelineLayout {
  constructor(keys = [], heights = new Map()) {
    this.keys = keys;
    this.heights = heights;
    this.sizes = keys.map(key => (heights.get(key) || 120) + 12);
    this.tree = new Float64Array(keys.length + 1);
    for (let i = 1; i < this.tree.length; i++) {
      this.tree[i] += this.sizes[i - 1];
      const parent = i + (i & -i);
      if (parent < this.tree.length) this.tree[parent] += this.tree[i];
    }
  }
  add(index, delta) {
    for (let i = index + 1; i < this.tree.length; i += i & -i) this.tree[i] += delta;
  }
  prefix(end) {
    let sum = 0;
    for (let i = end; i > 0; i -= i & -i) sum += this.tree[i];
    return sum;
  }
  total() { return Math.max(0, this.prefix(this.keys.length) - 12); }
  measure(index, height) {
    if (index < 0 || index >= this.keys.length || !Number.isFinite(height) || height <= 0) return false;
    const size = height + 12;
    if (Math.abs(this.sizes[index] - size) < 0.5) return false;
    this.heights.set(this.keys[index], height);
    this.add(index, size - this.sizes[index]);
    this.sizes[index] = size;
    return true;
  }
  at(offset) {
    let index = 0, sum = 0;
    let bit = 1;
    while (bit * 2 < this.tree.length) bit *= 2;
    for (; bit; bit >>= 1) {
      const next = index + bit;
      if (next < this.tree.length && sum + this.tree[next] <= offset) {
        index = next;
        sum += this.tree[next];
      }
    }
    return Math.min(index, Math.max(0, this.keys.length - 1));
  }
  window(top, viewport, maxRows = 120) {
    if (!this.keys.length) return { start: 0, end: 0, top: 0, total: 0 };
    let start = this.at(Math.max(0, top - 600));
    let end = Math.min(this.keys.length, this.at(top + viewport + 600) + 1);
    if (end - start > maxRows) {
      const center = this.at(top);
      start = Math.max(start, center - 12);
      end = Math.min(this.keys.length, start + maxRows);
    }
    return { start, end, top: this.prefix(start), total: this.total() };
  }
}

async function runVirtualTimeline() {
  let config;
  try { config = await dioxus.recv(); } catch (_) { return; }
  const feed = document.getElementById(config.feed_id);
  const list = feed?.querySelector('[data-testid="virtual-timeline"]');
  if (!feed || !list) return;
  let heights = new Map(), layout = new TimelineLayout(), generation = 0;
  let frame = 0, last = '', disposed = false, awaiting = false;
  let followed = config.follows_latest !== false, pendingOffset = null, lastFocus = null;
  if (!followed) feed.scrollTop = config.restore_top || 0;
  const observed = new Set();
  let previousOrigin = null, previousTotal = null;
  const origin = () => list.getBoundingClientRect().top - feed.getBoundingClientRect().top + feed.scrollTop;
  const schedule = () => { if (!disposed && !frame) frame = requestAnimationFrame(update); };
  const resize = new ResizeObserver(schedule);
  const mutations = new MutationObserver(schedule);
  resize.observe(feed);
  mutations.observe(feed, { childList: true, subtree: true, characterData: true });
  const onScroll = () => {
    followed = feed.scrollHeight - feed.clientHeight - feed.scrollTop <= 32;
    schedule();
  };
  feed.addEventListener('scroll', onScroll, { passive: true });
  function update() {
    frame = 0;
    if (disposed || !feed.isConnected) return;
    const offset = origin();
    const originShift = previousOrigin !== null && !followed && pendingOffset === null
      ? offset - previousOrigin : 0;
    const before = Math.max(0, feed.scrollTop + originShift - offset);
    const anchor = layout.at(before);
    const anchorOffset = before - layout.prefix(anchor);
    const nearEnd = followed;
    const nodes = [...list.querySelectorAll('[data-virtual-index]')];
    const active = new Set(nodes);
    for (const node of observed) if (!active.has(node)) { resize.unobserve(node); observed.delete(node); }
    let changed = false;
    for (const node of nodes) {
      if (!observed.has(node)) { resize.observe(node); observed.add(node); }
      const index = Number(node.dataset.virtualIndex);
      if (layout.keys[index] !== node.dataset.messageId) continue;
      changed = layout.measure(index, node.getBoundingClientRect().height) || changed;
    }
    if (changed && pendingOffset === null) {
      pendingOffset = nearEnd ? 'latest' : offset + layout.prefix(anchor) + anchorOffset;
    }
    // Apply corrected height and scroll in one frame to keep an existing reader
    // anchored; browser auto-anchoring is disabled on this virtual container.
    if (pendingOffset === null && followed && (offset !== previousOrigin || layout.total() !== previousTotal)) pendingOffset = 'latest';
    if (pendingOffset === null && originShift) pendingOffset = feed.scrollTop + originShift;
    previousOrigin = offset;
    previousTotal = layout.total();
    list.style.height = `${layout.total()}px`;
    if (pendingOffset !== null) {
      feed.scrollTop = pendingOffset === 'latest' ? feed.scrollHeight : pendingOffset;
      pendingOffset = null;
    }
    followed = feed.scrollHeight - feed.clientHeight - feed.scrollTop <= 32;
    const window = layout.window(Math.max(0, feed.scrollTop - origin()), feed.clientHeight);
    const signature = [generation, window.start, window.end, window.top, window.total].join(':');
    if (signature !== last && !awaiting) {
      last = signature;
      awaiting = true;
      dioxus.send({ generation, ...window });
    }
  }
  try {
    for (;;) {
      const next = await dioxus.recv();
      if (next.dispose) break;
      if (next.ack) { awaiting = false; schedule(); continue; }
      const offset = origin();
      const index = layout.at(Math.max(0, feed.scrollTop - offset));
      const anchorKey = layout.keys[index];
      const anchorOffset = feed.scrollTop - offset - layout.prefix(index);
      const wasFollowing = followed;
      const allowed = new Set(next.keys);
      for (const key of heights.keys()) if (!allowed.has(key)) heights.delete(key);
      layout = new TimelineLayout(next.keys, heights);
      generation = next.generation;
      awaiting = false;
      last = '';
      const focusIndex = next.focus && next.focus !== lastFocus ? layout.keys.indexOf(next.focus) : -1;
      if (!next.focus || focusIndex >= 0) lastFocus = next.focus;
      const restored = layout.keys.indexOf(anchorKey);
      pendingOffset = focusIndex >= 0 ? offset + layout.prefix(focusIndex)
        : wasFollowing ? 'latest'
        : restored >= 0 ? offset + layout.prefix(restored) + anchorOffset : feed.scrollTop;
      schedule();
    }
  } catch (_) {
    // The owning component disposed its local eval channel.
  } finally {
    disposed = true;
    if (frame) cancelAnimationFrame(frame);
    resize.disconnect();
    mutations.disconnect();
    feed.removeEventListener('scroll', onScroll);
    observed.clear();
    heights.clear();
  }
}
if (typeof module !== 'undefined') module.exports = { TimelineLayout };
if (typeof dioxus !== 'undefined') runVirtualTimeline();
