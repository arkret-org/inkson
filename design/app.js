const cards = [
  {
    id: "legal",
    title: "Legal review for public beta",
    list: "Doing",
    summary: "Review privacy language before the public beta announcement.",
    priority: "High",
    due: "Today",
    assignee: "Alice",
    status: "Doing",
    labels: ["red", "cyan"],
    badge: "Review room · 4",
    roomState: "unread",
    state: "active",
  },
  {
    id: "checklist",
    title: "Draft launch checklist",
    list: "Todo",
    summary: "Acceptance criteria and release blockers.",
    priority: "Medium",
    due: "May 8",
    assignee: "Mina",
    status: "Todo",
    labels: ["green", "amber"],
    badge: "Room 5",
    roomState: "unread",
    state: "active",
  },
  {
    id: "announcement",
    title: "Prepare customer announcement",
    list: "Todo",
    summary: "Needs review from marketing and legal.",
    priority: "Medium",
    due: "May 10",
    assignee: "Sam",
    status: "Todo",
    labels: ["blue"],
    badge: "Locked room",
    roomState: "locked",
    state: "locked",
  },
  {
    id: "copy",
    title: "Finalize onboarding copy",
    list: "Doing",
    summary: "Move is queued while offline.",
    priority: "Low",
    due: "May 9",
    assignee: "Nina",
    status: "Doing",
    labels: ["green"],
    badge: "pending move",
    roomState: "",
    state: "pending",
  },
  {
    id: "security",
    title: "Security sign-off",
    list: "Review",
    summary: "CAS conflict: position changed remotely.",
    priority: "High",
    due: "Tomorrow",
    assignee: "Bob",
    status: "Review",
    labels: ["amber"],
    badge: "CAS conflict",
    roomState: "",
    state: "conflict",
  },
  {
    id: "release-board",
    title: "Create release board",
    list: "Done",
    summary: "Board/List/Card projection verified.",
    priority: "Low",
    due: "Done",
    assignee: "Alice",
    status: "Done",
    labels: ["blue"],
    badge: "cx.card.create",
    roomState: "",
    state: "done",
  },
];

const rooms = [
  { id: "review", name: "Review room", kind: "review", subtitle: "Primary room for Legal review", unread: 4, policy: "joined", encryption: "MLS" },
  { id: "board", name: "Launch board room", kind: "discussion", subtitle: "Board-level coordination", unread: 2, policy: "shared", encryption: "MLS" },
  { id: "external", name: "External counsel", kind: "external", subtitle: "Room-scoped external admission", unread: 0, policy: "joined", encryption: "MLS" },
  { id: "activity", name: "Activity feed", kind: "activity", subtitle: "Agent and workflow updates", unread: 0, policy: "restricted", encryption: "none" },
];

const nav = [
  ["dashboard", "layout-dashboard", "首页", "spaces / inbox"],
  ["space", "layers-3", "Space", "overview"],
  ["board", "columns-3", "Board", "kanban"],
  ["card/legal", "panel-right-open", "Card Detail", "clicked card"],
  ["room/review", "messages-square", "Rooms", "chat"],
  ["inbox", "inbox", "Inbox", "mentions"],
  ["directory", "search", "Directory", "discover"],
  ["contacts", "users", "Actors", "contacts"],
  ["admin", "shield-check", "Admin", "policy"],
  ["devices", "key-round", "Devices", "keys"],
  ["audit", "file-search", "Audit", "events"],
  ["settings", "settings", "Settings", "prefs"],
];

const app = document.getElementById("app");

document.addEventListener("click", (event) => {
  const target = event.target.closest("[data-route]");
  if (!target) return;
  event.preventDefault();
  location.hash = target.dataset.route;
});

window.addEventListener("hashchange", render);

function route() {
  return (location.hash || "#login").replace("#", "");
}

function base(path = route()) {
  return path.split("/")[0];
}

function currentCard() {
  const id = route().split("/")[1] || "legal";
  return cards.find((card) => card.id === id) || cards[0];
}

function currentRoom() {
  const id = route().split("/")[1] || "review";
  return rooms.find((room) => room.id === id) || rooms[0];
}

function render() {
  const current = route();
  if (current === "login") {
    app.innerHTML = login();
  } else if (current === "register") {
    app.innerHTML = register();
  } else {
    app.innerHTML = shell(current, main(current));
  }
  if (window.lucide) window.lucide.createIcons();
}

function login() {
  return `
    <main class="auth app-root">
      <section class="auth-main">
        ${brand()}
        <div class="auth-copy">
          <div class="eyebrow">Contrix product prototype</div>
          <h1>登录到你的协作空间</h1>
          <p>静态高保真原型。按钮会跳转，数据是固定假数据，用来验证完整应用流程、Board/Card/Room 信息架构和交互状态。</p>
        </div>
        <div class="form-card">
          <div class="field"><label>Principal Server</label><input value="http://127.0.0.1:8787"></div>
          <div class="form-grid">
            <div class="field"><label>DID / handle</label><input value="did:web:alice.example"></div>
            <div class="field"><label>Device</label><input value="alice-windows"></div>
          </div>
          <div class="actions">
            <button class="btn primary" data-route="dashboard"><i data-lucide="log-in"></i>登录</button>
            <button class="btn" data-route="register">创建账号</button>
            <button class="btn ghost" data-route="dashboard">Dev login</button>
          </div>
        </div>
        <div class="badge-row">
          <span class="badge green">server describe ready</span>
          <span class="badge blue">chat + kanban profiles</span>
          <span class="badge amber">2 local events</span>
        </div>
      </section>
      <section class="auth-stage">
        <div class="auth-copy">
          <div class="eyebrow">Workspace-first UI</div>
          <h1>Board、Card、Room 在一个真实工作台里流动</h1>
          <p>Card 点击后打开详情抽屉，primary Room 直接进入聊天；不可见 Room 显示 locked lazy link。拖拽、消息、设备和审计都有完整入口。</p>
        </div>
        <div class="auth-preview">
          <div class="preview-window">
            <div class="preview-top">
              <strong>Launch Board</strong>
              <div class="badge-row"><span class="badge dark">frontier cx:event:review-44</span><span class="badge dark">local queue 2</span></div>
            </div>
            <div class="preview-board">
              <div class="preview-col"><strong>Todo</strong><div class="preview-task">Draft launch checklist<small>Room 5</small></div><div class="preview-task">Customer announcement<small>Locked room</small></div></div>
              <div class="preview-col"><strong>Doing</strong><div class="preview-task">Legal review<small>Review room · 4 unread</small></div><div class="preview-task">Onboarding copy<small>pending move</small></div></div>
              <div class="preview-col"><strong>Review</strong><div class="preview-task">Security sign-off<small>CAS conflict</small></div></div>
            </div>
          </div>
        </div>
      </section>
    </main>
  `;
}

function register() {
  return `
    <main class="auth app-root">
      <section class="auth-main">
        ${brand()}
        <div class="auth-copy">
          <div class="eyebrow">Account bootstrap</div>
          <h1>创建 Contrix 账号</h1>
          <p>注册流程创建 actor 身份和设备信任，不自动授予任何 Space、Board、Card 或 Room 权限。</p>
        </div>
        <div class="form-card">
          <div class="form-grid">
            <div class="field"><label>DID method</label><select><option>did:web</option><option>did:key</option><option>Import DID</option></select></div>
            <div class="field"><label>Handle</label><input value="alice.example"></div>
            <div class="field"><label>Display name</label><input value="Alice Chen"></div>
            <div class="field"><label>Device label</label><input value="alice-windows"></div>
          </div>
          <div class="field"><label>Recovery policy</label><select><option>Passphrase + recovery contact</option><option>Security key</option></select></div>
          <div class="actions">
            <button class="btn primary" data-route="dashboard">完成注册</button>
            <button class="btn" data-route="login">返回登录</button>
          </div>
        </div>
      </section>
      <section class="auth-stage">
        <div class="auth-copy">
          <div class="eyebrow">Invite aware</div>
          <h1>从邀请进入时，注册后继续 Space Join Flow</h1>
          <p>接受 invite 写入 cx.invite.accept；Room membership 和 Space membership 仍然分别校验。</p>
        </div>
        <div class="preview-window">
          <div class="preview-top"><strong>Pending invite</strong><span class="badge dark">cx:invite:01demo</span></div>
          <div style="padding:18px;display:grid;gap:12px">
            <h2>Launch Board Review</h2>
            <p>邀请你加入 Contrix Demo Space，并可请求 Review room 的读取权限。</p>
            <div class="actions"><button class="btn primary" data-route="dashboard">Accept after signup</button></div>
          </div>
        </div>
      </section>
    </main>
  `;
}

function shell(current, content) {
  return `
    <div class="shell app-root">
      <aside class="sidebar">
        ${brand()}
        <section class="workspace-card">
          <h3>Contrix Demo Space</h3>
          <div class="status-row"><span>Server</span><b>online</b></div>
          <div class="status-row"><span>Cursor</span><b>sx:e2e:product</b></div>
          <div class="status-row"><span>Local queue</span><b>2</b></div>
        </section>
        <nav class="nav">${nav.map((item) => navItem(item, current)).join("")}</nav>
        <button class="btn dark" data-route="login"><i data-lucide="log-out"></i>退出原型</button>
      </aside>
      <section class="main">
        <header class="topbar">
          <button class="btn mobile-menu" data-route="dashboard">Menu</button>
          <div class="crumb"><strong>${titleFor(current)}</strong><span>Contrix Demo Space · cx:space:01js0sp0000000000000000000</span></div>
          <label class="search"><i data-lucide="search"></i><input placeholder="Search cards, rooms, messages, actors"></label>
          <div class="top-actions">
            <div class="avatar-stack"><span class="mini-avatar">AC</span><span class="mini-avatar" style="background:#7c3aed">B</span><span class="mini-avatar" style="background:#0f766e">M</span></div>
            <button class="btn small" data-route="inbox">Inbox 9</button>
            <button class="btn small primary" data-route="board">Create</button>
            <div class="avatar">AC</div>
          </div>
        </header>
        ${content}
      </section>
    </div>
  `;
}

function brand() {
  return `<div class="brand"><div class="logo">Y</div><span>yougen</span></div>`;
}

function navItem([path, icon, label, sub], current) {
  const active = base(path) === base(current) ? "active" : "";
  return `
    <button class="${active}" data-route="${path}">
      <span class="nav-icon"><i data-lucide="${icon}"></i></span>
      <span class="nav-label"><strong>${label}</strong><small>${sub}</small></span>
    </button>
  `;
}

function titleFor(path) {
  const titles = {
    dashboard: "应用首页",
    space: "Space 概览",
    board: "Launch Board",
    card: "Card Detail",
    room: "Review room",
    inbox: "Inbox",
    directory: "Directory",
    contacts: "Actors",
    admin: "Space Admin",
    devices: "Devices",
    audit: "Audit",
    settings: "Settings",
  };
  return titles[base(path)] || "yougen";
}

function main(current) {
  const key = base(current);
  if (key === "dashboard") return dashboard();
  if (key === "space") return space();
  if (key === "board") return board();
  if (key === "card") return cardDetail(currentCard());
  if (key === "room") return room(currentRoom());
  if (key === "inbox") return inbox();
  if (key === "directory") return directory();
  if (key === "contacts") return contacts();
  if (key === "admin") return admin();
  if (key === "devices") return devices();
  if (key === "audit") return audit();
  if (key === "settings") return settings();
  return dashboard();
}

function pageHead(title, copy, actions = "") {
  return `
    <div class="page-head">
      <div class="page-title"><div class="eyebrow">yougen prototype</div><h1>${title}</h1><p>${copy}</p></div>
      <div class="actions">${actions}</div>
    </div>
  `;
}

function dashboard() {
  return `
    <main class="page">
      ${pageHead("应用首页", "登录后的默认工作台：最近 Board、待处理通知、Space 活动、同步和设备健康集中展示。", `<button class="btn" data-route="space">Open Space</button><button class="btn primary" data-route="board">Open Launch Board</button>`)}
      <section class="grid four">
        ${metric("Joined Spaces", "12", "2 with lazy links")}
        ${metric("Assigned Cards", "7", "3 due this week")}
        ${metric("Unread Rooms", "28", "9 actionable")}
        ${metric("Local Queue", "2 events", "pending submit")}
      </section>
      <section class="grid two">
        <div class="panel pad">
          <div class="section-head"><h2>Recent Boards</h2><button class="btn small" data-route="board">View board</button></div>
          ${activity("kanban · 4 lists", "Launch Board", "Legal review, security sign-off and onboarding copy are active.", "board")}
          ${activity("review_queue · 8 cards", "Memory Review", "Agent memory candidates waiting for human confirmation.", "audit")}
        </div>
        <div class="panel pad">
          <div class="section-head"><h2>Inbox</h2><button class="btn small" data-route="inbox">View all</button></div>
          ${activity("@mention · Review room", "Bob mentioned you", "Open Card detail + target Room if both are visible.", "card/legal")}
          ${activity("conflict · cx.card.move", "Move needs review", "Your offline card move needs replay.", "audit")}
          ${activity("device · keys", "iPhone key package expires soon", "Verify or rotate the pending key package.", "devices")}
        </div>
      </section>
      <section class="panel pad">
        <div class="section-head"><h2>Protocol Health</h2><span class="badge green">frontier verified</span></div>
        ${table(["Area", "State", "Protocol", "Action"], [["Sync", "online", "frontier verified", "Backfill"], ["E2EE", "ready", "MLS epoch 4", "Verify device"], ["Projection", "partial", "1 lazy link", "Open audit"]])}
      </section>
    </main>
  `;
}

function space() {
  return `
    <main class="page">
      ${pageHead("Contrix Demo Space", "Space 是权限和同步边界。这个页面展示该 Space 下可见的 Boards、Rooms、近期 Event 和跨 Space lazy link。", `<button class="btn">Backfill</button><button class="btn primary" data-route="board">Create Board</button>`)}
      <section class="grid four">${metric("Boards", "4", "1 default view")}${metric("Rooms", "12", "3 restricted")}${metric("Cards", "83", "7 assigned")}${metric("Lazy Links", "3", "no cascade")}</section>
      <section class="grid two">
        <div class="panel pad">
          <h2>Visible work surfaces</h2>
          ${activity("board · kanban", "Launch Board", "Default working board with Card Rooms.", "board")}
          ${activity("room · discussion", "Launch board room", "Board-level coordination Room.", "room/board")}
          ${activity("room · external", "External counsel", "Room-scoped external admission.", "room/external")}
        </div>
        <div class="panel pad">
          <h2>Recent activity</h2>
          ${activity("cx.card.move", "Legal review moved into Doing", "Reducer accepted active position edge.", "card/legal")}
          ${activity("cx.message.create", "New message in Review room", "Message references cx:card:01legal.", "room/review")}
          ${activity("cx.room.member", "External counsel joined", "History visibility is joined.", "admin")}
        </div>
      </section>
    </main>
  `;
}

function board() {
  const lists = ["Todo", "Doing", "Review", "Done"];
  return `
    <main class="page">
      <section class="board">
        <div class="board-head">
          <div>
            <div class="eyebrow" style="color:#c9e7f1">board · cx:board:01launch0000000000000000</div>
            <h1>Launch Board</h1>
            <p>Shared board projection · frontier cx:event:review-44 · local queue 2</p>
          </div>
          <div class="actions">
            <button class="btn" data-route="room/board"><i data-lucide="messages-square"></i>Board Room</button>
            <button class="btn"><i data-lucide="share-2"></i>Share</button>
            <button class="btn primary" data-route="card/legal">Open selected card</button>
          </div>
        </div>
        <div class="board-canvas">
          ${lists.map((name) => listColumn(name, cards.filter((card) => card.list === name))).join("")}
          <button class="add-list">+ Add another list</button>
        </div>
      </section>
    </main>
  `;
}

function listColumn(name, items) {
  return `
    <section class="list">
      <div class="list-head"><strong>${name}</strong><span>${items.length} cards</span></div>
      ${items.map(task).join("")}
      <button class="add-card">+ Add a card</button>
    </section>
  `;
}

function task(card) {
  const taskClass = card.id === "legal" ? "active" : card.state === "pending" ? "pending" : card.state === "conflict" ? "conflict" : "";
  return `
    <button class="task ${taskClass}" data-route="card/${card.id}">
      <div class="label-row">${card.labels.map((label) => `<span class="label ${label}"></span>`).join("")}</div>
      <h3>${card.title}</h3>
      <p>${card.summary}</p>
      <div class="task-meta">
        <span>${card.assignee}</span>
        <span>${card.due}</span>
        <span class="room-pill ${card.roomState}">${card.badge}</span>
      </div>
    </button>
  `;
}

function cardDetail(card) {
  return `
    <main class="page">
      ${pageHead("点击 Card 后的详情", "点击 Card 不跳出工作上下文，而是打开详情抽屉：字段、Room、Chat、Activity、Audit 同屏完成。", `<button class="btn" data-route="board">Back to Board</button><button class="btn primary">Save changes</button>`)}
      <section class="drawer-layout">
        <div class="board" style="min-height:620px">
          <div class="board-head"><div><h2>Launch Board context</h2><p>Card drawer keeps board position visible.</p></div></div>
          <div class="board-canvas">${["Todo", "Doing", "Review"].map((name) => listColumn(name, cards.filter((item) => item.list === name))).join("")}</div>
        </div>
        <aside class="drawer">
          <div class="panel detail-hero">
            <div class="detail-title-row">
              <div><div class="eyebrow">cx:card:01${card.id}...</div><h1>${card.title}</h1></div>
              <span class="badge ${card.state === "conflict" ? "red" : "green"}">${card.state}</span>
            </div>
            <p>${card.summary} Card state is separate from Room discussion and permissions.</p>
            <div class="field-grid">${fieldTile("Status", card.status)}${fieldTile("Priority", card.priority)}${fieldTile("Due", card.due)}${fieldTile("Assignee", card.assignee)}</div>
          </div>
          <div class="panel pad">
            <div class="section-head"><h2>Rooms</h2><button class="btn small">Link room</button></div>
            <div class="room-list">
              <button class="room-row active" data-route="room/review"><span><strong>Review room</strong><br><small>primary_room · review · E2EE MLS · 4 unread</small></span><span class="badge blue">Open</span></button>
              <button class="room-row"><span><strong>Private decision</strong><br><small>locked lazy link · no title leak if not discoverable</small></span><span class="badge amber">Locked</span></button>
              <button class="room-row" data-route="room/external"><span><strong>External counsel</strong><br><small>external · history_visibility=joined</small></span><span class="badge purple">External</span></button>
            </div>
          </div>
          <div class="panel pad">
            <div class="section-head"><h2>Chat preview</h2><button class="btn small" data-route="room/review">Open Room</button></div>
            ${messageBubble("A", "Alice", "09:41", "@bob 请确认 privacy clause 是否可以进入 public beta。")}
            <div class="field"><label>Reply in primary Room</label><textarea placeholder="Write a message"></textarea></div>
            <div class="actions"><button class="btn small">Attach</button><button class="btn small primary">Send</button></div>
          </div>
          <div class="panel pad">
            <h2>Activity and audit</h2>
            ${activity("cx.card.move", "Move conflict handled", "Doing -> Review was rejected as stale; current card remains in Doing.", "audit")}
            ${activity("cx.card.link_room", "Review room linked", "purpose=review; link does not grant Room access.", "audit")}
          </div>
        </aside>
      </section>
    </main>
  `;
}

function room(room) {
  return `
    <main class="page">
      ${pageHead("Room 聊天", "Room 是标准对象，不是 Card comment。Card 可见和 Room 可见分别校验。", `<button class="btn">New room</button><button class="btn primary">Invite</button>`)}
      <section class="chat-layout">
        <aside class="room-column">
          ${rooms.map((item) => `<button class="room-button ${item.id === room.id ? "active" : ""}" data-route="room/${item.id}"><strong>${item.name}</strong><small>${item.kind} · ${item.subtitle}</small><span class="badge ${item.unread ? "blue" : "green"}">${item.unread ? `${item.unread} unread` : "read"}</span></button>`).join("")}
        </aside>
        <section class="panel message-panel">
          <div class="message-head">
            <div><h2>${room.name}</h2><p>room_kind=${room.kind} · history_visibility=${room.policy} · encryption_profile=${room.encryption}</p></div>
            <span class="badge green">member</span>
          </div>
          <div class="message-scroll">
            ${messageRow("A", "Alice", "09:41 · cx.message.create", "@bob 请确认 privacy clause 是否可以进入 public beta。", ["mentions did:web:bob.example", "references cx:card:01legal"])}
            ${messageRow("B", "Bob", "09:58 · revised", "需要把 external processor 的表述收窄，我会给出替换文本。", ["revision chain", "reaction +2"])}
            ${messageRow("C", "Carol", "10:03 · cx.message.redact", "[Message redacted]", ["tombstone"])}
          </div>
          <div class="composer">
            <div class="field"><label>Message composer</label><textarea placeholder="Write markdown with structured @mentions and #object refs"></textarea></div>
            <div class="actions"><button class="btn small">Attach blob</button><button class="btn small">Mention</button><button class="btn small primary">Send</button></div>
          </div>
        </section>
        <aside class="context-column">
          <div class="panel pad"><h2>Context</h2>${activity("linked card · visible", "Legal review for public beta", "Card visibility checked independently from Room visibility.", "card/legal")}</div>
          <div class="panel pad"><h2>Membership</h2><p>Alice, Bob, Carol, external counsel. External badge is visible because policy allows member list disclosure.</p><div class="badge-row"><span class="badge purple">external</span><span class="badge green">joined history</span></div></div>
          <div class="panel pad"><h2>Policy</h2><p>New members see messages after join unless a history sharing event is explicitly approved.</p></div>
        </aside>
      </section>
    </main>
  `;
}

function inbox() {
  return `
    <main class="page">
      ${pageHead("Inbox / Notifications", "Notification 是派生投影。点击通知时重新验证 Card 和 Room 权限。", `<button class="btn">Mark all read</button><button class="btn primary">Refresh</button>`)}
      <section class="grid two">
        <div class="panel pad">
          <h2>Actionable</h2>
          ${activity("@mention · Review room", "Bob mentioned you", "Open Card detail + target Room if both are visible.", "card/legal")}
          ${activity("assigned · Security sign-off", "Card assigned to you", "Assignment relation is visible; linked private Room remains locked.", "card/security")}
          ${activity("conflict · cx.card.move", "Move needs review", "Your offline move was stale after sync; replay from latest projection.", "audit")}
        </div>
        <div class="panel pad"><h2>Read state and mute rules</h2>${table(["Source", "Read marker", "Mute", "Policy"], [["Review room", "private account data", "off", "joined history"], ["Launch board", "public receipt allowed", "off", "shared"], ["External counsel", "private only", "on", "restricted"]])}</div>
      </section>
    </main>
  `;
}

function directory() {
  return `
    <main class="page">
      ${pageHead("Directory", "发现 Spaces、Boards、Cards、Rooms、Actors。结果区分 readable、discoverable 和 locked lazy link。", `<button class="btn">Exact resolve</button><button class="btn primary">Search</button>`)}
      <section class="panel pad">
        <div class="form-grid"><div class="field"><label>Search</label><input value="launch legal review"></div><div class="field"><label>Scope</label><select><option>All visible objects</option><option>Spaces</option><option>Rooms</option><option>Cards</option><option>Actors</option></select></div></div>
        <div class="badge-row"><span class="badge blue">Card</span><span class="badge green">Room</span><span class="badge">Board</span><span class="badge amber">Locked</span></div>
      </section>
      <section class="grid three">
        ${activity("card · readable", "Legal review for public beta", "Located in Launch Board / Doing. Primary Room visible.", "card/legal")}
        ${activity("room · locked", "Private decision", "Discovery policy allows existence only. No title, members, unread or summary in restricted mode.", "inbox")}
        ${activity("actor · verified", "did:web:bob.example", "Handle verified, two trusted devices.", "contacts")}
      </section>
    </main>
  `;
}

function contacts() {
  return `
    <main class="page">
      ${pageHead("Actors / Contacts", "联系人不是 Space membership，也不是 Room membership。这里管理 actor 发现、请求、信任提示和 block。", `<button class="btn">Resolve handle</button><button class="btn primary">Add contact</button>`)}
      <section class="panel pad"><div class="form-grid"><div class="field"><label>DID / handle</label><input value="did:web:bob.example"></div><div class="field"><label>Request note</label><input value="Let's collaborate on launch review"></div></div></section>
      <section class="panel pad"><h2>Requests and contacts</h2>${table(["Actor", "Relationship", "Trust", "Action"], [["did:web:bob.example", "contact", "verified handle", "Message / Remove"], ["did:web:carol.example", "pending inbound", "unknown device", "Accept / reject"], ["did:web:spam.example", "blocked", "hidden", "Unblock"]])}</section>
    </main>
  `;
}

function admin() {
  return `
    <main class="page">
      ${pageHead("Space Admin", "管理 Space 元数据、成员、邀请、capability、Room 外部接入策略和危险生命周期。", `<button class="btn">Rotate epoch</button><button class="btn primary">Invite member</button>`)}
      <section class="grid two">
        <div class="panel pad">
          <h2>Metadata and policy</h2>
          <div class="form-grid">
            <div class="field"><label>Name</label><input value="Contrix Demo Space"></div>
            <div class="field"><label>Join rule</label><select><option>Invite only</option><option>Public request</option></select></div>
            <div class="field"><label>Room external admission</label><select><option>Allowed by policy</option><option>Disabled</option></select></div>
            <div class="field"><label>Default history visibility</label><select><option>joined</option><option>shared</option><option>restricted</option></select></div>
          </div>
        </div>
        <div class="panel pad">
          <h2>Invite flow</h2>
          ${activity("pending · cx.invite.create", "did:web:carol.example", "Invite does not grant Room membership until accepted and policy checks pass.", "contacts")}
          ${activity("external room · room-scoped", "vendor@example.com", "Allowed only in External counsel Room; no Board or directory read.", "room/external")}
        </div>
      </section>
      <section class="panel pad"><h2>Members and grants</h2>${table(["Actor", "Role", "Scope", "Action"], [["did:web:alice.example", "owner", "space admin", "Transfer"], ["did:web:bob.example", "member", "board/card/room", "Update grant"], ["vendor@example.com", "external", "single room", "Revoke"]])}</section>
    </main>
  `;
}

function devices() {
  return `
    <main class="page">
      ${pageHead("Devices and Keys", "设备信任、KeyPackage、one-time keys、to-device queue、push registration 和 Room E2EE 状态。", `<button class="btn">Upload keys</button><button class="btn primary">Verify device</button>`)}
      <section class="grid four">${metric("Current device", "alice-windows", "trusted")}${metric("One-time keys", "42", "healthy")}${metric("To-device queue", "2", "pending")}${metric("MLS epoch", "4", "active")}</section>
      <section class="grid two">
        <div class="panel pad"><h2>Trusted devices</h2>${table(["Device", "Trust", "Keys", "Action"], [["alice-windows", "current trusted", "uploaded", "Rotate"], ["alice-iphone", "pending SAS", "keypackage received", "Verify / reject"], ["old-laptop", "revoked", "epoch rotated", "Audit"]])}</div>
        <div class="panel pad"><h2>Verification ceremony</h2><div class="grid two">${metric("SAS", "742 918", "compare both devices")}${metric("Pending device", "alice-iphone", "keypackage received")}</div><div class="actions"><button class="btn primary">Trust device</button><button class="btn danger">Reject</button></div></div>
      </section>
    </main>
  `;
}

function audit() {
  return `
    <main class="page">
      ${pageHead("Audit", "查看 Event Envelope、frontier、snapshot、projection 来源、authz decision 和冲突记录。", `<button class="btn">Backfill</button><button class="btn">Verify snapshot</button><button class="btn primary">Refresh</button>`)}
      <section class="grid four">${metric("Frontier", "cx:event:review-44", "current")}${metric("Cursor", "sx:e2e:product", "saved")}${metric("State hash", "verified", "ok")}${metric("Conflicts", "1", "needs review")}</section>
      <section class="panel pad"><h2>Event log</h2>${table(["Event", "Kind", "Target", "Reducer result"], [["cx:event:01move...", "cx.card.move", "cx:card:01legal...", "accepted"], ["cx:event:01stale...", "cx.card.move", "cx:card:01security...", "cas_conflict"], ["cx:event:01msg...", "cx.message.redact", "cx:message:01...", "tombstone"]])}</section>
      <section class="grid two"><div class="panel pad"><h2>Conflict detail</h2><p>同一 `(board_id, card_id)` 出现多个 active position edge，reducer 按授权权重、HLC、Actor ID、Event ID 收敛，并记录 loser。</p></div><div class="panel pad"><h2>Authz explanation</h2><p>Card 可见、Room 不可见时，projection 返回 locked lazy link，不返回 Room title、member list 或 unread exact count。</p></div></section>
    </main>
  `;
}

function settings() {
  return `
    <main class="page">
      ${pageHead("Settings", "本地账号配置、actor-private preference、共享 Space policy 和 release readiness 分开处理。", `<button class="btn">Export diagnostics</button><button class="btn primary">Save local prefs</button>`)}
      <section class="grid two">
        <div class="panel pad">
          <h2>Server and account</h2>
          <div class="form-grid"><div class="field"><label>Server URL</label><input value="http://127.0.0.1:8787"></div><div class="field"><label>Account DID</label><input value="did:web:alice.example"></div><div class="field"><label>Device ID</label><input value="alice-windows"></div><div class="field"><label>Default landing</label><select><option>Last board</option><option>Inbox</option><option>Dashboard</option></select></div></div>
        </div>
        <div class="panel pad"><h2>Personal view preferences</h2><div class="badge-row"><span class="badge blue">compact cards</span><span class="badge">show room badge</span><span class="badge">hide archived</span><span class="badge green">local only</span></div><p>列折叠、密度、最近打开 tab 和临时 filter 写入 actor-private account data，不写 cx.view.update。</p></div>
      </section>
      <section class="panel pad"><h2>Release readiness</h2>${table(["Area", "State", "Risk", "Next action"], [["Board projection", "designed", "API integration pending", "Implement AppView query"], ["Room/Message", "designed", "old channel model remains", "Migrate chat view"], ["E2EE web", "partial", "key storage hardening", "Audit IndexedDB storage"]])}</section>
    </main>
  `;
}

function metric(label, value, hint) {
  return `<div class="panel metric"><small>${label}</small><strong>${value}</strong><span>${hint}</span></div>`;
}

function fieldTile(label, value) {
  return `<div class="field-tile"><small>${label}</small><strong>${value}</strong></div>`;
}

function activity(meta, title, text, path) {
  return `<button class="activity" data-route="${path}"><div class="activity-head"><span>${meta}</span><span>Open</span></div><h3>${title}</h3><p>${text}</p></button>`;
}

function messageBubble(initial, name, time, text) {
  return `<div class="message"><div class="message-avatar">${initial}</div><div class="bubble"><div class="bubble-head"><strong>${name}</strong><span>${time}</span></div><p>${text}</p></div></div>`;
}

function messageRow(initial, name, time, text, tags) {
  return `<div class="message"><div class="message-avatar">${initial}</div><div class="bubble ${tags.includes("tombstone") ? "redacted" : ""}"><div class="bubble-head"><strong>${name}</strong><span>${time}</span></div><p>${text}</p><div class="badge-row">${tags.map((tag) => `<span class="badge ${tag === "tombstone" ? "red" : "blue"}">${tag}</span>`).join("")}</div></div></div>`;
}

function table(headers, rows) {
  return `<div class="table"><div class="row">${headers.map((cell) => `<div class="cell">${cell}</div>`).join("")}</div>${rows.map((row) => `<div class="row">${row.map((cell) => `<div class="cell">${cell}</div>`).join("")}</div>`).join("")}</div>`;
}

render();
