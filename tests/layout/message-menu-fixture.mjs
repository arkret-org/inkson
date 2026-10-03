import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const metadata = JSON.parse(execFileSync("cargo", ["metadata", "--format-version", "1", "--locked", "--offline"], { cwd: root, maxBuffer: 20 * 1024 * 1024 }));
const yoface = dirname(metadata.packages.find((pkg) => pkg.name === "yoface").manifest_path);
const read = (file) => readFileSync(file, "utf8");
const app = read(resolve(root, "src/app/mod.rs"));
const css = [
  read(resolve(yoface, "src/tokens.css")),
  read(resolve(yoface, "src/ui/button/style.css")),
  ...[...app.matchAll(/include_str!\("\.\.\/(styles\/[^\"]+)"\)/g)]
    .map((match) => read(resolve(root, "src", match[1]))),
].join("\n");
const mount = read(resolve(root, "src/views/chat/message_menu.js"));

// This DOM fixture exercises production styles and positioning, without
// sending protocol operations or requiring an authenticated chat session.
export function messageMenuFixture({ bottom = false, long = false, badges = false, compact = false } = {}) {
  const items = ["回复", "回应", "编辑", "共享钉选", "仅为我保存", "举报", "撤回"];
  return `<!doctype html><html data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><style>${css}</style>
  <style>
  #fixture { position:fixed; inset:24px; display:flex; flex-direction:column; overflow:hidden; transform:translateZ(0); }
  #fixture .discussion-chat-feed { height:${compact ? "210px" : "100%"}; flex:none; overflow:auto; display:flex; flex-direction:column; gap:16px; padding:12px; }
  #fixture .fixture-spacer { flex:none; height:${bottom ? "440px" : "0"}; }
  #fixture .discussion-message { flex:none; }
  </style></head><body><main id="fixture"><div class="discussion-chat-feed" data-testid="message-list">
  <div class="fixture-spacer"></div>
  <div class="discussion-message${badges ? " is-pinned" : ""}">
    <div class="msg-body">
      ${badges ? '<button class="dx-button message-pin-indicator" data-size="default" data-style="secondary">P</button><span class="message-private-saved-indicator">✓</span>' : ""}
      <div class="msg-head"><span class="name">aa</span><span class="badge member-badge member-badge-agent">🤖 智能体</span><span class="agent-owner-label">agent of alice:local.host</span><time>21:33</time></div>
      <div class="msg-content">你好！有什么需要帮忙的吗？${long ? "<br>这是一条很长的消息。".repeat(30) : ""}</div>
      <div class="chat-message-actions"><button type="button" class="dx-button chat-message-menu-button" data-size="default" data-style="secondary" aria-haspopup="menu" aria-expanded="false" aria-controls="fixture-menu" aria-label="消息操作"><svg class="ui-icon" viewBox="0 0 24 24"><circle cx="5" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="19" cy="12" r="2"/></svg></button></div>
    </div>
  </div>
  <div style="height:900px; flex:none"></div>
  </div></main><template id="menu-template"><div class="message-context-menu-scrim" popover="manual"></div><div id="fixture-menu" class="message-context-menu" popover="manual" role="menu" aria-label="消息操作">${items.map((label, i) => `<button type="button" role="menuitem" data-size="default" data-style="secondary" class="dx-button message-context-menu-item${i > 4 ? " danger" : ""}"${i === 2 ? " disabled" : ""}>${label}</button>`).join("")}</div></template>
  <script>${mount}
  const trigger = document.querySelector('.chat-message-menu-button');
  const row = trigger.closest('.discussion-message');
  function closeMenu() {
    row.querySelector('.message-context-menu')?.remove();
    row.querySelector('.message-context-menu-scrim')?.remove();
    trigger.setAttribute('aria-expanded', 'false');
    trigger.parentElement.classList.remove('is-open');
  }
  // Dioxus delegates key events outside the menu's native DOM listener.
  row.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenu(); });
  trigger.onclick = () => {
    if (row.querySelector('.message-context-menu')) return closeMenu();
    row.append(document.getElementById('menu-template').content.cloneNode(true));
    trigger.setAttribute('aria-expanded', 'true');
    trigger.parentElement.classList.add('is-open');
    row.querySelector('.message-context-menu-scrim').onclick = closeMenu;
    mountMessageMenu('fixture-menu');
  };
  </script></body></html>`;
}
