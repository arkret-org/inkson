# 统一侧栏模板 / Canonical Sidebar Template

> 所有桌面端带 chrome 的页面共用同一份侧栏。先改这里，再同步每页副本。

## 1. 信息架构

```text
┌──────────────────────────────────┐
│ ⌘  Contrix                       │  ← product brand
│    v1 client                     │
│                                  │
│ ◇  Organization                  │  ← current organization principal
│    Acme Inc.                     │
│    did:webvh:acme.example.com    │
│ ◌  Principal Server       primary│  ← delegated service boundary
│    server.acme.example.com       │
│    did:web:server.acme.example…  │
│                                  │
│  PERSONAL                        │
│   ⌂ 工作台                       │
│   □ 收件箱                  3    │
│   ⌕ 发现                         │
│   ⚙ 设置                         │
│                                  │
│  ACME 背书 SPACES          +     │
│   ▣ Engineering             12   │
│      ├ Active sprint             │  ← Place, no independent boundary
│      └ Q4 retro           child  │  ← child Space, independent boundary
│   ▣ Design                       │
│   ▣ Product roadmap              │
│                                  │
│  受控跨组织                      │
│   ◎ Acme × Beta partnership HA closed
│                                  │
│  PERSONAL SPACES           +     │
│   □ 我的笔记                     │
│   □ 草稿箱                       │
│                                  │
│ ●  Alice Wang              ⚙     │
│    @alice.example.com            │
└──────────────────────────────────┘
```

## 2. 协议语义

- `Contrix` 是产品 / 协议品牌，固定显示在侧栏左上。
- `Acme Inc.` 是当前 Organization Principal，不是 Principal Server。
- `Principal Server` 是被当前 principal 或 organization DID 委托的服务边界。它承载 events / sync / discovery 等 API，但不是身份本身，也不能替 actor 伪造 Event。
- `Acme 背书 Spaces` 表示 `owning_organizations`、组织目录或组织背书关系，不表示 Space 被 Principal Server 强包含。
- Space hierarchy 只用于导航和可发现性。child Space 拥有独立 membership / policy / history / E2EE epoch；Place 只是 Space 内结构容器。
- `受控跨组织` 用于 Controlled Collaboration Space：通常 `security_class=high_assurance`，`federation_policy` 为 `closed` / `restricted` / `quarantine`，并通过 allowlist、invite、claim 和审计控制外部组织访问。
- 个人 Space 用 `Space.fields.purpose=personal`、schema 或 labels 表达，不使用 `kind=personal`。

## 3. 当前 HTML 模板

```html
<aside class="sidebar">
  <div class="sidebar-header">
    <a class="brand" href="home.html" style="text-decoration:none; color:inherit;">
      <span class="logo">⌘</span>
      <span class="product-meta"><span class="product-name">Contrix</span><span class="product-sub">v1 client</span></span>
    </a>
  </div>

  <div class="sidebar-context" aria-label="Current workspace context">
    <a class="context-line" href="directory.html?org=did:webvh:acme.example.com"><span class="icon">◇</span><span class="grow truncate"><span class="k">Organization</span><span class="v">Acme Inc.</span><span class="id mono">did:webvh:acme.example.com</span></span><span class="mini">▾</span></a>
    <div class="context-sep"></div>
    <a class="context-line" href="settings.html?tab=services"><span class="icon">◌</span><span class="grow truncate"><span class="k">Principal Server</span><span class="v">server.acme.example.com</span><span class="id mono">did:web:server.acme.example.com</span></span><span class="pill muted xs">primary</span></a>
  </div>

  <div class="sidebar-section" style="padding-bottom:0;"><a class="nav-item" href="directory.html"><span class="icon">⌕</span><span class="i18n"><span class="zh">搜索 / 发现</span><span class="en">Search / Directory</span></span><span class="kbd-tag" style="margin-left:auto;">⌘K</span></a></div>

  <div class="sidebar-section">
    <h4 class="i18n"><span class="zh">个人</span><span class="en">Personal</span></h4>
    <a class="nav-item" href="home.html"><span class="icon">⌂</span><span class="i18n"><span class="zh">工作台</span><span class="en">Home</span></span></a>
    <a class="nav-item" href="inbox.html"><span class="icon">□</span><span class="i18n"><span class="zh">收件箱</span><span class="en">Inbox</span></span><span class="badge" style="margin-left:auto;">3</span></a>
    <a class="nav-item" href="directory.html"><span class="icon">⌕</span><span class="i18n"><span class="zh">发现</span><span class="en">Directory</span></span></a>
    <a class="nav-item" href="settings.html"><span class="icon">⚙</span><span class="i18n"><span class="zh">设置</span><span class="en">Settings</span></span></a>
  </div>

  <div class="sidebar-section">
    <h4><span class="i18n"><span class="zh">Acme 背书 Spaces</span><span class="en">Acme-backed Spaces</span></span><a class="add" href="space-admin.html?new=1" title="New Space">+</a></h4>
    <a class="nav-item" href="space.html?id=eng"><span class="icon">▣</span><span class="grow truncate">Engineering</span><span class="pill muted xs">12</span></a>
    <a class="nav-item" href="board.html?id=eng-sprint" style="padding-left:30px; color:var(--text-2);"><span class="icon">├</span><span class="grow truncate">Active sprint</span></a>
    <a class="nav-item" href="discussion.html?id=q4-retro" style="padding-left:30px; color:var(--text-2);"><span class="icon">└</span><span class="grow truncate">Q4 retro</span><span class="pill muted xs" title="child Space · independent boundary">child</span></a>
  </div>

  <div class="sidebar-section"><h4 class="i18n"><span class="zh">受控跨组织</span><span class="en">Controlled cross-org</span></h4><a class="nav-item" href="space.html?id=acme-beta"><span class="icon">◎</span><span class="grow truncate">Acme × Beta partnership</span><span class="pill warning xs">HA</span><span class="pill muted xs">closed</span></a></div>

  <div class="sidebar-section"><h4><span class="i18n"><span class="zh">个人 Spaces</span><span class="en">Personal Spaces</span></span><a class="add" href="space-admin.html?new=1&amp;purpose=personal" title="New personal Space">+</a></h4><a class="nav-item" href="space.html?id=notes"><span class="icon">□</span><span class="grow truncate">我的笔记</span></a><a class="nav-item dim" href="space.html?id=drafts"><span class="icon">□</span><span class="grow truncate">草稿箱</span></a></div>

  <a class="sidebar-footer" href="settings.html" style="text-decoration:none; color:inherit;"><span class="avatar">A</span><span class="grow"><span class="who">Alice Wang</span><span class="handle">@alice.example.com</span></span><span class="dot-online" title="online" style="margin-right:4px;"></span><span class="btn icon sm ghost" onclick="event.preventDefault(); location.href='settings.html?tab=account';">⚙</span></a>
</aside>
```
