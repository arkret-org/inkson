# yougen → dioxus-components 迁移规范(表单原语 Pass)

本文是把 yougen 视图从裸 HTML 原语迁移到 `src/ui/`(dioxus-components / dioxus-primitives 样式化组件)的**精确执行手册**。组件已主题化对齐 yougen 设计 token,观感保持不变。

## 本 Pass 范围(只做这些)

把视图 rsx 里的裸元素替换为 `src/ui` 组件:

| 裸元素 | 替换为 | import |
|---|---|---|
| `button { … }` | `Button { variant, size, … }` | `crate::ui::button::{Button, ButtonVariant, ButtonSize}` |
| `input { … }` | `Input { … }` | `crate::ui::input::Input` |
| `textarea { … }` | `Textarea { … }` | `crate::ui::textarea::Textarea` |
| `label { … }`(表单标签) | `Label { html_for: "…", … }` | `crate::ui::label::Label` |

**不在本 Pass**:`select`(泛型 API 不同,单独处理)、modal/dialog、tabs、switch/checkbox、卡片容器。这些保持原样,留待后续 Pass。

## 绝对铁律

1. **逐字保留**每个 `data-testid` / `aria-label` / `aria-*` / `role` / `data-*` / `id` / `name` 属性,取值一字不改。e2e 选择器依赖它们。
2. **不改任何业务逻辑**:事件处理器闭包体、Signal 读写、`spawn`/`async`、条件渲染分支,全部原样。只换"表现层标签"。
3. **不增删功能**,不动 import 以外的非 rsx 代码。
4. 不留注释掉的旧代码 / dead code。

## 替换细则

### button → Button
- 开标签 `button {` → `Button {`。**闭合 `}` 不变**(组件与元素都用 `}`)。
- 视觉变体类映射到 `variant`,并**从 class 字符串中删除该变体 token**(其余 class token 原样保留,它们是布局/语义类):
  - `primary` → `variant: ButtonVariant::Primary`
  - `secondary` → `ButtonVariant::Secondary`
  - `ghost` → `ButtonVariant::Ghost`
  - `danger` / `destructive` → `ButtonVariant::Destructive`
  - `outline` → `ButtonVariant::Outline`
  - `link` → `ButtonVariant::Link`
  - **无视觉变体类**(裸 `button` 或只有布局类)→ `ButtonVariant::Secondary`(中性默认)
  - 特殊:`success` 等 dxc 无对应 → 保持 `variant` 默认并在 class 里**保留** `success`(留旧 CSS,后续处理),报告中标注。
- 尺寸类映射到 `size`,并从 class 删除该 token:`sm`→`ButtonSize::Sm`,`xs`→`ButtonSize::Xs`,`lg`→`ButtonSize::Lg`,`icon`→`ButtonSize::Icon`。无则不写 `size`。
- `onclick`/`onmousedown`/`onmouseup`/`onkeydown` 是**具名 prop**,原样保留。
- `disabled` / `title` / `class` / `data-testid` 等作为属性原样保留(组件 `extends=button` 透传)。
- 若删变体/尺寸 token 后 class 变空,则整条 `class:` 删除。

示例:
```rust
// 前
button { class: "primary sm", "data-testid": "save", disabled: busy(), onclick: move |_| save(), "保存" }
// 后
Button { variant: ButtonVariant::Primary, size: ButtonSize::Sm,
    class: "", "data-testid": "save", disabled: busy(), onclick: move |_| save(), "保存" }
// class 变空则删掉 class: 行
```

### input → Input
- `input {` → `Input {`,闭合 `}` 不变。
- `value` / `disabled` / `placeholder` / `type` / `data-testid` / `aria-label` / `id` / `name` 等作为属性原样保留。
- 事件是**具名 prop**:`oninput` / `onchange` / `onfocus` / `onblur` / `onkeydown` 等原样保留。
- **GOTCHA(必做)**:`oninput`/`onchange` 等闭包参数**必须显式标注类型** `move |event: FormEvent| { … }`(经 `Option<EventHandler<FormEvent>>` 包装后类型推断失效)。`onkeydown` 标 `KeyboardEvent`,`onfocus`/`onblur` 标 `FocusEvent`。
- input 无 children,保持自闭合(`}` 收尾)。

### textarea → Textarea
- 同 Input。`oninput` 等闭包同样需 `FormEvent` 标注。文本内容若以 children 形式存在则保留。

### label → Label
- 仅当是表单字段标签时迁移。`Label { html_for: "<目标input的id>", … }` —— `html_for` **必填**。
- 若原 label 关联的 input 没有 `id`,给该 input 补一个稳定 `id`(如 `"<testid>-input"`),并让 label `html_for` 指向它。`id` 不影响 testid 选择器。
- 非表单语境的 `label` 文本(如纯展示)可不迁移。

## import 处理
在文件已有 `use` 区按字母序加入所需 import。只加实际用到的(用了 Button 才 import ButtonVariant/ButtonSize)。

## 不要做编译验证
**不要运行 cargo**(并行会抢 build 锁)。做精确编辑即可,统一编译/修复由编排者串行完成。

## 返回报告(结构化)
完成后返回:
- `file`: 视图文件路径
- `replaced`: { button: N, input: N, textarea: N, label: N }
- `dropped_classes`: 从 class 中删除的视觉/尺寸 token 列表(用于后续 CSS 清理判断,如 `["primary","sm","ghost"]`)
- `added_ids`: 为 label 关联而新增的 input id 列表
- `uncertain`: 任何拿不准/未迁移的点(如 success 变体、动态 class 字符串、非标准结构),带行号
- `testids_preserved`: true/false(自检:迁移前后 data-testid 集合是否完全一致)
