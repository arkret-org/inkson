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

---

# 二期附录:checkbox → dxc Checkbox(绑定翻译)

> ⚠️ 与一期不同:checkbox 不是机械改名,需**重接状态绑定**(dxc 用三态枚举 + 回调)。dxc Checkbox 渲染 `role=checkbox` 元素(Playwright `.check()` 仍可用),但视觉从原生复选框变为样式化复选框。

## 范围
只迁移 `input { r#type: "checkbox", ... }`(含包裹在 `label { input{} " 文本" }` 里的)。**保留** `label` 包裹与文本。

## import(按字母序加入)
```rust
use crate::ui::checkbox::Checkbox;
use dioxus_primitives::checkbox::CheckboxState;
```

## 翻译模式(已编译验证的参考:views/timeline.rs 的 public-update-guard-toggle,约 1340 行,已完成,勿重复)
```rust
// 前
input {
    r#type: "checkbox",
    "data-testid": "foo-toggle",
    checked: <bool 表达式>,
    onchange: move |evt| <signal>.set(evt.value() == "true"),
}
// 后
Checkbox {
    "data-testid": "foo-toggle",
    checked: if <bool 表达式> { CheckboxState::Checked } else { CheckboxState::Unchecked },
    on_checked_change: move |state: CheckboxState| <signal>.set(bool::from(state)),
}
```

## 细则
- 把 `checked: X`(bool)改成 `checked: if X { CheckboxState::Checked } else { CheckboxState::Unchecked }`。
- 把 `onchange: |evt| ...` 改成 `on_checked_change: move |state: CheckboxState| ...`;闭包体内原来用 `evt.value() == "true"` 取得的 bool,统一改为 `bool::from(state)`(类型注解 `state: CheckboxState` 必写)。若闭包体除了 set 还有其它逻辑(如 `state_store.write()` / `status.set(...)`),先 `let enabled = bool::from(state);` 再保留其余逻辑(把原先的 bool 变量名对齐)。
- **逐字保留** `data-testid` / `disabled` / `name` / `aria-*`;删除 `r#type: "checkbox"`(dxc Checkbox 不需要)。
- 不碰 `r#type` 为 file/range/number/text 的 input;不碰 select/dialog/tabs;不碰业务逻辑的其余部分。
- 不要运行 cargo。

## 报告
返回:file、replaced(checkbox 数)、testids_preserved、uncertain(任何非标准 onchange 逻辑/拿不准点,带行号)。

---

# 二期附录:select → dxc Select(泛型 + 受控绑定)

> ⚠️ 最复杂:dxc Select 是泛型组件,渲染**自定义弹层**(非原生下拉)。受控 value 需 `use_memo` hook。视觉/交互会变,且会打烂依赖 `selectOption()` 的 e2e(由编排者单独改测试)。

## import(按字母序)
```rust
use crate::ui::select::{Select, SelectOption};
```

## 受控 value:必须在**组件顶层**加 memo
在该 select 绑定的 `Signal<String>`(如 `let mut x = use_signal(...)`)附近、组件顶层(**不能在 rsx 内、不能在循环/条件里**)加:
```rust
let x_selected = use_memo(move || Some(x()));
```

## 静态选项(已编译验证参考:views/timeline.rs incident-priority-select,~1335 行)
```rust
// 前
select {
    "data-testid": "foo-select",
    value: "{x}",
    onchange: move |evt| x.set(evt.value()),
    option { value: "a", "A" }
    option { value: "b", "B" }
}
// 后
Select::<String> {
    "data-testid": "foo-select",
    value: Some(x_selected.into()),
    on_value_change: move |v: Option<String>| { if let Some(v) = v { x.set(v); } },
    SelectOption::<String> { index: 0usize, value: "a".to_string(), text_value: "A", "A" }
    SelectOption::<String> { index: 1usize, value: "b".to_string(), text_value: "B", "B" }
}
```

## 动态选项(for 循环)
```rust
// 前
select {
    "data-testid": "foo-select",
    value: "{x}",
    onchange: move |event| x.set(event.value()),
    for (option_value, label, _) in LIST {
        option { value: "{option_value}", selected: x == option_value, "{label}" }
    }
}
// 后
Select::<String> {
    "data-testid": "foo-select",
    value: Some(x_selected.into()),
    on_value_change: move |v: Option<String>| { if let Some(v) = v { x.set(v); } },
    for (i, (option_value, label, _)) in LIST.iter().enumerate() {
        SelectOption::<String> { index: i, value: option_value.to_string(), text_value: "{label}", "{label}" }
    }
}
```
- `selected: ...` 属性删除(dxc 由 `value` 表达当前选中)。
- `index` 用 `.enumerate()` 的 i;`value` 须是 `T`(String→`.to_string()`),`text_value` 给可读文本(typeahead 用)。

## 细则
- 保留外层 `label { span{} ... }` 包裹与文本(若有)。
- **逐字保留** `data-testid` / aria-*(放在 `Select` 上,会透传到外层 div)。
- 选项的 value 都用 `String` 泛型(`Select::<String>` / `SelectOption::<String>`),与原 `value: "..."` 字符串一致。
- 若 select 的 value 不是 String(少见),用对应类型;拿不准就标 uncertain。
- **不要运行 cargo**。每个迁移的 select 都要在组件顶层加对应 memo。

## 报告
返回:file、replaced(select 数)、added_memos(新增的 use_memo 变量名)、testids_preserved、uncertain(动态/非String/拿不准点,带行号)。

---

# 二期附录:独立手写模态 → dxc Dialog(结构性,e2e 敏感)

> ⚠️ 仅迁移**字面写了 `role: "dialog"` 的手写模态**(`div.modal-overlay > div.modal[role=dialog]` 结构)。**不要碰** `DismissiblePopup` 组件及其调用方(它有刻意的防误关逻辑,保留)。e2e 依赖部分 modal 的 testid 与 `role=dialog` 名称、`toHaveCount(0)`,务必按下述保形。

## import(按字母序)
```rust
use crate::ui::dialog::Dialog;
```

## 已编译验证参考:components/create_circle_modal.rs(Dialog{open,on_open_change,...} 包裹 .modal 内容)

## 铁律(保 e2e)
1. **保留外层条件渲染** `if <signal> { ... }`(若有):关闭时整个 Dialog 不渲染 → `toHaveCount(0)` 成立。若该模态是「父组件条件挂载的独立组件」(无内部 if),则 `open: true`。
2. **把模态原来的 data-testid 都保留**;尤其把 **overlay(外层)那个 testid 放到 `Dialog` 上**(e2e 常用它做 toBeVisible/toHaveCount)。内层 `.modal` 的 surface testid 保留在内层 div 上。
3. 保留 `aria-label` / `aria-labelledby`(放到 `Dialog` 上)——`role=dialog` 的可访问名称靠它,e2e `getByRole("dialog",{name})` 依赖。
4. **删除**手写的 `role: "dialog"`、`"aria-modal": "true"`(dxc DialogContent 自动设)。
5. 不改任何业务逻辑、关闭按钮、内部 Button/Input/Select。

## 转换模式
```rust
// 前(role 在内层 surface 的情形,如 mls_backup_prompt)
if needs_x() {
    div { class: "modal-overlay foo-overlay", "data-testid": "foo-modal",
        div { class: "modal event ...", "data-testid": "foo-banner",
            role: "dialog", "aria-modal": "true",
            "aria-labelledby": "foo-title", "aria-label": "...",
            // ... head/body/foot,含关闭按钮 onclick: x.set(false)
        }
    }
}
// 后
if needs_x() {
    Dialog {
        open: true,
        on_open_change: move |open: bool| { if !open { /* 原关闭动作,如 x.set(false) */ } },
        "data-testid": "foo-modal",          // overlay testid 提到 Dialog(e2e 用)
        "aria-labelledby": "foo-title",
        "aria-label": "...",
        div { class: "modal event ...", "data-testid": "foo-banner",
            // ... head/body/foot 原样保留(含关闭按钮)
        }
    }
}
```
- `on_open_change` 的关闭动作 = 该模态原本「点 backdrop / 关闭按钮」所做的事(set 信号 false / 调 on_cancel 等);若原本无 backdrop 关闭,则写最贴近的关闭动作。
- 若 role/aria/testid 原本在**外层 overlay**(如 create_circle),则把它们提到 Dialog,内层 `.modal` 保留 class+surface testid。

## 不确定就标注
若某模态结构特殊(多层、非 modal-overlay 结构、关闭逻辑复杂、role 位置不典型),**跳过并在 uncertain 详述(带行号)**,留给编排者手工处理。**不要运行 cargo**。

## 报告
返回:file、replaced(模态数)、testids 清单(放到 Dialog 的 / 保留在内层的)、close_action(每个模态的关闭动作)、uncertain(跳过/拿不准点带行号)。
