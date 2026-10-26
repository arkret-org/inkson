//! Lower the renderer's sanitized HTML subset to portable semantic widgets.
use std::collections::BTreeMap;
use std::rc::Rc;

use glory::prelude::*;
use glory::render::{Action, EventKind, NodeId, SemanticId, Semantics};

use crate::presentation::View;

#[derive(Clone, Default)]
struct Node {
    tag: String,
    attributes: BTreeMap<String, String>,
    text: String,
    children: Vec<Node>,
}

fn parse(value: &str) -> Node {
    let mut stack = vec![Node::default()];
    let mut rest = value;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('<') {
            let Some(end) = after.find('>') else { break };
            let token = &after[..end];
            rest = &after[end + 1..];
            if token.starts_with('/') {
                if stack.len() > 1 {
                    let node = stack.pop().unwrap_or_default();
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    }
                }
                continue;
            }
            if token.starts_with('!') {
                continue;
            }
            let tag = token
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_ascii_lowercase();
            let mut attributes = BTreeMap::new();
            for name in ["href", "title", "class", "id", "type"] {
                if let Some((_, tail)) = token.split_once(&format!("{name}=\""))
                    && let Some((value, _)) = tail.split_once('"')
                {
                    attributes.insert(name.into(), decode(value));
                }
            }
            if token.split_whitespace().any(|attribute| {
                attribute.trim_end_matches('/') == "checked" || attribute.starts_with("checked=")
            }) {
                attributes.insert("checked".into(), String::new());
            }
            let node = Node {
                tag: tag.clone(),
                attributes,
                ..Default::default()
            };
            if matches!(tag.as_str(), "hr" | "br" | "input" | "img") || token.ends_with('/') {
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                }
            } else if stack.len() < 128 {
                stack.push(node);
            }
        } else {
            let end = rest.find('<').unwrap_or(rest.len());
            let text = decode(&rest[..end]);
            if let Some(parent) = stack.last_mut() {
                parent.children.push(Node {
                    text,
                    ..Default::default()
                });
            }
            rest = &rest[end..];
        }
    }
    while stack.len() > 1 {
        let node = stack.pop().unwrap_or_default();
        if let Some(parent) = stack.last_mut() {
            parent.children.push(node);
        }
    }
    stack.pop().unwrap_or_default()
}

#[derive(Clone)]
struct AnchorTarget {
    id: SemanticId,
    node: Cage<Option<NodeId>>,
}
type Anchors = BTreeMap<String, AnchorTarget>;

fn collect_anchors(node: &Node, scope: &Scope, anchors: &mut Anchors) -> glory::ui::Result {
    if let Some(id) = node.attributes.get("id") {
        let index = anchors.len();
        if let std::collections::btree_map::Entry::Vacant(entry) = anchors.entry(id.clone()) {
            let semantic = SemanticId::new(format!(
                "content-{}-{}-{}-anchor-{index}",
                scope.id().runtime().value(),
                scope.id().slot(),
                scope.id().generation()
            ))?;
            entry.insert(AnchorTarget {
                id: semantic,
                node: scope.cage(None),
            });
        }
    }
    for child in &node.children {
        collect_anchors(child, scope, anchors)?;
    }
    Ok(())
}

pub(super) fn html(value: &str) -> View {
    let root = parse(value);
    Box::new(widget(move |scope| {
        let mut anchors = Anchors::new();
        collect_anchors(&root, scope, &mut anchors)?;
        lower(root.clone(), scope, Rc::new(anchors)).build(scope)
    }))
}

fn flattened(node: &Node) -> String {
    if node.tag == "br" {
        return "\n".into();
    }
    let mut value = node.text.clone();
    for child in &node.children {
        value.push_str(&flattened(child));
    }
    value
}

fn lower(node: Node, scope: &Scope, anchors: Rc<Anchors>) -> View {
    let class = format!(
        "content-html-{} {}",
        node.tag,
        node.attributes
            .get("class")
            .map(String::as_str)
            .unwrap_or_default()
    );
    let target = node
        .attributes
        .get("id")
        .and_then(|id| anchors.get(id))
        .cloned();
    let part = match node.tag.as_str() {
        "ul" => Some(glory::render::DocumentPart::UnorderedList),
        "ol" => Some(glory::render::DocumentPart::OrderedList),
        "li" => Some(glory::render::DocumentPart::ListItem),
        "blockquote" => Some(glory::render::DocumentPart::Blockquote),
        "table" => Some(glory::render::DocumentPart::Table),
        "thead" => Some(glory::render::DocumentPart::TableHead),
        "tbody" => Some(glory::render::DocumentPart::TableBody),
        "tr" => Some(glory::render::DocumentPart::TableRow),
        "th" => Some(glory::render::DocumentPart::ColumnHeader),
        "td" => Some(glory::render::DocumentPart::TableCell),
        _ => None,
    };
    macro_rules! finish {
        ($builder:expr) => {{
            let mut builder = $builder.class(class.clone());
            if let Some(target) = &target {
                builder = builder
                    .node_ref(target.node)
                    .semantics(Some(Box::new(Semantics {
                        id: Some(target.id.clone()),
                        document_part: part,
                        ..Default::default()
                    })));
            }
            Box::new(builder) as View
        }};
    }
    if node.tag.is_empty() && node.children.is_empty() {
        return finish!(text().content(node.text));
    }
    if let Some(level) = node
        .tag
        .strip_prefix('h')
        .and_then(|level| level.parse::<u8>().ok())
        .filter(|level| (1..=6).contains(level))
    {
        return finish!(
            text()
                .kind(TextKind::Heading(level))
                .content(flattened(&node))
        );
    }
    if node.tag == "a" {
        let href = super::renderer::sanitize_link_url(
            node.attributes
                .get("href")
                .map(String::as_str)
                .unwrap_or("#"),
        )
        .to_string();
        let fragment = href.strip_prefix('#');
        let destination = fragment.and_then(|id| anchors.get(id)).cloned();
        let local = fragment.is_some();
        let metadata = Semantics {
            id: target.as_ref().map(|target| target.id.clone()),
            link_open: Some(if local || !cfg!(target_arch = "wasm32") {
                LinkOpen::Current
            } else {
                LinkOpen::NewContext
            }),
            link_request: local || !cfg!(target_arch = "wasm32"),
            ..Default::default()
        };
        let mut anchor = link()
            .class(format!("sapid-anchor {class}"))
            .target(href.clone())
            .label(flattened(&node))
            .semantics(Some(Box::new(metadata)));
        if let Some(target) = target {
            anchor = anchor.node_ref(target.node);
        }
        if local {
            let owner = scope.downgrade();
            anchor = anchor.on(EventKind::Activate, move |_| {
                let Some(scope) = owner.upgrade() else { return };
                if let Some(target) = &destination
                    && let Some(node) = target.node.get_untracked()
                    && let Err(error) = scope.action(Action::ScrollIntoView(node))
                {
                    scope.report_error(error);
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        if !local {
            anchor = anchor.on(
                EventKind::Activate,
                super::external_link::activation(scope, href),
            );
        }
        return Box::new(anchor);
    }
    if node.tag == "input"
        && node
            .attributes
            .get("type")
            .is_some_and(|value| value == "checkbox")
    {
        return finish!(
            check()
                .checked(node.attributes.contains_key("checked"))
                .enabled(false)
        );
    }
    if node.tag == "br" {
        return finish!(text().content("\n"));
    }
    if node.tag == "hr" {
        return finish!(view().role(Role::Separator));
    }
    let structural = matches!(
        node.tag.as_str(),
        "ul" | "ol" | "table" | "thead" | "tbody" | "tr"
    );
    let children = node
        .children
        .into_iter()
        .filter(|child| !structural || !child.tag.is_empty() || !child.text.trim().is_empty())
        .map(|node| lower(node, scope, anchors.clone()))
        .collect::<Vec<_>>();
    let mut root = view().fill(children);
    if let Some(part) = part {
        root = root.document_part(part);
    }
    finish!(root)
}

fn decode(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        out.push_str(&rest[..index]);
        rest = &rest[index..];
        let Some(end) = rest.find(';').filter(|end| *end <= 16) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let scalar = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" | "#39" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ => entity
                .strip_prefix("#x")
                .and_then(|v| u32::from_str_radix(v, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|v| v.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(value) = scalar {
            out.push(value);
        } else {
            out.push_str(&rest[..=end]);
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn entity_decoding_does_not_interpret_markup() {
        assert_eq!(decode("&lt;script&gt;&amp; &#x1f600;"), "<script>& 😀");
        let app = glory::ui::App::memory();
        app.mount(html(
            "<p><strong>safe</strong> &lt;script&gt;<a href=\"javascript:alert(1)\">link</a></p>",
        ))
        .unwrap();
    }
    fn nodes(app: &App) -> Vec<NodeId> {
        let tree = app.tree();
        let mut pending = tree.roots().to_vec();
        let mut nodes = Vec::new();
        while let Some(id) = pending.pop() {
            nodes.push(id);
            pending.extend(tree.node(id).unwrap().children.iter().copied());
        }
        nodes
    }
    #[test]
    fn sanitized_markdown_keeps_readonly_task_state_and_footnote_semantics() {
        use glory::render::Props;
        let source = "# Heading\n\n- [x] Done\n- [ ] Pending\n\nText[^1]\n\n[^1]: Note\n\n[external](https://example.com)";
        let app = App::memory();
        app.mount(html(&super::super::renderer::markdown_to_safe_html(source)))
            .unwrap();
        let tree = app.tree();
        let mut checks = Vec::new();
        let mut local = 0;
        let mut external = 0;
        let mut definition = false;
        for id in nodes(&app) {
            let descriptor = tree.node(id).unwrap().descriptor.view();
            if let Props::Check(check) = descriptor.props {
                checks.push((check.checked, check.enabled));
            }
            if descriptor
                .classes
                .iter()
                .any(|class| class == "footnote-definition")
            {
                definition = true;
                assert!(descriptor.semantics.as_ref().unwrap().id.is_some());
            }
            if let Props::Link(link) = descriptor.props {
                let semantics = descriptor.semantics.as_ref().unwrap();
                if link.target.starts_with('#') {
                    local += 1;
                    assert_eq!(semantics.link_open, Some(LinkOpen::Current));
                    assert!(semantics.link_request);
                }
                if link.target == "https://example.com" {
                    external += 1;
                    assert_eq!(
                        semantics.link_open,
                        Some(if cfg!(target_arch = "wasm32") {
                            LinkOpen::NewContext
                        } else {
                            LinkOpen::Current
                        })
                    );
                    assert_eq!(semantics.link_request, !cfg!(target_arch = "wasm32"));
                }
            }
        }
        checks.sort();
        assert_eq!(checks, vec![(false, false), (true, false)]);
        assert!(definition);
        assert!(local > 0);
        assert_eq!(external, 1);
    }

    struct ScrollHost {
        memory: glory::render::memory::Memory,
        actions: Rc<std::cell::RefCell<Vec<Action>>>,
    }
    impl glory::render::Render for ScrollHost {
        fn capabilities(&self) -> glory::render::Capabilities {
            glory::render::Capabilities {
                scroll: true,
                ..Default::default()
            }
        }
        fn apply(
            &mut self,
            changes: &[glory::render::Mutation],
        ) -> std::result::Result<glory::render::Receipt, glory::render::Error> {
            self.memory.apply(changes)
        }
        fn request(
            &mut self,
            query: glory::render::Query,
            token: glory::render::QueryToken,
        ) -> std::result::Result<(), glory::render::Error> {
            self.memory.request(query, token)
        }
        fn drain(&mut self, inputs: &mut Vec<glory::render::Input>) {
            self.memory.drain(inputs);
        }
        fn action(&mut self, action: Action) -> std::result::Result<(), glory::render::Error> {
            self.actions.borrow_mut().push(action);
            Ok(())
        }
    }
    #[test]
    fn fragment_activation_reveals_only_its_owner_and_retirement_disables_it() {
        use glory::render::Props;
        let actions = Rc::new(std::cell::RefCell::new(Vec::new()));
        let captured = actions.clone();
        let app = App::new(move |id| ScrollHost {
            memory: glory::render::memory::Memory::new(id),
            actions: captured,
        });
        let fragment = "<a href=\"#release\" class=\"footnote-reference\">Jump</a><h2 id=\"release\" class=\"release-heading\">Release</h2>";
        app.mount(html(fragment)).unwrap();
        let identify = |app: &App| {
            let all = nodes(app);
            let tree = app.tree();
            let link = all
                .iter()
                .copied()
                .find(|id| {
                    matches!(
                        tree.node(*id).unwrap().descriptor.view().props,
                        Props::Link(_)
                    )
                })
                .unwrap();
            let target = all
                .iter()
                .copied()
                .find(|id| {
                    tree.node(*id)
                        .unwrap()
                        .descriptor
                        .view()
                        .classes
                        .iter()
                        .any(|class| class == "release-heading")
                })
                .unwrap();
            let semantic = tree
                .node(target)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .id
                .clone()
                .unwrap();
            (link, target, semantic)
        };
        let (first_link, first_target, first_id) = identify(&app);
        app.dispatch(first_link, Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(
            *actions.borrow(),
            vec![Action::ScrollIntoView(first_target)]
        );
        app.mount(html(fragment)).unwrap();
        let (second_link, second_target, second_id) = identify(&app);
        assert_ne!(first_id, second_id);
        app.dispatch(first_link, Event::Activate).unwrap();
        app.dispatch(second_link, Event::Activate).unwrap();
        app.flush().unwrap();
        assert_eq!(
            *actions.borrow(),
            vec![
                Action::ScrollIntoView(first_target),
                Action::ScrollIntoView(first_target),
                Action::ScrollIntoView(second_target)
            ]
        );
        app.clear().unwrap();
        assert!(!app.dispatch(first_link, Event::Activate).unwrap());
        app.flush().unwrap();
        assert_eq!(actions.borrow().len(), 3);
    }
}
