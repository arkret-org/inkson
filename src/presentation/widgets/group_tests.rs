use std::collections::BTreeMap;

use glory::render::{NodeId, Props};

use super::*;

fn visible_children(tree: &glory::render::memory::Memory, parent: NodeId) -> Vec<NodeId> {
    fn append(tree: &glory::render::memory::Memory, node: NodeId, result: &mut Vec<NodeId>) {
        let item = tree.node(node).unwrap();
        if matches!(item.descriptor.view().props, Props::Group) {
            for child in &item.children {
                append(tree, *child, result);
            }
        } else {
            result.push(node);
        }
    }
    let mut result = Vec::new();
    for child in &tree.node(parent).unwrap().children {
        append(tree, *child, &mut result);
    }
    result
}

fn exercise(app: glory::App) {
    let parent = app.scope().cage(None);
    let before = app.scope().cage(None);
    let after = app.scope().cage(None);
    let phase = app.scope().cage(0_u8);
    let locale = app.scope().cage(false);
    let source = app.scope().bond(move || (phase.get(), locale.get()));
    let previous = Rc::new(RefCell::new(None::<Cage<String>>));
    let child_value = previous.clone();
    let retired = Rc::new(Cell::new(0));
    let cleanups = retired.clone();
    app.mount(
        view().node_ref(parent).fill((
            input()
                .name("Before")
                .value("unsaved before")
                .node_ref(before),
            reactive(source, move |scope, (phase, locale)| {
                let value = scope.cage(if locale { "中文" } else { "English" }.to_owned());
                *child_value.borrow_mut() = Some(value);
                let cleanups = cleanups.clone();
                scope
                    .on_cleanup(move || cleanups.set(cleanups.get() + 1))
                    .unwrap();
                match phase {
                    0 => empty(),
                    1 => Box::new(input().name("Middle one").value(value)),
                    _ => Box::new(group().fill((
                        input().name("Middle one").value(value),
                        input().name("Middle two").value("second"),
                    ))),
                }
            }),
            input().name("After").value("unsaved after").node_ref(after),
        )),
    )
    .unwrap();
    let parent = parent.get_untracked().unwrap();
    let before = before.get_untracked().unwrap();
    let after = after.get_untracked().unwrap();
    let boundary = app.tree().node(parent).unwrap().children[1];
    assert!(matches!(
        app.tree().node(boundary).unwrap().descriptor.view().props,
        Props::Group
    ));
    let mut counts = BTreeMap::new();
    for iteration in 1..=60 {
        let next = (iteration % 3) as u8;
        let language = iteration % 2 == 0;
        let old = previous.borrow().unwrap();
        app.scope()
            .batch(|| {
                phase.revise(|phase| *phase = next);
                locale.revise(|locale| *locale = language);
            })
            .unwrap();
        app.flush().unwrap();
        assert!(!old.is_alive(), "replaced child's state must retire");
        assert_eq!(
            app.tree().node(parent).unwrap().children,
            vec![before, boundary, after]
        );
        let tree = app.tree();
        let children = visible_children(&tree, parent);
        assert_eq!(children.first(), Some(&before));
        assert_eq!(children.last(), Some(&after));
        assert_eq!(children.len(), usize::from(next) + 2);
        if next != 0 {
            let Props::Input(middle) = tree.node(children[1]).unwrap().descriptor.view().props
            else {
                panic!("middle is input")
            };
            assert_eq!(middle.value, if language { "中文" } else { "English" });
        }
        let Props::Input(before_props) = tree.node(before).unwrap().descriptor.view().props else {
            panic!("before is input")
        };
        assert_eq!(before_props.value, "unsaved before");
        let Props::Input(after_props) = tree.node(after).unwrap().descriptor.view().props else {
            panic!("after is input")
        };
        assert_eq!(after_props.value, "unsaved after");
        drop(tree);
        let count = (
            app.stats().nodes,
            app.stats().owners,
            app.graph_stats().nodes,
        );
        if let Some(expected) = counts.insert((next, language), count) {
            assert_eq!(
                count, expected,
                "repeating a phase must not grow live owners or graph"
            );
        }
    }
    assert_eq!(retired.get(), 60);
    let last = previous.borrow().unwrap();
    app.clear().unwrap();
    assert!(!last.is_alive());
    assert_eq!(retired.get(), 61);
    assert_eq!(app.stats().nodes, 0);
}

#[test]
fn reactive_groups_preserve_sibling_order_empty_positions_locale_and_bounded_owners() {
    exercise(glory::App::memory());
}

#[cfg(all(not(target_arch = "wasm32"), feature = "desktop"))]
#[test]
fn actual_blitz_accepts_repeated_group_replacement_between_stable_controls() {
    exercise(glory::App::new(glory::blitz::Renderer::new));
}
