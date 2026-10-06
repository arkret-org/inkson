use super::*;

#[derive(Clone, Copy, Debug, PartialEq, serde::Deserialize)]
pub(super) struct TimelineWindow {
    pub generation: u64,
    pub start: usize,
    pub end: usize,
    pub top: f64,
    pub total: f64,
}

impl TimelineWindow {
    pub fn initial(count: usize, focus: Option<usize>) -> Self {
        let start = focus.map_or_else(
            || count.saturating_sub(32),
            |index| index.saturating_sub(12),
        );
        Self {
            generation: 0,
            start,
            end: (start + 32).min(count),
            top: start as f64 * 132.0,
            total: (count as f64 * 132.0 - 12.0).max(0.0),
        }
    }
    pub fn valid_for(&self, generation: u64, count: usize) -> bool {
        self.generation == generation
            && self.start <= self.end
            && self.end <= count
            && self.end - self.start <= 120
            && self.top.is_finite()
            && self.top >= 0.0
            && self.total.is_finite()
            && self.total >= self.top
    }
}

pub(super) fn use_virtual_timeline(
    rows: Memo<Vec<ChatMessage>>,
    focus: String,
    follows_latest: bool,
    restore_top: f64,
) -> (String, TimelineWindow, EventHandler<MountedEvent>) {
    let feed_id = use_hook(|| format!("chat-feed-{}", uuid_v7()));
    let initial = rows.peek();
    let mut window = use_signal(|| {
        TimelineWindow::initial(
            initial.len(),
            initial.iter().position(|row| row.id == focus),
        )
    });
    drop(initial);
    let mut bridge = use_signal(|| None::<document::Eval>);
    let generation = use_hook(|| std::rc::Rc::new(std::cell::Cell::new(0_u64)));
    let generation_for_effect = generation.clone();
    use_effect(use_reactive((&focus,), move |(focus,)| {
        let rows = rows.read();
        if let Some(eval) = *bridge.read() {
            let next = generation_for_effect.get().wrapping_add(1);
            generation_for_effect.set(next);
            let _ = eval.send(json!({"generation":next, "focus":focus,
                "keys":rows.iter().map(|row|row.id.as_str()).collect::<Vec<_>>()}));
        }
    }));
    use_drop(move || {
        if let Some(eval) = *bridge.peek() {
            let _ = eval.send(json!({"dispose":true}));
        }
    });
    let mounted_id = feed_id.clone();
    let mounted = use_callback(move |_: MountedEvent| {
        if bridge.peek().is_some() {
            return;
        }
        let mut eval = document::eval(include_str!("timeline_window.js"));
        let _ = eval.send(json!({"feed_id": mounted_id, "follows_latest":follows_latest, "restore_top":restore_top}));
        bridge.set(Some(eval));
        let generation = generation.clone();
        spawn(async move {
            while let Ok(candidate) = eval.recv::<TimelineWindow>().await {
                if candidate.valid_for(generation.get(), rows.peek().len())
                    && *window.peek() != candidate
                {
                    window.set(candidate);
                }
                if eval.send(json!({"ack":true})).is_err() {
                    break;
                }
            }
        });
    });
    (feed_id, window(), mounted)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn production_window_harness(mounted: std::rc::Rc<std::cell::Cell<bool>>) -> Element {
        let rows = use_memo(Vec::<ChatMessage>::new);
        let (id, window, _) = use_virtual_timeline(rows, String::new(), true, 0.0);
        mounted.set(true);
        rsx! { div { id, "{window.start}:{window.end}" } }
    }

    #[test]
    fn production_virtual_window_hooks_mount_and_render_without_reentrant_hooks() {
        let mounted = std::rc::Rc::new(std::cell::Cell::new(false));
        let mut dom = VirtualDom::new_with_props(production_window_harness, mounted.clone());
        dom.rebuild_in_place();
        for _ in 0..6 {
            dom.render_immediate_to_vec();
        }
        assert!(
            mounted.get(),
            "production virtual window hook did not complete"
        );
    }

    #[test]
    fn initial_window_is_bounded_and_can_focus_an_old_message() {
        let tail = TimelineWindow::initial(10_000, None);
        assert_eq!((tail.start, tail.end), (9968, 10_000));
        let focus = TimelineWindow::initial(10_000, Some(500));
        assert!(focus.start <= 500 && focus.end > 500);
        assert!(focus.end - focus.start <= 32);
    }
    #[test]
    fn late_or_invalid_layout_cannot_publish_out_of_bounds_rows() {
        let mut window = TimelineWindow::initial(10_000, None);
        assert!(window.valid_for(0, 10_000));
        assert!(!window.valid_for(1, 10_000));
        window.end = 10001;
        assert!(!window.valid_for(0, 10_000));
        window = TimelineWindow::initial(10_000, None);
        window.top = f64::NAN;
        assert!(!window.valid_for(0, 10_000));
    }
}
