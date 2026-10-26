#![cfg(any(target_arch = "wasm32", test))]

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

pub(super) fn virtual_timeline(
    scope: &Scope,
    rows: Bond<Vec<ChatMessage>>,
    focus: String,
    follows_latest: bool,
    restore_top: f64,
    save_position: Rc<dyn Fn(f64, bool)>,
) -> (String, Cage<TimelineWindow>) {
    let feed_id = format!("chat-feed-{}", uuid_v7());
    let initial = rows.get_untracked();
    let window = scope.cage(TimelineWindow::initial(
        initial.len(),
        initial.iter().position(|row| row.id == focus),
    ));
    #[cfg(target_arch = "wasm32")]
    browser::install(
        scope,
        feed_id.clone(),
        rows,
        focus,
        follows_latest,
        restore_top,
        window,
        save_position,
    );
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (focus, follows_latest, restore_top, save_position);
    (feed_id, window)
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use wasm_bindgen::JsCast;
    use wasm_bindgen::prelude::*;

    use super::*;
    #[wasm_bindgen(module = "/src/views/chat/timeline_window.js")]
    extern "C" {
        #[wasm_bindgen(catch,js_name=mountVirtualTimeline)]
        fn mount_virtual_timeline(
            configuration: &JsValue,
            publish: &js_sys::Function,
            save_position: &js_sys::Function,
        ) -> std::result::Result<JsValue, JsValue>;
    }
    struct Bridge {
        controller: JsValue,
        _publish: Closure<dyn FnMut(JsValue)>,
        _position: Closure<dyn FnMut(f64, bool)>,
    }
    impl Bridge {
        fn update(&self, value: &serde_json::Value) {
            if let Ok(value) = js_sys::JSON::parse(&value.to_string()) {
                let _ = self.call("update", &value);
            }
        }
        fn call(&self, method: &str, value: &JsValue) -> std::result::Result<(), JsValue> {
            let function = js_sys::Reflect::get(&self.controller, &method.into())?
                .dyn_into::<js_sys::Function>()?;
            function.call1(&self.controller, value).map(|_| ())
        }
    }
    impl Drop for Bridge {
        fn drop(&mut self) {
            let _ = self.call("dispose", &JsValue::UNDEFINED);
        }
    }
    pub(super) fn install(
        scope: &Scope,
        feed_id: String,
        rows: Bond<Vec<ChatMessage>>,
        focus: String,
        follows_latest: bool,
        restore_top: f64,
        window: Cage<TimelineWindow>,
        save_position: Rc<dyn Fn(f64, bool)>,
    ) {
        let focus = if focus.is_empty() {
            focus
        } else {
            message_row::presentation_key(&focus)
        };
        let bridge: Rc<RefCell<Option<Bridge>>> = Rc::new(RefCell::new(None));
        let generation = Rc::new(Cell::new(0_u64));
        let observed_bridge = bridge.clone();
        let observed_generation = generation.clone();
        let observed_focus = focus.clone();
        scope.effect(move || {
            let next=observed_generation.get().wrapping_add(1);observed_generation.set(next);
            let rows=rows.get();
            if let Some(bridge)=observed_bridge.borrow().as_ref(){bridge.update(&json!({"generation":next,"focus":observed_focus,"keys":rows.iter().map(|row|message_row::presentation_key(&row.id)).collect::<Vec<_>>()}));}
        });
        let retired = bridge.clone();
        scope
            .on_cleanup(move || {
                retired.borrow_mut().take();
            })
            .unwrap_or_else(|error| scope.report_error(error));
        let owner = scope.downgrade();
        let _=scope.spawn(async move {
            for _ in 0..120 {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(16)).await;
                if owner.upgrade().is_none(){return;}
                let callback_bridge=bridge.clone();let callback_generation=generation.clone();
                let publish=Closure::wrap(Box::new(move |value:JsValue| {
                    let candidate=js_sys::JSON::stringify(&value).ok().and_then(|value|value.as_string()).and_then(|value|serde_json::from_str::<TimelineWindow>(&value).ok());
                    if let Some(candidate)=candidate.filter(|value|value.valid_for(callback_generation.get(),rows.get_untracked().len()))
                        && window.get_untracked()!=candidate {window.revise(|value|*value=candidate);}
                    if let Some(bridge)=callback_bridge.borrow().as_ref(){bridge.update(&json!({"ack":true}));}
                }) as Box<dyn FnMut(JsValue)>);
                let configuration=match js_sys::JSON::parse(&json!({"feed_id":feed_id,"follows_latest":follows_latest,"restore_top":restore_top}).to_string()) {
                    Ok(configuration)=>configuration,
                    Err(error)=>{tracing::warn!(?error,"timeline configuration could not be serialized");return;}
                };
                let saved = save_position.clone();
                let position = Closure::wrap(Box::new(move |top, follows| saved(top, follows)) as Box<dyn FnMut(f64, bool)>);
                match mount_virtual_timeline(&configuration,publish.as_ref().unchecked_ref(),position.as_ref().unchecked_ref()) {
                    Ok(controller) if !controller.is_undefined() && !controller.is_null() => {
                        let next=Bridge{controller,_publish:publish,_position:position};
                        let rows=rows.get_untracked();
                        next.update(&json!({"generation":generation.get(),"focus":focus,"keys":rows.iter().map(|row|message_row::presentation_key(&row.id)).collect::<Vec<_>>()}));
                        *bridge.borrow_mut()=Some(next);return;
                    }
                    Ok(_) => {},
                    Err(error) => {tracing::warn!(?error,"timeline presentation host failed");return;}
                }
            }
            tracing::warn!("timeline presentation host did not mount");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_window_mounts_with_native_owner_and_disposes() {
        let app = glory::ui::App::memory();
        let scope = app.scope();
        let rows = scope.bond(Vec::<ChatMessage>::new);
        let (_, window) =
            virtual_timeline(scope, rows, String::new(), true, 0.0, Rc::new(|_, _| {}));
        assert_eq!(window.get_untracked().end, 0);
        scope.dispose();
        assert!(!window.is_alive());
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
