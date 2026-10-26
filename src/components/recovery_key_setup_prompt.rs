//! Inline Recovery Key setup prompt used by encryption onboarding.
//!
//! This is intentionally a modal flow instead of a settings-page redirect:
//! users choosing recommended encryption need the single required action
//! directly in context, namely generating and saving the 24-word Recovery Key.

use std::rc::Rc;

use glory::prelude::*;

use super::mls_backup_prompt::{
    copy_text_to_clipboard, download_text_as_file, recovery_key_filename_from_handles,
    try_set_state,
};
use crate::presentation::widgets::{heading, line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
use crate::recovery_crypto::{
    RecoveryKeyConfirmationDiff, generate_recovery_key, recovery_key_confirmation_diff,
};
use crate::views::recovery::RecoveryKeyBackupOutcome;
#[cfg(feature = "wasm-localstorage-secrets-test")]
fn trace_recovery_setup(
    stage: &'static str,
    generated: &str,
    confirmation: &str,
    open: bool,
    publishing: bool,
) {
    tracing::warn!(
        stage,
        generated_words = generated.split_whitespace().count(),
        confirmation_words = confirmation.split_whitespace().count(),
        confirmed = matches!(
            recovery_key_confirmation_diff(generated, confirmation),
            RecoveryKeyConfirmationDiff::Match
        ),
        open,
        publishing,
        "recovery setup state transition"
    );
}

#[derive(Clone)]
struct RecoverySetup {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    generated: Cage<String>,
    confirmation: Cage<String>,
    status: Cage<String>,
    copied: Cage<bool>,
    started: Cage<bool>,
    unauthorized: Cage<bool>,
    publishing: Cage<bool>,
    failed: Cage<bool>,
}
impl RecoverySetup {
    fn generate(&self) {
        if self.publishing.get() {
            return;
        }
        try_set_state(self.started, true);
        try_set_state(self.failed, false);
        if self.context.principal_id.get().is_none() {
            try_set_state(
                self.status,
                self.context.tr("recovery_setup.err_requires_account"),
            );
            return;
        }
        let key = match generate_recovery_key() {
            Ok(value) => value,
            Err(error) => {
                try_set_state(self.failed, true);
                try_set_state(
                    self.status,
                    crate::i18n::substitute_args(
                        self.context.tr("recovery_setup.err_generation_failed"),
                        &[("error", error.to_string())],
                    ),
                );
                return;
            }
        };
        #[cfg(feature = "wasm-localstorage-secrets-test")]
        trace_recovery_setup("generate", &key, &self.confirmation.get(), true, false);
        try_set_state(self.copied, false);
        try_set_state(self.confirmation, String::new());
        try_set_state(self.unauthorized, false);
        try_set_state(self.generated, key);
        try_set_state(
            self.status,
            self.context.tr("recovery_setup.status_after_generate"),
        );
    }
    fn dismiss(&self) {
        if self.generated.get().trim().is_empty() {
            try_set_state(self.context.recovery_key_setup_open, false)
        } else {
            try_set_state(
                self.status,
                self.context.tr("recovery_setup.save_first_guard"),
            );
        }
    }
    fn discard(&self) {
        if self.publishing.get() {
            return;
        }
        try_set_state(self.generated, String::new());
        try_set_state(self.confirmation, String::new());
        try_set_state(self.context.recovery_key_setup_open, false);
    }
    fn publish(&self) {
        if self.publishing.get() {
            return;
        }
        let key = self.generated.get();
        match recovery_key_confirmation_diff(&key, &self.confirmation.get()) {
            RecoveryKeyConfirmationDiff::Match => {}
            RecoveryKeyConfirmationDiff::WordCount { entered } => {
                try_set_state(
                    self.status,
                    crate::i18n::substitute_args(
                        self.context.tr("recovery_setup.err_word_count"),
                        &[("entered", entered.to_string())],
                    ),
                );
                return;
            }
            RecoveryKeyConfirmationDiff::MismatchAt { index } => {
                try_set_state(
                    self.status,
                    crate::i18n::substitute_args(
                        self.context.tr("recovery_setup.err_word_mismatch"),
                        &[("index", index.to_string())],
                    ),
                );
                return;
            }
        }
        let Some(account) = self.context.active_account.get() else {
            try_set_state(
                self.status,
                self.context.tr("recovery_setup.err_requires_account"),
            );
            return;
        };
        if self.context.principal_id.get().is_none() || key.trim().is_empty() {
            try_set_state(
                self.status,
                self.context.tr("recovery_setup.err_requires_account"),
            );
            return;
        }
        try_set_state(self.publishing, true);
        try_set_state(self.status, self.context.tr("recovery_setup.publishing"));
        let state = self.clone();
        let generation = self.context.session_generation.get();
        let active = self.context.active_account.get();
        let accepted_key = key.clone();
        let outcome = Rc::new(move |outcome: RecoveryKeyBackupOutcome| {
            if state.owner.upgrade().is_none()
                || !state.context.session_matches(generation, &active)
            {
                return;
            }
            match outcome {
                RecoveryKeyBackupOutcome::Established => {
                    let saved = state.context.state_store.write(|store| {
                        let (fingerprint, _) =
                            crate::views::recovery::save_generated_recovery_key_metadata_in_store(
                                store,
                                &accepted_key,
                            )?;
                        store
                            .save_plain_local_data(crate::app::RECOVERY_AUTO_PROMPT_SHOWN_KEY, "1");
                        store.save_plain_local_data(
                            crate::app::RECOVERY_AUTO_PROMPT_LOCAL_ONLY_SHOWN_KEY,
                            fingerprint,
                        );
                        Some(())
                    });
                    if saved.is_none() {
                        try_set_state(state.publishing, false);
                        try_set_state(
                            state.status,
                            state.context.tr("recovery_setup.metadata_save_failed"),
                        );
                        return;
                    }
                    try_set_state(state.generated, String::new());
                    try_set_state(state.confirmation, String::new());
                    try_set_state(state.context.recovery_key_setup_open, false);
                }
                RecoveryKeyBackupOutcome::DeviceUnauthorized => {
                    try_set_state(state.publishing, false);
                    try_set_state(state.unauthorized, true);
                }
                RecoveryKeyBackupOutcome::Transient => try_set_state(state.publishing, false),
            }
        });
        let bound_account = account.clone();
        let context = self.context.clone();
        let configured = Rc::new(move |()| {
            if context.session_matches(generation, &Some(account.clone())) {
                try_set_state(context.account_recovery_configured, Some(true));
            }
        });
        // Only custody-confirmed words reach the publication owner.
        crate::views::recovery::upload_recovery_key_account_backup(
            self.context.clone(),
            self.context.token,
            self.context.device_id,
            bound_account,
            self.context.state_store.handle(),
            key,
            self.status,
            Some(configured),
            Some(outcome),
        );
    }
}
fn setup_dialog(
    open: Cage<bool>,
    name: Lotus<String>,
    dismiss: impl FnMut(glory::render::DismissReason) + 'static,
    content: View,
) -> View {
    let mut content = Some(content);
    Box::new(
        sapid::dialog("recovery-key-setup")
            .unstyled()
            .class("recovery-key-setup-modal")
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .name(name)
            .open(open)
            .show_trigger(false)
            .show_close(false)
            .on_dismiss(dismiss)
            .content(move || {
                content
                    .take()
                    .unwrap_or_else(|| Box::new(widget(|_| Ok(()))))
            }),
    )
}
pub fn recovery_key_setup_prompt(scope: &Scope, context: Rc<InksonContext>) -> View {
    let state = RecoverySetup {
        context: context.clone(),
        owner: scope.downgrade(),
        generated: scope.cage(String::new()),
        confirmation: scope.cage(String::new()),
        status: scope.cage(String::new()),
        copied: scope.cage(false),
        started: scope.cage(false),
        unauthorized: scope.cage(false),
        publishing: scope.cage(false),
        failed: scope.cage(false),
    };
    let open = context.recovery_key_setup_open;
    let initialize = state.clone();
    let principal = context.principal_id;
    scope.effect(move || {
        if !open.get() {
            try_set_state(initialize.started, false);
            try_set_state(initialize.generated, String::new());
            try_set_state(initialize.confirmation, String::new());
            try_set_state(initialize.status, String::new());
            try_set_state(initialize.copied, false);
            try_set_state(initialize.unauthorized, false);
            try_set_state(initialize.publishing, false);
            try_set_state(initialize.failed, false);
            return;
        }
        if !initialize.started.get()
            && initialize.generated.get().is_empty()
            && principal.get().is_some()
        {
            initialize.generate();
        }
    });
    let source = scope.bond({
        let state = state.clone();
        let context = context.clone();
        move || {
            (
                open.get(),
                state.generated.get(),
                state.unauthorized.get(),
                state.failed.get(),
                context.locale.get(),
            )
        }
    });
    reactive(
        source,
        move |scope, (is_open, generated, unauthorized, failed, _)| {
            if !is_open {
                return Box::new(widget(|_| Ok(())));
            }
            let publishing = state.publishing;
            let enabled = scope.bond(move || !publishing.get());
            let mut body = vec![paragraph(
                if unauthorized {
                    "form-hint-warn"
                } else {
                    "muted"
                },
                context.translated(
                    scope,
                    if unauthorized {
                        "recovery_setup.device_unauthorized"
                    } else {
                        "recovery_setup.intro"
                    },
                ),
            )];
            if !generated.is_empty() {
                body.push(paragraph(
                    "",
                    context.translated(scope, "recovery_setup.generated_key_label"),
                ));
                body.push(Box::new(
                    sapid::text_field()
                        .unstyled()
                        .class("input recovery-key-words")
                        .name(context.translated(scope, "recovery_setup.generated_key_label"))
                        .multiline(true)
                        .readonly(true)
                        .value(generated.clone()),
                ) as View);
                let copy = state.clone();
                let copied = state.copied;
                let ctx = context.clone();
                let label = scope.bond(move || {
                    ctx.tr(if copied.get() {
                        "recovery_setup.copied"
                    } else {
                        "recovery_setup.copy_words"
                    })
                });
                let download = state.clone();
                body.push(line(
                    "mls-backup-key-actions",
                    vec![
                        Box::new(
                            sapid::button()
                                .unstyled()
                                .class("secondary")
                                .label(label)
                                .on_press(move || {
                                    copy_text_to_clipboard(&copy.generated.get());
                                    try_set_state(copy.copied, true);
                                }),
                        ),
                        Box::new(
                            sapid::button()
                                .unstyled()
                                .class("secondary")
                                .label(context.translated(scope, "recovery_setup.download"))
                                .on_press(move || {
                                    let handle = download.context.account_primary_handle.get();
                                    download_text_as_file(
                                        &recovery_key_filename_from_handles(std::slice::from_ref(
                                            &handle,
                                        )),
                                        &download.generated.get(),
                                    );
                                }),
                        ),
                    ],
                ));
                body.push(paragraph(
                    "form-hint-warn",
                    context.translated(scope, "recovery_setup.save_warning"),
                ));
                let value = state.confirmation;
                body.push(Box::new(
                    sapid::field("recovery-key-setup-confirm-key")
                        .unstyled()
                        .class("field")
                        .label(context.translated(scope, "recovery_setup.confirm_label"))
                        .control(move |field| {
                            sapid::text_field()
                                .unstyled()
                                .class("input")
                                .field(field)
                                .multiline(true)
                                .value(value)
                                .enabled(enabled)
                                .on_value_change(move |next| try_set_state(value, next))
                        }),
                ) as View);
                body.push(paragraph(
                    "muted",
                    context.translated(scope, "recovery_setup.confirm_hint"),
                ));
            }
            body.push(paragraph("muted", state.status));
            let mut actions = Vec::<View>::new();
            if unauthorized {
                let restore = state.clone();
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("primary")
                        .label(context.translated(scope, "recovery_setup.restore_button"))
                        .on_press(move || {
                            try_set_state(restore.context.recovery_key_setup_open, false);
                            restore.context.navigate(crate::routes::Route::Recovery);
                        }),
                ));
                let close = state.clone();
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("secondary")
                        .label(context.translated(scope, "recovery_setup.close"))
                        .on_press(move || {
                            try_set_state(close.context.recovery_key_setup_open, false)
                        }),
                ));
            } else if generated.is_empty() {
                if failed {
                    let retry = state.clone();
                    actions.push(Box::new(
                        sapid::button()
                            .unstyled()
                            .class("primary")
                            .label(context.translated(scope, "recovery_setup.try_again"))
                            .on_press(move || retry.generate()),
                    ));
                } else {
                    actions.push(Box::new(
                        sapid::button()
                            .unstyled()
                            .class("primary")
                            .label(context.translated(scope, "recovery_setup.generating_button"))
                            .enabled(false),
                    ));
                }
                let close = state.clone();
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("secondary")
                        .label(context.translated(scope, "recovery_setup.not_now"))
                        .on_press(move || close.dismiss()),
                ));
            } else {
                let regenerate = state.clone();
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("secondary")
                        .label(context.translated(scope, "recovery_setup.regenerate"))
                        .enabled(enabled)
                        .on_press(move || regenerate.generate()),
                ));
                let discard = state.clone();
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("secondary")
                        .label(context.translated(scope, "recovery_setup.close_unpublished"))
                        .enabled(enabled)
                        .on_press(move || discard.discard()),
                ));
                let publish = state.clone();
                let confirmation = state.confirmation;
                let can_publish =
                    scope.bond(move || !publishing.get() && !confirmation.get().trim().is_empty());
                actions.push(Box::new(
                    sapid::button()
                        .unstyled()
                        .class("primary")
                        .label(context.translated(scope, "recovery_setup.confirm_button"))
                        .enabled(can_publish)
                        .on_press(move || publish.publish()),
                ));
            }
            let content = stack(
                "modal event mls-recovery-modal mls-backup-banner recovery-key-setup-dialog",
                vec![
                    stack(
                        "modal-head event-head",
                        vec![
                            heading(3, "", context.translated(scope, "recovery_setup.title")),
                            paragraph(
                                "muted",
                                context.translated(scope, "recovery_setup.subtitle"),
                            ),
                        ],
                    ),
                    stack("modal-body mls-recovery-modal-body", body),
                    line("modal-foot mls-backup-row", actions),
                ],
            );
            let dismiss = state.clone();
            setup_dialog(
                open,
                context
                    .translated(scope, "recovery_setup.aria_label")
                    .into(),
                move |_| dismiss.dismiss(),
                content,
            )
        },
    )
}

#[cfg(test)]
mod dialog_lifecycle_tests {
    use super::*;
    #[test]
    fn recovery_setup_actual_dialog_tracks_close_and_reopen_without_parent_render() {
        let app = App::memory();
        let open = app.scope().cage(true);
        app.mount(setup_dialog(
            open,
            "Recovery Key".into(),
            |_| {},
            Box::new(text().class("public-fixture").content("public fixture")),
        ))
        .unwrap();
        let panels = |app: &App| {
            let tree = app.tree();
            let mut pending = tree.roots().to_vec();
            let mut found = Vec::new();
            while let Some(id) = pending.pop() {
                let node = tree.node(id).unwrap();
                if node
                    .descriptor
                    .view()
                    .classes
                    .iter()
                    .any(|class| class == "sapid-dialog")
                {
                    found.push(id)
                }
                pending.extend(&node.children);
            }
            found
        };
        let panel = panels(&app)[0];
        assert!(
            !app.tree()
                .node(panel)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .hidden
        );
        open.revise(|value| *value = false);
        app.flush().unwrap();
        assert!(
            app.tree()
                .node(panel)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .hidden
        );
        open.revise(|value| *value = false);
        app.flush().unwrap();
        assert_eq!(panels(&app), vec![panel]);
        open.revise(|value| *value = true);
        app.flush().unwrap();
        assert!(
            !app.tree()
                .node(panel)
                .unwrap()
                .descriptor
                .view()
                .semantics
                .as_ref()
                .unwrap()
                .hidden
        );
    }
}
