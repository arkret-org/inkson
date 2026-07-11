use super::*;

/// Route-scoped state shared by the shell and the selected route surface.
/// Keeping these handles together makes route changes explicit and prevents
/// individual surfaces from depending on the root component's hook order.
#[derive(Clone, PartialEq)]
pub(super) struct NavigationState {
    pub(super) route: Route,
    pub(super) view: Signal<crate::views::AppView>,
    pub(super) selected_realm_id: Signal<String>,
    pub(super) new_space_context_node: Signal<String>,
}

impl NavigationState {
    pub(super) fn new(
        route: Route,
        view: Signal<crate::views::AppView>,
        selected_realm_id: Signal<String>,
        new_space_context_node: Signal<String>,
    ) -> Self {
        Self {
            route,
            view,
            selected_realm_id,
            new_space_context_node,
        }
    }
}
