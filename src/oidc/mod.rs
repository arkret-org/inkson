//! OIDC sign-in support lives in `crate::coauth` and `crate::views::login`.
//!
//! The client opens a standard OIDC authorization URL, then submits the returned
//! authorization code to the Account Authority `session-grants` endpoint. It does
//! not keep OAuth access or refresh tokens as app session material.
