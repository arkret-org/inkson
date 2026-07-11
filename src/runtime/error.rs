#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeErrorClass {
    Terminal { reason: String },
    Retryable { reason: String },
    NeedsSignIn { reason: String },
}

impl RuntimeErrorClass {
    pub fn reason(&self) -> &str {
        match self {
            Self::Terminal { reason }
            | Self::Retryable { reason }
            | Self::NeedsSignIn { reason } => reason,
        }
    }
}

impl From<crate::session::CurrentSessionRefresh> for RuntimeErrorClass {
    fn from(value: crate::session::CurrentSessionRefresh) -> Self {
        match value {
            crate::session::CurrentSessionRefresh::Credential(_) => Self::Retryable {
                reason: "session refreshed; retry the operation".to_owned(),
            },
            crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                Self::NeedsSignIn { reason }
            }
            crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                Self::Terminal { reason }
            }
            crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                Self::Retryable { reason }
            }
        }
    }
}

impl From<&crate::authed_api::ApiCallError> for RuntimeErrorClass {
    fn from(value: &crate::authed_api::ApiCallError) -> Self {
        match value {
            crate::authed_api::ApiCallError::AuthExpired(error) => Self::Terminal {
                reason: error.to_string(),
            },
            crate::authed_api::ApiCallError::Unavailable(error)
            | crate::authed_api::ApiCallError::Failed(error) => Self::Retryable {
                reason: error.to_string(),
            },
        }
    }
}
