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

impl From<crate::runtime::session::CurrentSessionRefresh> for RuntimeErrorClass {
    fn from(value: crate::runtime::session::CurrentSessionRefresh) -> Self {
        match value {
            crate::runtime::session::CurrentSessionRefresh::Credential(_) => Self::Retryable {
                reason: "session refreshed; retry the operation".to_owned(),
            },
            crate::runtime::session::CurrentSessionRefresh::SignInRequired { reason } => {
                Self::NeedsSignIn { reason }
            }
            crate::runtime::session::CurrentSessionRefresh::LoginRequired { reason } => {
                Self::Terminal { reason }
            }
            crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                Self::Retryable { reason }
            }
        }
    }
}

impl From<&crate::transport::auth::ApiCallError> for RuntimeErrorClass {
    fn from(value: &crate::transport::auth::ApiCallError) -> Self {
        match value {
            crate::transport::auth::ApiCallError::AuthExpired(error) => Self::Terminal {
                reason: error.to_string(),
            },
            crate::transport::auth::ApiCallError::Unavailable(error)
            | crate::transport::auth::ApiCallError::Failed(error) => Self::Retryable {
                reason: error.to_string(),
            },
        }
    }
}
