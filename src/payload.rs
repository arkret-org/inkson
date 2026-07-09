use serde::Serialize;
use serde_json::Value;

pub(crate) fn sdk_payload_value(
    result: arkret_sdk::Result<Value>,
    context: &str,
) -> anyhow::Result<Value> {
    result.map_err(|err| anyhow::anyhow!("{context}: {err}"))
}

pub(crate) fn payload_value<T: Serialize>(payload: &T, context: &str) -> anyhow::Result<Value> {
    serde_json::to_value(payload).map_err(|err| anyhow::anyhow!("{context}: {err}"))
}

pub(crate) fn strand_id_value(value: &str) -> anyhow::Result<arkret_sdk::StrandId> {
    arkret_sdk::StrandId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid strand id {value:?}: {err:?}"))
}
