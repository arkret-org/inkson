use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
struct CanonicalInput {
    value: Value,
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        _ => bail!("unknown inkson-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn read_stdin_json() -> Result<Value> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .context("read stdin")?;
    serde_json::from_str(&stdin).context("parse stdin JSON")
}

fn canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse canonical input")?;
    let canonical = arkret_sdk::canonical::canonical_json_string(&input.value)
        .map_err(|err| anyhow::anyhow!("canonical JSON encode: {err}"))?;
    Ok(json!({ "canonical": canonical }))
}

fn sha256_canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse digest input")?;
    let digest = arkret_sdk::canonical::canonical_sha256(&input.value)
        .map_err(|err| anyhow::anyhow!("canonical JSON digest: {err}"))?;
    Ok(json!({ "digest": digest }))
}
