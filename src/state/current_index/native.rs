use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

#[derive(Clone)]
pub(super) struct Backend {
    connection: Arc<Mutex<Connection>>,
    key: Arc<[u8; 32]>,
}

impl Backend {
    #[cfg(test)]
    pub(super) async fn open_test(path: std::path::PathBuf) -> anyhow::Result<Self> {
        tokio::task::spawn_blocking(move || {
            let conn=Connection::open(path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS current_entries(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;")?;
            Ok(Self{connection:Arc::new(Mutex::new(conn)),key:Arc::new([37;32])})
        }).await?
    }
    pub(super) async fn open(location: super::CurrentIndexLocation) -> anyhow::Result<Self> {
        tokio::task::spawn_blocking(move || {
            if let Some(parent)=location.path.parent() { std::fs::create_dir_all(parent)?; }
            let name=format!("inkson.current.v1.wrapping.{}",arkret_sdk::canonical::canonical_sha256(&location.path.to_string_lossy())?);
            let mut conn=Connection::open(location.path)?;
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS current_entries(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;")?;
            let secure=crate::secure_key_store::default_secure_key_store("inkson");
            let tx=conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let key=match secure.get_secret(&name)? {
                Some(encoded)=>hex::decode(encoded)?.try_into().map_err(|_|anyhow::anyhow!("invalid current wrapping key"))?,
                None=>{
                    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM current_entries)",[],|row|row.get(0))?;
                    anyhow::ensure!(!exists,"current wrapping key unavailable for existing index");
                    let mut key=[0u8;32];getrandom::fill(&mut key)?;
                    secure.store_secret(&name,&hex::encode(key))?;key
                }
            };
            tx.commit()?;
            Ok(Self{connection:Arc::new(Mutex::new(conn)),key:Arc::new(key)})
        }).await?
    }
    fn unpack(&self, key: &str, value: String) -> anyhow::Result<Vec<u8>> {
        let plain = crate::secure_key_store::unwrap_secret(&value, &self.key)?
            .ok_or_else(|| anyhow::anyhow!("current entry authentication failed"))?;
        let (bound_key, payload): (String, String) = serde_json::from_str(&plain)?;
        anyhow::ensure!(bound_key == key, "current entry key binding differs");
        Ok(payload.into_bytes())
    }
    pub(super) async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let this = self.clone();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = this
                .connection
                .lock()
                .map_err(|_| anyhow::anyhow!("current index lock poisoned"))?;
            let raw: Option<String> = conn
                .query_row(
                    "SELECT value FROM current_entries WHERE key=?1",
                    [&key],
                    |row| row.get(0),
                )
                .optional()?;
            raw.map(|value| this.unpack(&key, value)).transpose()
        })
        .await?
    }
    pub(super) async fn scan(
        &self,
        prefix: &str,
        lower: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
        anyhow::ensure!((1..=100).contains(&limit), "unbounded current index scan");
        let this = self.clone();
        let prefix = prefix.to_owned();
        let lower = lower.unwrap_or(&prefix).to_owned();
        let after = after.unwrap_or("").to_owned();
        tokio::task::spawn_blocking(move || {
            let conn=this.connection.lock().map_err(|_|anyhow::anyhow!("current index lock poisoned"))?;
            let mut statement=conn.prepare("SELECT key,value FROM current_entries WHERE key>=?1 AND key<?2 AND key>?3 ORDER BY key LIMIT ?4")?;
            let rows=statement.query_map(params![lower,format!("{prefix}~"),after,limit as i64],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?;
            let mut out=Vec::new();
            for row in rows {let (key,value)=row?;let bytes=this.unpack(&key,value)?;out.push((key,bytes));}
            Ok(out)
        }).await?
    }
    pub(super) async fn keys(
        &self,
        prefix: &str,
        lower: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<String>> {
        anyhow::ensure!((1..=100).contains(&limit), "unbounded current key scan");
        let this = self.clone();
        let prefix = prefix.to_owned();
        let lower = lower.unwrap_or(&prefix).to_owned();
        let after = after.unwrap_or("").to_owned();
        tokio::task::spawn_blocking(move || {
            let conn=this.connection.lock().map_err(|_|anyhow::anyhow!("current index lock poisoned"))?;
            let mut statement=conn.prepare("SELECT key FROM current_entries WHERE key>=?1 AND key<?2 AND key>?3 ORDER BY key LIMIT ?4")?;
            let rows=statement.query_map(params![lower,format!("{prefix}~"),after,limit as i64],|row|row.get::<_,String>(0))?;
            Ok(rows.collect::<Result<Vec<_>,_>>()?)
        }).await?
    }
    pub(super) async fn apply(
        &self,
        deletes: Vec<String>,
        writes: Vec<(String, Vec<u8>)>,
    ) -> anyhow::Result<()> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn=this.connection.lock().map_err(|_|anyhow::anyhow!("current index lock poisoned"))?;
            let tx=conn.transaction()?;
            for key in deletes {tx.execute("DELETE FROM current_entries WHERE key=?1",[key])?;}
            for (key,value) in writes {
                let plain=serde_json::to_string(&(&key,String::from_utf8(value)?))?;
                let wrapped=crate::secure_key_store::wrap_secret(&plain,&this.key)?;
                tx.execute("INSERT INTO current_entries(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,wrapped])?;
            }
            tx.commit()?;Ok(())
        }).await?
    }
}
