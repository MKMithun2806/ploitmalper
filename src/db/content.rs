use std::fs;
use std::path::{Path, PathBuf};

use crate::config::config_dir;
use crate::db::models::sha256_hex;
use crate::error::Result;

/// Content that exceeds this size is never mirrored back into the database;
/// it lives only in the content store.
pub const MAX_DB_CONTENT: usize = 2000;

/// Directory holding all bulk content (full reports, long finding evidence).
/// Relative paths stored in the database are resolved against this.
pub fn content_dir() -> PathBuf {
    config_dir().join("content")
}

/// Store `content` in the content store, content-addressed by sha256. Returns
/// `(hash, relative_path)` where relative_path is relative to the config dir.
pub fn store_content(content: &str) -> Result<(String, String)> {
    let hash = sha256_hex(content);
    let dir = content_dir();
    fs::create_dir_all(&dir)?;
    let abs = dir.join(&hash);
    if !abs.exists() {
        fs::write(&abs, content)?;
    }
    Ok((hash.clone(), format!("content/{}", hash)))
}

/// Resolve a content-store relative path to an absolute filesystem path.
pub fn resolve_path(rel: &str) -> PathBuf {
    config_dir().join(rel)
}

/// Read a content-store file back.
pub fn read_content(rel: &str) -> Result<String> {
    Ok(fs::read_to_string(resolve_path(rel))?)
}

/// Truncate a string to at most `max` characters for storage as a short DB
/// field; the full content should already be in the content store.
pub fn short_excerpt(content: &str, max: usize) -> String {
    if content.chars().count() <= max {
        return content.to_string();
    }
    let mut out: String = content.chars().take(max).collect();
    out.push('…');
    out
}

/// True if the content is "short stuff" that can stay in the database.
pub fn is_short(content: &str) -> bool {
    content.len() <= MAX_DB_CONTENT
}

/// Store long content in the content store and keep only a short excerpt in
/// the database. Returns `(db_value, detail_path)`; for short content the
/// value is the full content and `detail_path` is `None`.
pub fn store_or_excerpt(content: &str) -> Result<(String, Option<String>)> {
    if is_short(content) {
        return Ok((content.to_string(), None));
    }
    let (_, rel) = store_content(content)?;
    Ok((short_excerpt(content, MAX_DB_CONTENT), Some(rel)))
}

/// Ensure a path is a content-store-relative path (sanity check).
pub fn is_content_rel(path: &Path) -> bool {
    path.starts_with("content")
}
