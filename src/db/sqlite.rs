use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::Value;

use crate::db::models::{Asset, Finding, Observation, Relationship, Report, ScanRun, Service};
use crate::db::{collections, Storage};
use crate::error::Result;

/// SQLite storage backend. Each collection maps to a table; JSON fields are
/// stored as TEXT columns and (de)serialized on write/read.
pub struct SqliteStorage {
    conn: Connection,
}

impl SqliteStorage {
    pub fn open(path: &str) -> Result<Self> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        let storage = Self { conn };
        storage.create_tables()?;
        Ok(storage)
    }

    fn create_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS Assets (
                stable_id   TEXT PRIMARY KEY,
                asset_type  TEXT,
                name        TEXT NOT NULL,
                ip          TEXT,
                fqdn        TEXT,
                reverse_dns TEXT,
                first_seen  TEXT,
                last_seen   TEXT,
                status      TEXT,
                metadata    TEXT
            );
            CREATE TABLE IF NOT EXISTS Services (
                stable_id    TEXT PRIMARY KEY,
                asset_id     TEXT NOT NULL,
                port         INTEGER,
                protocol     TEXT,
                service_name TEXT,
                product      TEXT,
                version      TEXT,
                version_str  TEXT,
                banner       TEXT,
                technologies TEXT,
                cpes         TEXT,
                first_seen   TEXT,
                last_seen    TEXT,
                status       TEXT,
                metadata     TEXT
            );
            CREATE TABLE IF NOT EXISTS Findings (
                stable_id       TEXT PRIMARY KEY,
                asset_id        TEXT NOT NULL,
                service_id      TEXT,
                title           TEXT NOT NULL,
                severity        TEXT,
                tool            TEXT,
                target_url      TEXT,
                detail          TEXT,
                reference       TEXT,
                cves            TEXT,
                endpoints       TEXT,
                technologies    TEXT,
                first_seen      TEXT,
                last_seen       TEXT,
                status          TEXT,
                exploitability  TEXT,
                metadata        TEXT
            );
            CREATE TABLE IF NOT EXISTS Observations (
                stable_id    TEXT PRIMARY KEY,
                run_id       TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                subject_id   TEXT NOT NULL,
                kind         TEXT NOT NULL,
                before       TEXT,
                after        TEXT,
                detail       TEXT,
                observed_at  TEXT
            );
            CREATE TABLE IF NOT EXISTS Relationships (
                stable_id    TEXT PRIMARY KEY,
                run_id       TEXT,
                subject_type TEXT NOT NULL,
                subject_id   TEXT NOT NULL,
                object_type  TEXT NOT NULL,
                object_id    TEXT NOT NULL,
                kind         TEXT NOT NULL,
                detail       TEXT
            );
            CREATE TABLE IF NOT EXISTS ScanRuns (
                stable_id    TEXT PRIMARY KEY,
                target       TEXT NOT NULL,
                folder       TEXT,
                started_at   TEXT,
                finished_at  TEXT,
                tools        TEXT,
                artifacts    TEXT,
                content_hash TEXT,
                imported_at  TEXT,
                stats        TEXT
            );
            CREATE TABLE IF NOT EXISTS Reports (
                stable_id    TEXT PRIMARY KEY,
                run_id       TEXT NOT NULL,
                tool         TEXT NOT NULL,
                format       TEXT NOT NULL,
                title        TEXT,
                source_path  TEXT,
                content      TEXT,
                content_hash TEXT,
                imported_at  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_services_asset ON Services(asset_id);
            CREATE INDEX IF NOT EXISTS idx_findings_asset ON Findings(asset_id);
            CREATE INDEX IF NOT EXISTS idx_obs_subject ON Observations(subject_type, subject_id);
            CREATE INDEX IF NOT EXISTS idx_rel_subject ON Relationships(subject_type, subject_id);
            CREATE INDEX IF NOT EXISTS idx_reports_run ON Reports(run_id);",
        )?;
        Ok(())
    }
}

fn json_or_null<T: serde::Serialize>(value: &T) -> rusqlite::Result<String> {
    serde_json::to_string(value).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
}

fn parse_json(raw: Option<String>) -> Value {
    raw.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null)
}

fn parse_vec(raw: Option<String>) -> Vec<String> {
    match parse_json(raw) {
        Value::Array(items) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_vec_value(raw: Option<String>) -> Vec<Value> {
    match parse_json(raw) {
        Value::Array(items) => items,
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

fn asset_from_row(row: &Row) -> rusqlite::Result<Asset> {
    Ok(Asset {
        stable_id: row.get("stable_id")?,
        asset_type: row.get("asset_type")?,
        name: row.get("name")?,
        ip: row.get("ip")?,
        fqdn: row.get("fqdn")?,
        reverse_dns: row.get("reverse_dns")?,
        first_seen: row.get("first_seen")?,
        last_seen: row.get("last_seen")?,
        status: row.get("status")?,
        metadata: parse_json(row.get("metadata")?),
    })
}

fn service_from_row(row: &Row) -> rusqlite::Result<Service> {
    Ok(Service {
        stable_id: row.get("stable_id")?,
        asset_id: row.get("asset_id")?,
        port: row.get("port")?,
        protocol: row.get("protocol")?,
        service_name: row.get("service_name")?,
        product: row.get("product")?,
        version: row.get("version")?,
        version_str: row.get("version_str")?,
        banner: row.get("banner")?,
        technologies: parse_vec(row.get("technologies")?),
        cpes: parse_vec(row.get("cpes")?),
        first_seen: row.get("first_seen")?,
        last_seen: row.get("last_seen")?,
        status: row.get("status")?,
        metadata: parse_json(row.get("metadata")?),
    })
}

fn finding_from_row(row: &Row) -> rusqlite::Result<Finding> {
    Ok(Finding {
        stable_id: row.get("stable_id")?,
        asset_id: row.get("asset_id")?,
        service_id: row.get("service_id")?,
        title: row.get("title")?,
        severity: row.get("severity")?,
        tool: row.get("tool")?,
        target_url: row.get("target_url")?,
        detail: row.get("detail")?,
        reference: row.get("reference")?,
        cves: parse_vec(row.get("cves")?),
        endpoints: parse_vec(row.get("endpoints")?),
        technologies: parse_vec(row.get("technologies")?),
        first_seen: row.get("first_seen")?,
        last_seen: row.get("last_seen")?,
        status: row.get("status")?,
        exploitability: row.get("exploitability")?,
        metadata: parse_json(row.get("metadata")?),
    })
}

fn observation_from_row(row: &Row) -> rusqlite::Result<Observation> {
    Ok(Observation {
        stable_id: row.get("stable_id")?,
        run_id: row.get("run_id")?,
        subject_type: row.get("subject_type")?,
        subject_id: row.get("subject_id")?,
        kind: row.get("kind")?,
        before: parse_json(row.get("before")?),
        after: parse_json(row.get("after")?),
        detail: row.get("detail")?,
        observed_at: row.get("observed_at")?,
    })
}

fn relationship_from_row(row: &Row) -> rusqlite::Result<Relationship> {
    Ok(Relationship {
        stable_id: row.get("stable_id")?,
        run_id: row.get("run_id")?,
        subject_type: row.get("subject_type")?,
        subject_id: row.get("subject_id")?,
        object_type: row.get("object_type")?,
        object_id: row.get("object_id")?,
        kind: row.get("kind")?,
        detail: row.get("detail")?,
    })
}

fn scan_run_from_row(row: &Row) -> rusqlite::Result<ScanRun> {
    Ok(ScanRun {
        stable_id: row.get("stable_id")?,
        target: row.get("target")?,
        folder: row.get("folder")?,
        started_at: row.get("started_at")?,
        finished_at: row.get("finished_at")?,
        tools: parse_vec(row.get("tools")?),
        artifacts: parse_vec_value(row.get("artifacts")?),
        content_hash: row.get("content_hash")?,
        imported_at: row.get("imported_at")?,
        stats: parse_json(row.get("stats")?),
    })
}

fn report_from_row(row: &Row) -> rusqlite::Result<Report> {
    Ok(Report {
        stable_id: row.get("stable_id")?,
        run_id: row.get("run_id")?,
        tool: row.get("tool")?,
        format: row.get("format")?,
        title: row.get("title")?,
        source_path: row.get("source_path")?,
        content: row.get("content")?,
        content_hash: row.get("content_hash")?,
        imported_at: row.get("imported_at")?,
    })
}

impl Storage for SqliteStorage {
    fn kind(&self) -> &str {
        "sqlite"
    }

    fn ping(&mut self) -> Result<bool> {
        let value: String = self
            .conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1",
                params![collections::ASSETS],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_default();
        Ok(value == collections::ASSETS)
    }

    fn ensure_schema(&mut self) -> Result<()> {
        self.create_tables()
    }

    fn upsert_scan_run(&mut self, run: &ScanRun) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO ScanRuns (stable_id, target, folder, started_at, finished_at, tools, artifacts, content_hash, imported_at, stats)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                run.stable_id,
                run.target,
                run.folder,
                run.started_at,
                run.finished_at,
                json_or_null(&run.tools)?,
                json_or_null(&run.artifacts)?,
                run.content_hash,
                run.imported_at,
                json_or_null(&run.stats)?
            ],
        )?;
        Ok(())
    }

    fn get_scan_run(&mut self, run_id: &str) -> Result<Option<ScanRun>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM ScanRuns WHERE stable_id = ?1",
                params![run_id],
                scan_run_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn list_scan_runs(&mut self) -> Result<Vec<ScanRun>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM ScanRuns ORDER BY imported_at DESC")?;
        let rows = stmt.query_map([], scan_run_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn upsert_asset(&mut self, asset: &Asset) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO Assets (stable_id, asset_type, name, ip, fqdn, reverse_dns, first_seen, last_seen, status, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                asset.stable_id,
                asset.asset_type,
                asset.name,
                asset.ip,
                asset.fqdn,
                asset.reverse_dns,
                asset.first_seen,
                asset.last_seen,
                asset.status,
                json_or_null(&asset.metadata)?
            ],
        )?;
        Ok(())
    }

    fn get_asset(&mut self, asset_id: &str) -> Result<Option<Asset>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM Assets WHERE stable_id = ?1",
                params![asset_id],
                asset_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn list_assets(&mut self) -> Result<Vec<Asset>> {
        let mut stmt = self.conn.prepare("SELECT * FROM Assets ORDER BY name")?;
        let rows = stmt.query_map([], asset_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn upsert_service(&mut self, service: &Service) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO Services (stable_id, asset_id, port, protocol, service_name, product, version, version_str, banner, technologies, cpes, first_seen, last_seen, status, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                service.stable_id,
                service.asset_id,
                service.port,
                service.protocol,
                service.service_name,
                service.product,
                service.version,
                service.version_str,
                service.banner,
                json_or_null(&service.technologies)?,
                json_or_null(&service.cpes)?,
                service.first_seen,
                service.last_seen,
                service.status,
                json_or_null(&service.metadata)?
            ],
        )?;
        Ok(())
    }

    fn get_service(&mut self, service_id: &str) -> Result<Option<Service>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM Services WHERE stable_id = ?1",
                params![service_id],
                service_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn list_services_for_asset(&mut self, asset_id: &str) -> Result<Vec<Service>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM Services WHERE asset_id = ?1 ORDER BY port")?;
        let rows = stmt.query_map(params![asset_id], service_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn list_all_services(&mut self) -> Result<Vec<Service>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM Services ORDER BY asset_id, port")?;
        let rows = stmt.query_map([], service_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn upsert_finding(&mut self, finding: &Finding) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO Findings (stable_id, asset_id, service_id, title, severity, tool, target_url, detail, reference, cves, endpoints, technologies, first_seen, last_seen, status, exploitability, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                finding.stable_id,
                finding.asset_id,
                finding.service_id,
                finding.title,
                finding.severity,
                finding.tool,
                finding.target_url,
                finding.detail,
                finding.reference,
                json_or_null(&finding.cves)?,
                json_or_null(&finding.endpoints)?,
                json_or_null(&finding.technologies)?,
                finding.first_seen,
                finding.last_seen,
                finding.status,
                finding.exploitability,
                json_or_null(&finding.metadata)?
            ],
        )?;
        Ok(())
    }

    fn get_finding(&mut self, finding_id: &str) -> Result<Option<Finding>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM Findings WHERE stable_id = ?1",
                params![finding_id],
                finding_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn list_findings_for_asset(&mut self, asset_id: &str) -> Result<Vec<Finding>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM Findings WHERE asset_id = ?1 ORDER BY severity, title")?;
        let rows = stmt.query_map(params![asset_id], finding_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn list_all_findings(&mut self) -> Result<Vec<Finding>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM Findings ORDER BY asset_id, title")?;
        let rows = stmt.query_map([], finding_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn add_observation(&mut self, observation: &Observation) -> Result<()> {
        if self.get_observation(&observation.stable_id)?.is_some() {
            return Ok(());
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO Observations (stable_id, run_id, subject_type, subject_id, kind, before, after, detail, observed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                observation.stable_id,
                observation.run_id,
                observation.subject_type,
                observation.subject_id,
                observation.kind,
                json_or_null(&observation.before)?,
                json_or_null(&observation.after)?,
                observation.detail,
                observation.observed_at
            ],
        )?;
        Ok(())
    }

    fn get_observation(&mut self, obs_id: &str) -> Result<Option<Observation>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM Observations WHERE stable_id = ?1",
                params![obs_id],
                observation_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn list_observations_for(
        &mut self,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<Observation>> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM Observations WHERE subject_type = ?1 AND subject_id = ?2 ORDER BY observed_at",
        )?;
        let rows = stmt.query_map(params![subject_type, subject_id], observation_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn list_all_observations(&mut self) -> Result<Vec<Observation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM Observations ORDER BY observed_at")?;
        let rows = stmt.query_map([], observation_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn upsert_relationship(&mut self, relationship: &Relationship) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO Relationships (stable_id, run_id, subject_type, subject_id, object_type, object_id, kind, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                relationship.stable_id,
                relationship.run_id,
                relationship.subject_type,
                relationship.subject_id,
                relationship.object_type,
                relationship.object_id,
                relationship.kind,
                relationship.detail
            ],
        )?;
        Ok(())
    }

    fn get_relationship(&mut self, rel_id: &str) -> Result<Option<Relationship>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM Relationships WHERE stable_id = ?1",
                params![rel_id],
                relationship_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn list_relationships_for(
        &mut self,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<Relationship>> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM Relationships WHERE subject_type = ?1 AND subject_id = ?2 ORDER BY kind",
        )?;
        let rows = stmt.query_map(params![subject_type, subject_id], relationship_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    fn upsert_report(&mut self, report: &Report) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO Reports (stable_id, run_id, tool, format, title, source_path, content, content_hash, imported_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                report.stable_id,
                report.run_id,
                report.tool,
                report.format,
                report.title,
                report.source_path,
                report.content,
                report.content_hash,
                report.imported_at
            ],
        )?;
        Ok(())
    }

    fn get_report(&mut self, report_id: &str) -> Result<Option<Report>> {
        let row = self
            .conn
            .query_row(
                "SELECT * FROM Reports WHERE stable_id = ?1",
                params![report_id],
                report_from_row,
            )
            .optional()?;
        Ok(row)
    }

    fn list_reports_for_run(&mut self, run_id: &str) -> Result<Vec<Report>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM Reports WHERE run_id = ?1 ORDER BY tool")?;
        let rows = stmt.query_map(params![run_id], report_from_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}
