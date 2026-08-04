pub mod content;
pub mod models;
pub mod pocketbase;
pub mod schema;
pub mod sqlite;

use crate::config::DatabaseConfig;
use crate::error::Result;
use models::{Asset, ExploitExecution, Finding, Observation, ScanRun, Service};

/// Collection names used by every backend. Kept intentionally small: bulk
/// content (full reports, long finding evidence) is stored as files in the
/// content store, so the database only holds metadata and short fields.
pub mod collections {
    pub const ASSETS: &str = "Assets";
    pub const SERVICES: &str = "Services";
    pub const FINDINGS: &str = "Findings";
    pub const OBSERVATIONS: &str = "Observations";
    pub const SCAN_RUNS: &str = "ScanRuns";
    pub const EXPLOIT_EXECUTIONS: &str = "ExploitExecutions";

    pub const ALL: [&str; 6] = [
        ASSETS,
        SERVICES,
        FINDINGS,
        OBSERVATIONS,
        SCAN_RUNS,
        EXPLOIT_EXECUTIONS,
    ];
}

/// Backend-agnostic persistence interface used by the importer.
///
/// All write operations are upserts keyed by a stable, content-derived id so
/// that re-running an import over the same scan folder is idempotent. History
/// is preserved through the `Observations` collection rather than by
/// overwriting prior rows.
pub trait Storage: Send {
    fn kind(&self) -> &str;

    /// Verify connectivity (PocketBase health / SQLite open + query).
    fn ping(&mut self) -> Result<bool>;

    /// Create all required collections/tables if they do not exist.
    fn ensure_schema(&mut self) -> Result<()>;

    // --- Scan runs ------------------------------------------------------

    fn upsert_scan_run(&mut self, run: &ScanRun) -> Result<()>;
    fn get_scan_run(&mut self, run_id: &str) -> Result<Option<ScanRun>>;
    fn list_scan_runs(&mut self) -> Result<Vec<ScanRun>>;
    /// Delete a scan run and the records owned by it (observations and
    /// exploit executions). Assets, services and findings are shared across
    /// runs and are left untouched.
    fn delete_scan_run(&mut self, run_id: &str) -> Result<()>;

    // --- Assets ---------------------------------------------------------

    fn upsert_asset(&mut self, asset: &Asset) -> Result<()>;
    fn get_asset(&mut self, asset_id: &str) -> Result<Option<Asset>>;
    fn list_assets(&mut self) -> Result<Vec<Asset>>;

    // --- Services -------------------------------------------------------

    fn upsert_service(&mut self, service: &Service) -> Result<()>;
    fn get_service(&mut self, service_id: &str) -> Result<Option<Service>>;
    fn list_services_for_asset(&mut self, asset_id: &str) -> Result<Vec<Service>>;
    fn list_all_services(&mut self) -> Result<Vec<Service>>;

    // --- Findings -------------------------------------------------------

    fn upsert_finding(&mut self, finding: &Finding) -> Result<()>;
    fn get_finding(&mut self, finding_id: &str) -> Result<Option<Finding>>;
    fn list_findings_for_asset(&mut self, asset_id: &str) -> Result<Vec<Finding>>;
    fn list_all_findings(&mut self) -> Result<Vec<Finding>>;

    // --- Observations ---------------------------------------------------

    fn add_observation(&mut self, observation: &Observation) -> Result<()>;
    fn get_observation(&mut self, obs_id: &str) -> Result<Option<Observation>>;
    fn list_observations_for(
        &mut self,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<Observation>>;
    fn list_all_observations(&mut self) -> Result<Vec<Observation>>;

    // --- Exploit executions ---------------------------------------------

    fn upsert_exploit_execution(&mut self, execution: &ExploitExecution) -> Result<()>;
    fn get_exploit_execution(&mut self, execution_id: &str) -> Result<Option<ExploitExecution>>;
    fn list_exploit_executions(&mut self) -> Result<Vec<ExploitExecution>>;
    fn list_exploit_executions_for_run(&mut self, run_id: &str) -> Result<Vec<ExploitExecution>>;
}

/// Open a storage backend based on the persisted configuration.
pub fn open_storage(config: &DatabaseConfig) -> Result<Box<dyn Storage>> {
    if config.backend == "sqlite" {
        Ok(Box::new(sqlite::SqliteStorage::open(&config.sqlite_path)?))
    } else {
        Ok(Box::new(pocketbase::PocketBaseStorage::new(config)?))
    }
}

/// Open a storage backend, overriding the configured backend.
pub fn open_storage_with(
    config: &DatabaseConfig,
    backend: &str,
    pocketbase_url: Option<&str>,
    sqlite_path: Option<&str>,
) -> Result<Box<dyn Storage>> {
    if backend == "sqlite" {
        let path = sqlite_path
            .map(str::to_string)
            .unwrap_or_else(|| config.sqlite_path.clone());
        Ok(Box::new(sqlite::SqliteStorage::open(&path)?))
    } else {
        let mut override_config = config.clone();
        if let Some(url) = pocketbase_url {
            override_config.pocketbase_url = url.to_string();
        }
        Ok(Box::new(pocketbase::PocketBaseStorage::new(
            &override_config,
        )?))
    }
}
