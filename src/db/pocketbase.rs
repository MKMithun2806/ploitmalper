use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::config::DatabaseConfig;
use crate::db::models::{Asset, Finding, Observation, ScanRun, Service};
use crate::db::schema::{self, FieldDef};
use crate::db::{collections, Storage};
use crate::error::{AppError, Result};

const REQUEST_TIMEOUT_S: u64 = 60;

/// PocketBase storage backend. Talks to the PocketBase REST API over `curl`
/// (matching the rest of PloitMalper's lightweight HTTP transport) and uses
/// `pbctl` for declarative schema management when available.
pub struct PocketBaseStorage {
    config: DatabaseConfig,
    token: String,
}

struct HttpResponse {
    status: u16,
    body: Value,
}

fn curl_request(
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<&Value>,
    query: &[(&str, &str)],
) -> Result<HttpResponse> {
    let mut command = Command::new("curl");
    command
        .arg("-sS")
        .arg("--max-time")
        .arg(REQUEST_TIMEOUT_S.to_string())
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-w")
        .arg("\n%{http_code}")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(token) = token {
        command
            .arg("-H")
            .arg(format!("Authorization: Bearer {}", token));
    }

    if !query.is_empty() {
        command.arg("-G");
        for (key, value) in query {
            command
                .arg("--data-urlencode")
                .arg(format!("{}={}", key, value));
        }
    }

    if body.is_some() {
        if method != "GET" {
            command.arg("-X").arg(method);
        }
        command.arg("--data-binary").arg("@-").stdin(Stdio::piped());
    } else if method != "GET" {
        command.arg("-X").arg(method);
    }

    command.arg(url);

    let mut child = command
        .spawn()
        .map_err(|e| AppError::Network(format!("failed to spawn curl: {e}")))?;

    if let Some(b) = body {
        if let Some(mut stdin) = child.stdin.take() {
            let payload = serde_json::to_string(b)?;
            stdin
                .write_all(payload.as_bytes())
                .map_err(|e| AppError::Network(format!("failed to write request body: {e}")))?;
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|e| AppError::Network(format!("failed to wait for curl: {e}")))?;

    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    let trimmed = raw.trim_end();
    let (body_str, status) = match trimmed.rsplit_once('\n') {
        Some((rest, code)) => (rest, code.trim().parse::<u16>().unwrap_or(0)),
        None => (trimmed, 0),
    };

    let body: Value = if body_str.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body_str).unwrap_or_else(|_| json!({ "raw": body_str }))
    };

    Ok(HttpResponse { status, body })
}

fn get_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn get_opt_str(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn get_vec(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn get_vec_value(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn get_json(value: &Value, key: &str) -> Value {
    value.get(key).cloned().unwrap_or(Value::Null)
}

fn as_json_object(value: &Value) -> Value {
    match value {
        Value::Null => Value::Object(Default::default()),
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// Record <-> model conversion
// ---------------------------------------------------------------------------

fn asset_to_record(asset: &Asset) -> Value {
    let mut record = serde_json::Map::new();
    record.insert("stable_id".into(), json!(asset.stable_id));
    record.insert("asset_type".into(), json!(asset.asset_type));
    record.insert("name".into(), json!(asset.name));
    if let Some(v) = &asset.ip {
        record.insert("ip".into(), json!(v));
    }
    if let Some(v) = &asset.fqdn {
        record.insert("fqdn".into(), json!(v));
    }
    if let Some(v) = &asset.reverse_dns {
        record.insert("reverse_dns".into(), json!(v));
    }
    record.insert("first_seen".into(), json!(asset.first_seen));
    record.insert("last_seen".into(), json!(asset.last_seen));
    record.insert("status".into(), json!(asset.status));
    record.insert("metadata".into(), as_json_object(&asset.metadata));
    Value::Object(record)
}

fn record_to_asset(value: &Value) -> Asset {
    Asset {
        stable_id: get_str(value, "stable_id"),
        asset_type: get_str(value, "asset_type"),
        name: get_str(value, "name"),
        ip: get_opt_str(value, "ip"),
        fqdn: get_opt_str(value, "fqdn"),
        reverse_dns: get_opt_str(value, "reverse_dns"),
        first_seen: get_str(value, "first_seen"),
        last_seen: get_str(value, "last_seen"),
        status: get_str(value, "status"),
        metadata: get_json(value, "metadata"),
    }
}

fn service_to_record(service: &Service) -> Value {
    let mut record = serde_json::Map::new();
    record.insert("stable_id".into(), json!(service.stable_id));
    record.insert("asset_id".into(), json!(service.asset_id));
    record.insert("port".into(), json!(service.port));
    record.insert("protocol".into(), json!(service.protocol));
    record.insert("service_name".into(), json!(service.service_name));
    if let Some(v) = &service.product {
        record.insert("product".into(), json!(v));
    }
    if let Some(v) = &service.version {
        record.insert("version".into(), json!(v));
    }
    if let Some(v) = &service.version_str {
        record.insert("version_str".into(), json!(v));
    }
    if let Some(v) = &service.banner {
        record.insert("banner".into(), json!(v));
    }
    record.insert("technologies".into(), json!(service.technologies));
    record.insert("cpes".into(), json!(service.cpes));
    record.insert("first_seen".into(), json!(service.first_seen));
    record.insert("last_seen".into(), json!(service.last_seen));
    record.insert("status".into(), json!(service.status));
    record.insert("metadata".into(), as_json_object(&service.metadata));
    Value::Object(record)
}

fn record_to_service(value: &Value) -> Service {
    Service {
        stable_id: get_str(value, "stable_id"),
        asset_id: get_str(value, "asset_id"),
        port: value
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(0),
        protocol: get_str(value, "protocol"),
        service_name: get_str(value, "service_name"),
        product: get_opt_str(value, "product"),
        version: get_opt_str(value, "version"),
        version_str: get_opt_str(value, "version_str"),
        banner: get_opt_str(value, "banner"),
        technologies: get_vec(value, "technologies"),
        cpes: get_vec(value, "cpes"),
        first_seen: get_str(value, "first_seen"),
        last_seen: get_str(value, "last_seen"),
        status: get_str(value, "status"),
        metadata: get_json(value, "metadata"),
    }
}

fn finding_to_record(finding: &Finding) -> Value {
    let mut record = serde_json::Map::new();
    record.insert("stable_id".into(), json!(finding.stable_id));
    record.insert("asset_id".into(), json!(finding.asset_id));
    if let Some(v) = &finding.service_id {
        record.insert("service_id".into(), json!(v));
    }
    record.insert("title".into(), json!(finding.title));
    record.insert("severity".into(), json!(finding.severity));
    record.insert("tool".into(), json!(finding.tool));
    if let Some(v) = &finding.target_url {
        record.insert("target_url".into(), json!(v));
    }
    if let Some(v) = &finding.detail {
        record.insert("detail".into(), json!(v));
    }
    if let Some(v) = &finding.detail_path {
        record.insert("detail_path".into(), json!(v));
    }
    if let Some(v) = &finding.reference {
        record.insert("reference".into(), json!(v));
    }
    record.insert("cves".into(), json!(finding.cves));
    record.insert("endpoints".into(), json!(finding.endpoints));
    record.insert("technologies".into(), json!(finding.technologies));
    record.insert("first_seen".into(), json!(finding.first_seen));
    record.insert("last_seen".into(), json!(finding.last_seen));
    record.insert("status".into(), json!(finding.status));
    if let Some(v) = &finding.exploitability {
        record.insert("exploitability".into(), json!(v));
    }
    record.insert("metadata".into(), as_json_object(&finding.metadata));
    Value::Object(record)
}

fn record_to_finding(value: &Value) -> Finding {
    Finding {
        stable_id: get_str(value, "stable_id"),
        asset_id: get_str(value, "asset_id"),
        service_id: get_opt_str(value, "service_id"),
        title: get_str(value, "title"),
        severity: get_str(value, "severity"),
        tool: get_str(value, "tool"),
        target_url: get_opt_str(value, "target_url"),
        detail: get_opt_str(value, "detail"),
        detail_path: get_opt_str(value, "detail_path"),
        reference: get_opt_str(value, "reference"),
        cves: get_vec(value, "cves"),
        endpoints: get_vec(value, "endpoints"),
        technologies: get_vec(value, "technologies"),
        first_seen: get_str(value, "first_seen"),
        last_seen: get_str(value, "last_seen"),
        status: get_str(value, "status"),
        exploitability: get_opt_str(value, "exploitability"),
        metadata: get_json(value, "metadata"),
    }
}

fn observation_to_record(observation: &Observation) -> Value {
    json!({
        "stable_id": observation.stable_id,
        "run_id": observation.run_id,
        "subject_type": observation.subject_type,
        "subject_id": observation.subject_id,
        "kind": observation.kind,
        "before": as_json_object(&observation.before),
        "after": as_json_object(&observation.after),
        "detail": observation.detail,
        "observed_at": observation.observed_at,
    })
}

fn record_to_observation(value: &Value) -> Observation {
    Observation {
        stable_id: get_str(value, "stable_id"),
        run_id: get_str(value, "run_id"),
        subject_type: get_str(value, "subject_type"),
        subject_id: get_str(value, "subject_id"),
        kind: get_str(value, "kind"),
        before: get_json(value, "before"),
        after: get_json(value, "after"),
        detail: get_str(value, "detail"),
        observed_at: get_str(value, "observed_at"),
    }
}

fn scan_run_to_record(run: &ScanRun) -> Value {
    json!({
        "stable_id": run.stable_id,
        "target": run.target,
        "folder": run.folder,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "tools": run.tools,
        "artifacts": run.artifacts,
        "content_hash": run.content_hash,
        "imported_at": run.imported_at,
        "stats": as_json_object(&run.stats),
    })
}

fn record_to_scan_run(value: &Value) -> ScanRun {
    ScanRun {
        stable_id: get_str(value, "stable_id"),
        target: get_str(value, "target"),
        folder: get_str(value, "folder"),
        started_at: get_opt_str(value, "started_at"),
        finished_at: get_opt_str(value, "finished_at"),
        tools: get_vec(value, "tools"),
        artifacts: get_vec_value(value, "artifacts"),
        content_hash: get_str(value, "content_hash"),
        imported_at: get_str(value, "imported_at"),
        stats: get_json(value, "stats"),
    }
}

impl PocketBaseStorage {
    pub fn new(config: &DatabaseConfig) -> Result<Self> {
        let mut url = config.pocketbase_url.trim().to_string();
        if url.is_empty() {
            url = "http://127.0.0.1:8090".to_string();
        }
        let url = url.trim_end_matches('/').to_string();
        Ok(Self {
            config: DatabaseConfig {
                pocketbase_url: url,
                ..config.clone()
            },
            token: config.pocketbase_token.clone(),
        })
    }

    fn base_url(&self) -> &str {
        &self.config.pocketbase_url
    }

    /// Current auth token, if a login has been performed.
    pub fn token(&self) -> String {
        self.token.clone()
    }

    /// Authenticate with the configured superuser credentials and cache a
    /// fresh token. Returns the token.
    pub fn login(&mut self) -> Result<String> {
        let email = self.config.pocketbase_admin_email.trim();
        let password = self.config.pocketbase_admin_password.trim();
        if email.is_empty() || password.is_empty() {
            return Err(AppError::Message(
                "PocketBase requires superuser credentials (email + password) to connect. \
                 Run `ploit-malper db_setup` to configure them."
                    .to_string(),
            ));
        }
        let url = format!(
            "{}/api/collections/_superusers/auth-with-password",
            self.base_url()
        );
        let body = json!({ "identity": email, "password": password });
        let resp = curl_request("POST", &url, None, Some(&body), &[])?;
        if resp.status != 200 && resp.status != 201 {
            return Err(AppError::Network(format!(
                "PocketBase authentication failed (HTTP {}): {}",
                resp.status, resp.body
            )));
        }
        let token = get_str(&resp.body, "token");
        if token.is_empty() {
            return Err(AppError::Network(format!(
                "PocketBase authentication response did not include a token: {}",
                resp.body
            )));
        }
        self.token = token.clone();
        self.config.pocketbase_token = token.clone();
        Ok(token)
    }

    /// Ensure we have a usable token, minting one from credentials if needed.
    fn ensure_token(&mut self) -> Result<String> {
        if !self.token.is_empty() {
            return Ok(self.token.clone());
        }
        self.login()
    }

    pub fn list_collection_names(&mut self) -> Result<Vec<String>> {
        let token = self.ensure_token()?;
        let url = format!("{}/api/collections", self.base_url());
        let resp = curl_request("GET", &url, Some(&token), None, &[("perPage", "200")])?;
        if resp.status != 200 {
            return Err(AppError::Network(format!(
                "Failed to list PocketBase collections (HTTP {}): {}",
                resp.status, resp.body
            )));
        }
        let names = resp
            .body
            .get("items")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|c| c.get("name").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(names)
    }

    fn find_record(
        &mut self,
        collection: &str,
        stable_id: &str,
    ) -> Result<Option<(String, Value)>> {
        let token = self.ensure_token()?;
        let url = format!("{}/api/collections/{}/records", self.base_url(), collection);
        let filter = format!("stable_id = \"{}\"", stable_id);
        let resp = curl_request(
            "GET",
            &url,
            Some(&token),
            None,
            &[("filter", &filter), ("perPage", "200")],
        )?;
        if resp.status != 200 {
            return Err(AppError::Network(format!(
                "Failed to query records in '{}' (HTTP {}): {}",
                collection, resp.status, resp.body
            )));
        }
        let items = resp
            .body
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(first) = items.into_iter().next() {
            let id = get_str(&first, "id");
            return Ok(Some((id, first)));
        }
        Ok(None)
    }

    fn create_record(&mut self, collection: &str, record: &Value) -> Result<()> {
        let token = self.ensure_token()?;
        let url = format!("{}/api/collections/{}/records", self.base_url(), collection);
        let resp = curl_request("POST", &url, Some(&token), Some(record), &[])?;
        if resp.status != 200 && resp.status != 201 {
            return Err(AppError::Network(format!(
                "Failed to create record in '{}' (HTTP {}): {}",
                collection, resp.status, resp.body
            )));
        }
        Ok(())
    }

    fn update_record(&mut self, collection: &str, record_id: &str, record: &Value) -> Result<()> {
        let token = self.ensure_token()?;
        let url = format!(
            "{}/api/collections/{}/records/{}",
            self.base_url(),
            collection,
            record_id
        );
        let resp = curl_request("PATCH", &url, Some(&token), Some(record), &[])?;
        if resp.status != 200 && resp.status != 204 {
            return Err(AppError::Network(format!(
                "Failed to update record in '{}' (HTTP {}): {}",
                collection, resp.status, resp.body
            )));
        }
        Ok(())
    }

    fn upsert(&mut self, collection: &str, stable_id: &str, record: &Value) -> Result<()> {
        if let Some((record_id, _)) = self.find_record(collection, stable_id)? {
            self.update_record(collection, &record_id, record)
        } else {
            self.create_record(collection, record)
        }
    }

    fn list_records(&mut self, collection: &str, filter: Option<&str>) -> Result<Vec<Value>> {
        let token = self.ensure_token()?;
        let url = format!("{}/api/collections/{}/records", self.base_url(), collection);
        let mut query: Vec<(&str, &str)> = vec![("perPage", "200")];
        if let Some(f) = filter {
            query.push(("filter", f));
        }
        let resp = curl_request("GET", &url, Some(&token), None, &query)?;
        if resp.status != 200 {
            return Err(AppError::Network(format!(
                "Failed to list records in '{}' (HTTP {}): {}",
                collection, resp.status, resp.body
            )));
        }
        Ok(resp
            .body
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// Create a collection directly via the REST API (fallback when pbctl is
    /// unavailable).
    fn create_collection_via_api(&mut self, name: &str) -> Result<()> {
        let token = self.ensure_token()?;
        let url = format!("{}/api/collections", self.base_url());
        let defs = schema::field_defs(name);
        let fields: Vec<Value> = defs.iter().map(|def| self.field_to_json(def)).collect();
        let body = json!({
            "name": name,
            "type": "base",
            "fields": fields,
        });
        let resp = curl_request("POST", &url, Some(&token), Some(&body), &[])?;
        if resp.status != 200 && resp.status != 201 {
            return Err(AppError::Network(format!(
                "Failed to create PocketBase collection '{}' (HTTP {}): {}",
                name, resp.status, resp.body
            )));
        }
        Ok(())
    }

    fn field_to_json(&self, def: &FieldDef) -> Value {
        let mut field = serde_json::Map::new();
        field.insert("name".to_string(), json!(def.name));
        field.insert("type".to_string(), json!(def.kind));
        field.insert("required".to_string(), json!(def.required));
        field.insert("unique".to_string(), json!(def.unique));
        field.insert("hidden".to_string(), json!(false));
        if def.kind == "select" {
            field.insert(
                "values".to_string(),
                json!(["ip", "hostname", "domain", "url"]),
            );
            field.insert("maxSelect".to_string(), json!(1));
        }
        Value::Object(field)
    }
}

impl Storage for PocketBaseStorage {
    fn kind(&self) -> &str {
        "pocketbase"
    }

    fn ping(&mut self) -> Result<bool> {
        let url = format!("{}/api/health", self.base_url());
        let resp = curl_request("GET", &url, None, None, &[])?;
        if resp.status == 200 {
            return Ok(true);
        }
        // Health may be unauthenticated; fall back to an authenticated call.
        match self.ensure_token() {
            Ok(token) => {
                let resp = curl_request("GET", &url, Some(&token), None, &[])?;
                Ok(resp.status == 200)
            }
            Err(e) => Err(e),
        }
    }

    fn ensure_schema(&mut self) -> Result<()> {
        // Pure REST API path — no pbctl required. Create any required
        // collections that are missing; leave existing ones untouched.
        let existing = self.list_collection_names()?;
        for name in collections::ALL {
            if !existing.iter().any(|n| n == name) {
                self.create_collection_via_api(name)?;
            }
        }
        Ok(())
    }

    fn upsert_scan_run(&mut self, run: &ScanRun) -> Result<()> {
        self.upsert(
            collections::SCAN_RUNS,
            &run.stable_id,
            &scan_run_to_record(run),
        )
    }

    fn get_scan_run(&mut self, run_id: &str) -> Result<Option<ScanRun>> {
        if let Some((_, record)) = self.find_record(collections::SCAN_RUNS, run_id)? {
            return Ok(Some(record_to_scan_run(&record)));
        }
        Ok(None)
    }

    fn list_scan_runs(&mut self) -> Result<Vec<ScanRun>> {
        let records = self.list_records(collections::SCAN_RUNS, None)?;
        Ok(records.iter().map(record_to_scan_run).collect())
    }

    fn upsert_asset(&mut self, asset: &Asset) -> Result<()> {
        self.upsert(
            collections::ASSETS,
            &asset.stable_id,
            &asset_to_record(asset),
        )
    }

    fn get_asset(&mut self, asset_id: &str) -> Result<Option<Asset>> {
        if let Some((_, record)) = self.find_record(collections::ASSETS, asset_id)? {
            return Ok(Some(record_to_asset(&record)));
        }
        Ok(None)
    }

    fn list_assets(&mut self) -> Result<Vec<Asset>> {
        let records = self.list_records(collections::ASSETS, None)?;
        Ok(records.iter().map(record_to_asset).collect())
    }

    fn upsert_service(&mut self, service: &Service) -> Result<()> {
        self.upsert(
            collections::SERVICES,
            &service.stable_id,
            &service_to_record(service),
        )
    }

    fn get_service(&mut self, service_id: &str) -> Result<Option<Service>> {
        if let Some((_, record)) = self.find_record(collections::SERVICES, service_id)? {
            return Ok(Some(record_to_service(&record)));
        }
        Ok(None)
    }

    fn list_services_for_asset(&mut self, asset_id: &str) -> Result<Vec<Service>> {
        let filter = format!("asset_id = \"{}\"", asset_id);
        let records = self.list_records(collections::SERVICES, Some(&filter))?;
        Ok(records.iter().map(record_to_service).collect())
    }

    fn list_all_services(&mut self) -> Result<Vec<Service>> {
        let records = self.list_records(collections::SERVICES, None)?;
        Ok(records.iter().map(record_to_service).collect())
    }

    fn upsert_finding(&mut self, finding: &Finding) -> Result<()> {
        self.upsert(
            collections::FINDINGS,
            &finding.stable_id,
            &finding_to_record(finding),
        )
    }

    fn get_finding(&mut self, finding_id: &str) -> Result<Option<Finding>> {
        if let Some((_, record)) = self.find_record(collections::FINDINGS, finding_id)? {
            return Ok(Some(record_to_finding(&record)));
        }
        Ok(None)
    }

    fn list_findings_for_asset(&mut self, asset_id: &str) -> Result<Vec<Finding>> {
        let filter = format!("asset_id = \"{}\"", asset_id);
        let records = self.list_records(collections::FINDINGS, Some(&filter))?;
        Ok(records.iter().map(record_to_finding).collect())
    }

    fn list_all_findings(&mut self) -> Result<Vec<Finding>> {
        let records = self.list_records(collections::FINDINGS, None)?;
        Ok(records.iter().map(record_to_finding).collect())
    }

    fn add_observation(&mut self, observation: &Observation) -> Result<()> {
        if self.get_observation(&observation.stable_id)?.is_some() {
            return Ok(());
        }
        self.create_record(
            collections::OBSERVATIONS,
            &observation_to_record(observation),
        )
    }

    fn get_observation(&mut self, obs_id: &str) -> Result<Option<Observation>> {
        if let Some((_, record)) = self.find_record(collections::OBSERVATIONS, obs_id)? {
            return Ok(Some(record_to_observation(&record)));
        }
        Ok(None)
    }

    fn list_observations_for(
        &mut self,
        subject_type: &str,
        subject_id: &str,
    ) -> Result<Vec<Observation>> {
        let filter = format!(
            "subject_type = \"{}\" && subject_id = \"{}\"",
            subject_type, subject_id
        );
        let records = self.list_records(collections::OBSERVATIONS, Some(&filter))?;
        Ok(records.iter().map(record_to_observation).collect())
    }

    fn list_all_observations(&mut self) -> Result<Vec<Observation>> {
        let records = self.list_records(collections::OBSERVATIONS, None)?;
        Ok(records.iter().map(record_to_observation).collect())
    }
}
