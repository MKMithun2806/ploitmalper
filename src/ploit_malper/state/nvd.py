"""NVD API client for CVE enrichment with CVSS scores and descriptions."""

import json
import time
import requests
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from rich.console import Console

from ploit_malper.state.config import NVD_CACHE_FILE

console = Console()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY = 0.6


@dataclass
class NVDCVEInfo:
    cve_id: str
    description: str
    cvss_v3_score: Optional[float]
    cvss_v3_severity: Optional[str]
    cvss_v2_score: Optional[float]
    published: str
    last_modified: str
    references: list[str]


class NVDClient:
    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key
        self._cache: dict[str, dict] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        if NVD_CACHE_FILE.exists():
            try:
                raw = NVD_CACHE_FILE.read_text(encoding="utf-8")
                self._cache = json.loads(raw)
            except (json.JSONDecodeError, OSError):
                self._cache = {}

    def _save_cache(self) -> None:
        NVD_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        NVD_CACHE_FILE.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")

    def _get_cached(self, cve_id: str) -> Optional[dict]:
        return self._cache.get(cve_id)

    def _cache_result(self, cve_id: str, data: dict) -> None:
        self._cache[cve_id] = data
        self._save_cache()

    def _fetch_cve(self, cve_id: str, use_key: bool = True) -> Optional[requests.Response]:
        headers: dict[str, str] = {"User-Agent": "PloitMalper/0.1.0"}
        if use_key and self.api_key:
            headers["apiKey"] = self.api_key

        resp = requests.get(
            f"{NVD_API_BASE}?cveId={cve_id}",
            headers=headers,
            timeout=15,
        )

        if resp.status_code == 404 and use_key and self.api_key:
            headers_no_key = {"User-Agent": "PloitMalper/0.1.0"}
            resp = requests.get(
                f"{NVD_API_BASE}?cveId={cve_id}",
                headers=headers_no_key,
                timeout=15,
            )

        return resp

    def lookup_cve(self, cve_id: str) -> Optional[NVDCVEInfo]:
        cached = self._get_cached(cve_id)
        if cached:
            return NVDCVEInfo(
                cve_id=cached["cve_id"],
                description=cached["description"],
                cvss_v3_score=cached.get("cvss_v3_score"),
                cvss_v3_severity=cached.get("cvss_v3_severity"),
                cvss_v2_score=cached.get("cvss_v2_score"),
                published=cached.get("published", ""),
                last_modified=cached.get("last_modified", ""),
                references=cached.get("references", []),
            )

        time.sleep(NVD_RATE_LIMIT_DELAY)

        try:
            resp = self._fetch_cve(cve_id)
            if resp is None or resp.status_code != 200:
                return None

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            cve_data = vulnerabilities[0].get("cve", {})
            descriptions = cve_data.get("descriptions", [])
            desc_text = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break
            if not desc_text and descriptions:
                desc_text = descriptions[0].get("value", "")

            metrics = cve_data.get("metrics", {})
            cvss_v3_score = None
            cvss_v3_severity = None
            cvss_v2_score = None

            for metric_group in metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", [])):
                cvss_data = metric_group.get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_severity = cvss_data.get("baseSeverity")
                break

            if cvss_v3_score is None and metrics.get("cvssMetricV2"):
                cvss_v2_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

            references = []
            for ref in cve_data.get("references", [])[:5]:
                url = ref.get("url", "")
                if url:
                    references.append(url)

            result = {
                "cve_id": cve_id,
                "description": desc_text,
                "cvss_v3_score": cvss_v3_score,
                "cvss_v3_severity": cvss_v3_severity,
                "cvss_v2_score": cvss_v2_score,
                "published": cve_data.get("published", ""),
                "last_modified": cve_data.get("lastModified", ""),
                "references": references,
            }

            self._cache_result(cve_id, result)

            return NVDCVEInfo(
                cve_id=cve_id,
                description=desc_text,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_severity=cvss_v3_severity,
                cvss_v2_score=cvss_v2_score,
                published=cve_data.get("published", ""),
                last_modified=cve_data.get("lastModified", ""),
                references=references,
            )

        except requests.RequestException as e:
            console.print(f"[!] NVD API error for {cve_id}: {e}")
            return None
        except Exception as e:
            console.print(f"[!] Unexpected error looking up {cve_id}: {e}")
            return None

    def enrich_records(self, records: list[dict]) -> list[dict]:
        console.print("[+] Enriching CVEs via NVD API...")
        enriched_count = 0
        cache_hits = 0
        not_found_count = 0

        for record in records:
            cve = record.get("cve")
            if not cve:
                continue

            cached = self._get_cached(cve)
            if cached:
                cache_hits += 1
                record["nvd_description"] = cached.get("description", "")
                record["nvd_cvss_v3"] = cached.get("cvss_v3_score")
                record["nvd_cvss_v3_severity"] = cached.get("cvss_v3_severity")
                record["nvd_published"] = cached.get("published", "")
                record["nvd_references"] = cached.get("references", [])
                continue

            nvd_info = self.lookup_cve(cve)
            if nvd_info:
                enriched_count += 1
                record["nvd_description"] = nvd_info.description
                record["nvd_cvss_v3"] = nvd_info.cvss_v3_score
                record["nvd_cvss_v3_severity"] = nvd_info.cvss_v3_severity
                record["nvd_published"] = nvd_info.published
                record["nvd_references"] = nvd_info.references

                if nvd_info.cvss_v3_severity:
                    record["severity"] = nvd_info.cvss_v3_severity.lower()
            else:
                not_found_count += 1

        console.print(f"[+] NVD enrichment complete: {enriched_count} fetched, {cache_hits} from cache, {not_found_count} not found")
        return records
