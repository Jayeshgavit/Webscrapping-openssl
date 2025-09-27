#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import psycopg2
import json
import logging
from datetime import datetime
from dotenv import load_dotenv

# -------------------------
# Setup logging & env
# -------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-8s | %(message)s")
logger = logging.getLogger("normalize_openssl")

load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Openssl"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "623809"),
    "port": int(os.getenv("DB_PORT", 5432)),
}

# -------------------------
# Table names (configurable)
# -------------------------
TABLE_STAGING = "staging_table"
TABLE_VENDORS = "vendors"
TABLE_ADVISORIES = "advisories"
TABLE_CVES = "cves"
TABLE_ADV_CVE_MAP = "advisory_cves_map"
TABLE_CVE_PRODUCT_MAP = "cve_product_map"

# -------------------------
# Ensure Tables Exist
# -------------------------
def ensure_tables(conn):
    cur = conn.cursor()

    # Vendors
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_VENDORS} (
            vendor_id SERIAL PRIMARY KEY,
            vendor_name TEXT NOT NULL UNIQUE
        );
    """)

    # Advisories
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_ADVISORIES} (
            advisory_id TEXT PRIMARY KEY,
            vendor_id INTEGER REFERENCES {TABLE_VENDORS}(vendor_id),
            title TEXT,
            severity TEXT,
            initial_release_date DATE,
            latest_update_date DATE,
            advisory_url TEXT
        );
    """)

    # CVEs
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_CVES} (
            cve_id TEXT PRIMARY KEY,
            cwe_id TEXT,
            description TEXT,
            severity TEXT,
            cvss_score NUMERIC(3,1),
            cvss_vector TEXT,
            initial_release_date DATE,
            latest_update_date DATE,
            reference_url TEXT
        );
    """)

    # Advisory ↔ CVE mapping
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_ADV_CVE_MAP} (
            advisory_id TEXT REFERENCES {TABLE_ADVISORIES}(advisory_id) ON DELETE CASCADE,
            cve_id TEXT REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
            PRIMARY KEY (advisory_id, cve_id)
        );
    """)

    # CVE → Product mapping
    cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_CVE_PRODUCT_MAP} (
            qs_id SERIAL NOT NULL UNIQUE,
            cve_id TEXT PRIMARY KEY REFERENCES {TABLE_CVES}(cve_id) ON DELETE CASCADE,
            affected_products_cpe JSONB,
            recommendations TEXT
        );
    """)
    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_cpe_gin ON {TABLE_CVE_PRODUCT_MAP} USING GIN (affected_products_cpe);")

    conn.commit()
    logger.info("Normalized tables created/checked.")

# -------------------------
# Vendor helper
# -------------------------
def get_or_create_vendor(conn, vendor_name="Openssl"):
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT vendor_id FROM {TABLE_VENDORS} WHERE LOWER(vendor_name) = %s;",
            (vendor_name.lower(),)
        )
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute(
            f"INSERT INTO {TABLE_VENDORS} (vendor_name) VALUES (%s) RETURNING vendor_id;",
            (vendor_name,)
        )
        vendor_id = cur.fetchone()[0]
    conn.commit()
    return vendor_id

# -------------------------
# Advisory ID generator
# -------------------------
def generate_advisory_id(cve_id: str, staging_id: int) -> str:
    """Use Openssl-CVE if cve_id exists, else fallback to staging_id"""
    if cve_id:
        return f"Openssl-{cve_id}"
    return f"Openssl-ADV-{staging_id}"

# -------------------------
# Recursive title search
# -------------------------
def extract_title(data):
    """Recursively find 'title' anywhere in JSON"""
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() == "title" and isinstance(v, str) and v.strip():
                return v.strip()
            found = extract_title(v)
            if found:
                return found
    elif isinstance(data, list):
        for item in data:
            found = extract_title(item)
            if found:
                return found
    return None

# -------------------------
# Main normalization
# -------------------------
def process_staging_data(conn):
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT staging_id, vendor_name, raw_data
            FROM {TABLE_STAGING}
            WHERE LOWER(vendor_name) = 'openssl' AND processed IS FALSE;
            """
        )
        rows = cur.fetchall()

    logger.info("Found %d staging rows to normalize.", len(rows))

    counts = {"advisories": 0, "cves": 0, "mappings": 0, "products": 0, "staging_marked": 0}

    for staging_id, vendor_name, raw_json in rows:
        try:
            data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            cna = data.get("containers", {}).get("cna", {})
            cve_metadata = data.get("cveMetadata", {})

            cve_id = cve_metadata.get("cveId") or None
            vendor_id = get_or_create_vendor(conn, vendor_name)
            advisory_id = generate_advisory_id(cve_id, staging_id)

            # Title: cna.title or recursively in raw JSON
            title = cna.get("title") or extract_title(data) or None

            # Description
            desc = None
            if cna.get("descriptions"):
                for d in cna["descriptions"]:
                    if d.get("lang") == "en":
                        desc = d.get("value") or None
                        break

            # Severity
            advisory_severity = None
            cve_severity = None
            if cna.get("metrics"):
                cve_severity = cna["metrics"][0].get("other", {}).get("content", {}).get("text") or None

            # Dates
            initial_release_date = None
            date_public_str = cna.get("datePublic")
            if date_public_str:
                try:
                    initial_release_date = datetime.fromisoformat(date_public_str.replace("Z", "+00:00")).date()
                except Exception:
                    initial_release_date = None
            latest_updated_date = None  # CVE dates remain NULL

            # CWE IDs (combine multiple)
            cwe_ids = []
            for pt in cna.get("problemTypes", []):
                for di in pt.get("descriptions", []):
                    cwe_val = di.get("cweId")
                    if cwe_val:
                        cwe_ids.append(cwe_val)
            cwe_id = ",".join(cwe_ids) if cwe_ids else None

            # References
            references = cna.get("references", [])
            reference_url = None
            if references:
                formatted = []
                for r in references:
                    name = (r.get("name") or "").strip()
                    link = (r.get("url") or "").strip()
                    if name and link:
                        formatted.append(f"{name}: {link}")
                    elif link:
                        formatted.append(link)
                reference_url = ", ".join(formatted) if formatted else None

            advisory_url = data.get("advisory_url") or None

            cur = conn.cursor()
            try:
                # Insert advisory
                cur.execute(
                    f"""
                    INSERT INTO {TABLE_ADVISORIES}
                    (advisory_id, vendor_id, title, severity, initial_release_date, latest_update_date, advisory_url)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (advisory_id) DO NOTHING;
                    """,
                    (advisory_id, vendor_id, title, advisory_severity, initial_release_date, latest_updated_date, advisory_url)
                )
                counts["advisories"] += 1

                # Insert CVE
                cur.execute(
                    f"""
                    INSERT INTO {TABLE_CVES}
                    (cve_id, cwe_id, description, severity, cvss_score, cvss_vector, initial_release_date, latest_update_date, reference_url)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO NOTHING;
                    """,
                    (cve_id, cwe_id, desc, cve_severity, None, None, None, None, reference_url)
                )
                counts["cves"] += 1

                # Mapping advisory <-> CVE
                if cve_id:
                    cur.execute(
                        f"""
                        INSERT INTO {TABLE_ADV_CVE_MAP} (advisory_id, cve_id)
                        VALUES (%s, %s)
                        ON CONFLICT (advisory_id, cve_id) DO NOTHING;
                        """,
                        (advisory_id, cve_id)
                    )
                    counts["mappings"] += 1

                # Product mapping
                cur.execute(
                    f"""
                    INSERT INTO {TABLE_CVE_PRODUCT_MAP} (cve_id, affected_products_cpe, recommendations)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (cve_id) DO NOTHING;
                    """,
                    (cve_id, None, None)
                )
                counts["products"] += 1

                # Mark staging row processed
                cur.execute(
                    f"""
                    UPDATE {TABLE_STAGING}
                    SET processed = TRUE, processed_at = NOW()
                    WHERE staging_id = %s;
                    """,
                    (staging_id,)
                )
                counts["staging_marked"] += 1

                conn.commit()
                cur.close()
                logger.info("staging_id %s normalized -> advisory %s", staging_id, advisory_id)

            except Exception as row_err:
                conn.rollback()
                cur.close()
                logger.exception("Failed processing staging_id %s — rolled back: %s", staging_id, row_err)

        except Exception as e:
            logger.exception("Unexpected error for staging_id %s: %s", staging_id, e)
            try:
                conn.rollback()
            except Exception:
                pass
            continue

    logger.info("Done. inserted advisories=%d cves=%d mappings=%d products=%d staged_marked=%d",
                counts["advisories"], counts["cves"], counts["mappings"], counts["products"], counts["staging_marked"])

# -------------------------
# Entry point
# -------------------------
def main():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        ensure_tables(conn)
        process_staging_data(conn)
    finally:
        try:
            conn.close()
        except Exception:
            pass
    logger.info("Finished normalization run.")

if __name__ == "__main__":
    main()
