
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import requests
from bs4 import BeautifulSoup
import logging
from urllib.parse import urljoin
import psycopg2
from psycopg2.extras import Json
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------
# Load environment variables
# -------------------------
load_dotenv()

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "Openssl"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASS", "623809"),
    "port": int(os.getenv("DB_PORT", 5432)),
}

BASE_URL = "https://openssl-library.org/news/secjson/"
START_URL = BASE_URL
TABLE_NAME = "staging_table"

# -------------------------
# Logging
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("openssl_scraper")

# -------------------------
# Create table if not exists
# -------------------------
def ensure_table():
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(f"""
            CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
                staging_id SERIAL PRIMARY KEY,
                vendor_name TEXT NOT NULL,
                source_url TEXT UNIQUE,
                raw_data JSONB NOT NULL,
                processed BOOLEAN DEFAULT FALSE,
                processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        cur.close()
        logger.info(f"Table '{TABLE_NAME}' is ready.")
    except Exception as e:
        logger.error(f"Error creating table: {e}")
    finally:
        if conn:
            conn.close()

# -------------------------
# Insert a single row
# -------------------------
def insert_row(raw_json, source_url):
    conn = None
    inserted = False
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute(f"""
            INSERT INTO {TABLE_NAME} (vendor_name, source_url, raw_data, processed)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (source_url) DO NOTHING;
        """, ("Openssl", source_url, Json(raw_json), False))
        if cur.rowcount > 0:
            inserted = True
            logger.info(f"Inserted advisory from {source_url}")
        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Database error: {e}")
    finally:
        if conn:
            conn.close()
    return inserted

# -------------------------
# Extract links
# -------------------------
def get_links():
    try:
        response = requests.get(START_URL, timeout=15)
        response.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Error fetching page: {e}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    main_tag = soup.find("main")
    if not main_tag:
        logger.warning("No <main> tag found")
        return []

    first_div = main_tag.find("div")
    if not first_div:
        logger.warning("No <div> inside <main> found")
        return []

    links = []
    for li in first_div.find_all("li"):
        a = li.find("a")
        if a and a.get("href"):
            href = urljoin(BASE_URL, a["href"])
            links.append(href)

    # Exclude the first link silently
    if links:
        links = links[1:]

    return links

# -------------------------
# Fetch advisory JSON
# -------------------------
def fetch_json(url):
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        data["advisory_url"] = url
        return data
    except Exception as e:
        logger.error(f"Failed to fetch/process {url}: {e}")
        return None

# -------------------------
# Worker function for threading
# -------------------------
def process_link(url):
    raw_json = fetch_json(url)
    if raw_json:
        return insert_row(raw_json, url)
    return False

# -------------------------
# Main
# -------------------------
def main():
    ensure_table()
    links = get_links()

    inserted_count = 0
    max_threads = 10  # Adjust based on your system
    with ThreadPoolExecutor(max_threads) as executor:
        futures = [executor.submit(process_link, link) for link in links]
        for future in as_completed(futures):
            try:
                if future.result():
                    inserted_count += 1
            except Exception as e:
                logger.error(f"Thread error: {e}")

    logger.info(f"Inserted {inserted_count} new records into the database.")

if __name__ == "__main__":
    main()
