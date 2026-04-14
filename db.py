"""
db.py — Loads superstore_sales.csv into a SQLite database.

Single table: superstore_sales
Mirrors the famous Kaggle 'Sample - Superstore' dataset exactly.

Schema exposed to the LLM (customer_name omitted — PII defence-in-depth):
  row_id, order_id, order_date, ship_mode, segment,
  city, state, country, region, category, sub_category,
  product_name, sales, quantity, discount, profit
"""

import sqlite3
import pandas as pd
from pathlib import Path

DB_PATH  = "superstore.db"
CSV_PATH = "superstore_sales.csv"

# What the LLM is allowed to know about (customer_name intentionally excluded)
SCHEMA_FOR_LLM = """
Table: superstore_sales

Columns you may query:
  row_id        INTEGER   - unique row identifier
  order_id      TEXT      - e.g. US-2021-100001
  order_date    TEXT      - YYYY-MM-DD format
  ship_mode     TEXT      - 'Standard Class' | 'Second Class' | 'First Class' | 'Same Day'
  segment       TEXT      - 'Consumer' | 'Corporate' | 'Home Office'
  city          TEXT
  state         TEXT
  country       TEXT
  region        TEXT      - 'West' | 'East' | 'Central' | 'South'
  category      TEXT      - 'Furniture' | 'Office Supplies' | 'Technology'
  sub_category  TEXT      - e.g. 'Chairs', 'Phones', 'Binders' …
  product_name  TEXT
  sales         REAL      - revenue in USD
  quantity      INTEGER
  discount      REAL      - 0.0 to 0.5
  profit        REAL      - can be negative

Database engine: SQLite  (use strftime() for date math, not DATE_FORMAT)
"""

# Columns that exist in DB but are NEVER shown to LLM or UI
SENSITIVE_COLUMNS = {"customer_name"}


def get_connection(read_only: bool = True) -> sqlite3.Connection:
    """
    Return a SQLite connection.
    read_only=True uses URI mode=ro — enforced at OS/VFS level,
    not just application logic (this is G8 Read-Only Connection).
    """
    if not Path(DB_PATH).exists():
        _load_csv_to_db()

    if read_only:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, check_same_thread=False)
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)

    conn.row_factory = sqlite3.Row
    return conn


def setup_db() -> None:
    """Public entry point — call on app startup."""
    if not Path(DB_PATH).exists():
        _load_csv_to_db()


def _load_csv_to_db() -> None:
    """Read CSV and write to SQLite — runs once on first launch."""
    if not Path(CSV_PATH).exists():
        raise FileNotFoundError(
            f"'{CSV_PATH}' not found. Run: python generate_data.py"
        )

    df = pd.read_csv(CSV_PATH)
    conn = sqlite3.connect(DB_PATH)
    df.to_sql("superstore_sales", conn, if_exists="replace", index=False)
    conn.close()
    print(f"✅  Loaded {len(df)} rows from {CSV_PATH} → {DB_PATH}")
