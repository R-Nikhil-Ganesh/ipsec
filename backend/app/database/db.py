"""
SQLite Storage Layer for IPsec Sentinel
Persists analysis runs, security fingerprints, baseline snapshots, and configuration drift histories.
"""
import sqlite3
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sentinel.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyses (
        id TEXT PRIMARY KEY,
        filename TEXT,
        created_at TEXT,
        dataset_type TEXT,
        status TEXT,
        overall_score INTEGER,
        grade TEXT,
        fingerprint_json TEXT,
        findings_json TEXT,
        score_breakdown_json TEXT,
        traffic_classification_json TEXT,
        anomalies_json TEXT,
        metadata_privacy_json TEXT,
        drift_json TEXT,
        risk_graph_json TEXT,
        packet_stats_json TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS baselines (
        id TEXT PRIMARY KEY,
        name TEXT,
        created_at TEXT,
        fingerprint_json TEXT,
        config_json TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_analysis(data: Dict[str, Any]):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR REPLACE INTO analyses (
        id, filename, created_at, dataset_type, status,
        overall_score, grade, fingerprint_json, findings_json,
        score_breakdown_json, traffic_classification_json, anomalies_json,
        metadata_privacy_json, drift_json, risk_graph_json, packet_stats_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["id"],
        data["filename"],
        data.get("analyzed_at", datetime.utcnow().isoformat()),
        data.get("dataset_type", "PCAP Upload"),
        data.get("status", "Analyzed"),
        data["risk_score"]["overall_score"],
        data["risk_score"]["posture_grade"],
        json.dumps(data["fingerprint"]),
        json.dumps(data["findings"]),
        json.dumps(data["risk_score"]),
        json.dumps(data["traffic_classification"]),
        json.dumps(data["anomalies"]),
        json.dumps(data["metadata_privacy"]),
        json.dumps(data["drift"]),
        json.dumps(data["risk_graph"]),
        json.dumps(data["packet_stats"])
    ))

    conn.commit()
    conn.close()


def get_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "filename": row[1],
        "analyzed_at": row[2],
        "dataset_type": row[3],
        "status": row[4],
        "overall_score": row[5],
        "grade": row[6],
        "fingerprint": json.loads(row[7]),
        "findings": json.loads(row[8]),
        "risk_score": json.loads(row[9]),
        "traffic_classification": json.loads(row[10]),
        "anomalies": json.loads(row[11]),
        "metadata_privacy": json.loads(row[12]),
        "drift": json.loads(row[13]),
        "risk_graph": json.loads(row[14]),
        "packet_stats": json.loads(row[15])
    }


def list_analyses() -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, filename, created_at, dataset_type, status, overall_score, grade
    FROM analyses ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "filename": r[1],
            "analyzed_at": r[2],
            "dataset_type": r[3],
            "status": r[4],
            "overall_score": r[5],
            "grade": r[6]
        }
        for r in rows
    ]


def save_baseline_fingerprint(baseline_id: str, name: str, fp_dict: Dict[str, Any]):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR REPLACE INTO baselines (id, name, created_at, fingerprint_json, config_json)
    VALUES (?, ?, ?, ?, ?)
    """, (
        baseline_id,
        name,
        datetime.utcnow().isoformat(),
        json.dumps(fp_dict),
        json.dumps({})
    ))

    conn.commit()
    conn.close()


def get_latest_baseline_fingerprint() -> Optional[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT fingerprint_json, name FROM baselines ORDER BY created_at DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return json.loads(row[0])
