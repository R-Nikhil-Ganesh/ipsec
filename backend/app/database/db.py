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

    # --- Temporal Security Twin additions ---
    # Group repeat analyses of the "same" tunnel under a stable tunnel_id so
    # historical state can be tracked over time (see app/temporal/state_tracker.py).
    cursor.execute("PRAGMA table_info(analyses)")
    existing_cols = [r[1] for r in cursor.fetchall()]
    if "tunnel_id" not in existing_cols:
        cursor.execute("ALTER TABLE analyses ADD COLUMN tunnel_id TEXT")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        event_id TEXT PRIMARY KEY,
        tunnel_id TEXT,
        analysis_id TEXT,
        timestamp TEXT,
        event_type TEXT,
        severity TEXT,
        source TEXT,
        previous_value TEXT,
        current_value TEXT,
        evidence TEXT,
        affected_component TEXT,
        confidence REAL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_simulations (
        id TEXT PRIMARY KEY,
        analysis_id TEXT,
        plan_id TEXT,
        created_at TEXT,
        request_json TEXT,
        result_json TEXT
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
        "packet_stats": json.loads(row[15]),
        "tunnel_id": row[16] if len(row) > 16 else None
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


# =====================================================================
# Temporal Security Twin — tunnel grouping, historical snapshots, events
# =====================================================================

def set_tunnel_id(analysis_id: str, tunnel_id: str):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE analyses SET tunnel_id = ? WHERE id = ?", (tunnel_id, analysis_id))
    conn.commit()
    conn.close()


def get_tunnel_analyses(tunnel_id: str) -> List[Dict[str, Any]]:
    """All full analysis rows for a tunnel, oldest first (the tunnel's historical state series)."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses WHERE tunnel_id = ? ORDER BY created_at ASC", (tunnel_id,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
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
            "packet_stats": json.loads(row[15]),
            "tunnel_id": row[16] if len(row) > 16 else None
        })
    return results


def delete_tunnel_history(tunnel_id: str):
    """Wipes all analyses/events for a tunnel_id. Used to make the temporal demo scenario
    idempotent — reloading it always produces exactly one fresh 5-stage history."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses WHERE tunnel_id = ?", (tunnel_id,))
    cursor.execute("DELETE FROM security_events WHERE tunnel_id = ?", (tunnel_id,))
    conn.commit()
    conn.close()


def replace_tunnel_events(tunnel_id: str, events: List[Dict[str, Any]]):
    """Recomputes are cheap (few snapshots), so we replace the full event set for a tunnel each time."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM security_events WHERE tunnel_id = ?", (tunnel_id,))
    for e in events:
        cursor.execute("""
        INSERT OR REPLACE INTO security_events (
            event_id, tunnel_id, analysis_id, timestamp, event_type, severity,
            source, previous_value, current_value, evidence, affected_component, confidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            e["event_id"], e["tunnel_id"], e["analysis_id"], e["timestamp"], e["event_type"], e["severity"],
            e["source"], e.get("previous_value"), e.get("current_value"), e["evidence"],
            e["affected_component"], e["confidence"]
        ))
    conn.commit()
    conn.close()


def get_tunnel_events(tunnel_id: str) -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_events WHERE tunnel_id = ? ORDER BY timestamp ASC", (tunnel_id,))
    rows = cursor.fetchall()
    conn.close()
    cols = ["event_id", "tunnel_id", "analysis_id", "timestamp", "event_type", "severity",
            "source", "previous_value", "current_value", "evidence", "affected_component", "confidence"]
    return [dict(zip(cols, row)) for row in rows]


def save_remediation_simulation(sim_id: str, analysis_id: str, plan_id: str, request_dict: Dict[str, Any], result_dict: Dict[str, Any]):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO remediation_simulations (id, analysis_id, plan_id, created_at, request_json, result_json)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        sim_id, analysis_id, plan_id, datetime.utcnow().isoformat(),
        json.dumps(request_dict), json.dumps(result_dict)
    ))
    conn.commit()
    conn.close()
