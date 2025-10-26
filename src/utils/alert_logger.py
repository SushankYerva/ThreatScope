from typing import Dict, Any, List, Iterable, Tuple
import sqlite3
import time
import json
import os


class AlertLogger:
    """
    SQLite backed alert store.

    Schema:
    alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL,
        flow_key TEXT,
        prediction_json TEXT
    )

    We no longer keep a long-lived sqlite3.Connection on the object.
    We open a new short-lived connection per method call.
    This avoids cross-thread use problems with FastAPI.
    """

    def __init__(self, db_path: str = "threatscope_alerts.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        # check_same_thread=False lets us reuse the same file across threads
        # but we are actually opening per-call anyway
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self) -> None:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                flow_key TEXT,
                prediction_json TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def record_alert(
        self,
        flow_key: Tuple[str, str, int, int, str],
        prediction: Dict[str, Any],
        ts: float,
    ) -> None:
        """
        Insert one alert row.
        """
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO alerts(ts, flow_key, prediction_json) VALUES (?,?,?)",
            (
                ts,
                json.dumps(flow_key),
                json.dumps(prediction),
            ),
        )
        conn.commit()
        conn.close()

    def bulk_record(self, alerts: Iterable[Dict[str, Any]]) -> None:
        """
        Batch insert multiple alerts.
        alerts: iterable of dicts with keys ts, flow_key, prediction
        """
        conn = self._connect()
        cur = conn.cursor()
        rows = []
        for a in alerts:
            rows.append(
                (
                    a["ts"],
                    json.dumps(a["flow_key"]),
                    json.dumps(a["prediction"]),
                )
            )
        cur.executemany(
            "INSERT INTO alerts(ts, flow_key, prediction_json) VALUES (?,?,?)",
            rows,
        )
        conn.commit()
        conn.close()

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Return newest alerts first as JSON-serializable dicts.
        """
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT ts, flow_key, prediction_json FROM alerts ORDER BY ts DESC LIMIT ?",
            (limit,),
        )

        out: List[Dict[str, Any]] = []
        for ts, flow_key_json, prediction_json in cur.fetchall():
            try:
                flow_key = json.loads(flow_key_json)
            except Exception:
                flow_key = flow_key_json  # fallback string

            try:
                prediction = json.loads(prediction_json)
            except Exception:
                prediction = {"error": "bad_prediction_json", "raw": prediction_json}

            out.append(
                {
                    "timestamp": ts,
                    "flow_key": flow_key,
                    "prediction": prediction,
                }
            )
        conn.close()
        return out
