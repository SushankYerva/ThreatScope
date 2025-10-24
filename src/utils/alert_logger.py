from typing import Dict, Any, List, Iterable, Tuple
import sqlite3
import time
import json


class AlertLogger:
    """
    SQLite backed alert store.

    Table schema
    alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL,
        flow_key TEXT,
        label TEXT,
        score REAL
    )
    """

    def __init__(self, db_path: str = "threatscope_alerts.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self._init_db()

    def _init_db(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                flow_key TEXT,
                label TEXT,
                score REAL
            )
            """
        )
        self.conn.commit()

    def record_alert(
        self,
        flow_key: Tuple[str, str, int, int, str],
        prediction: Dict[str, Any],
        ts: float,
    ) -> None:
        """
        Insert one alert row
        """
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO alerts(ts, flow_key, label, score) VALUES (?,?,?,?)",
            (
                ts,
                json.dumps(flow_key),
                prediction.get("label", "unknown"),
                float(prediction.get("score", 0.0)),
            ),
        )
        self.conn.commit()

    def bulk_record(self, alerts: Iterable[Dict[str, Any]]) -> None:
        """
        Batch insert multiple alerts
        alerts is an iterable of dicts with keys ts, flow_key, prediction
        """
        cur = self.conn.cursor()
        rows = []
        for a in alerts:
            rows.append(
                (
                    a["ts"],
                    json.dumps(a["flow_key"]),
                    a["prediction"].get("label", "unknown"),
                    float(a["prediction"].get("score", 0.0)),
                )
            )
        cur.executemany(
            "INSERT INTO alerts(ts, flow_key, label, score) VALUES (?,?,?,?)",
            rows,
        )
        self.conn.commit()

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Return newest alerts first
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT ts, flow_key, label, score FROM alerts ORDER BY ts DESC LIMIT ?",
            (limit,),
        )
        out: List[Dict[str, Any]] = []
        for ts, flow_key_json, label, score in cur.fetchall():
            out.append(
                {
                    "timestamp": ts,
                    "flow_key": json.loads(flow_key_json),
                    "prediction": {
                        "label": label,
                        "score": score,
                    },
                }
            )
        return out
