import hashlib
import json
import sqlite3
import time

from database_manager import DB_PATH


class BlockchainLedger:
    def __init__(self):
        self.chain = []
        self._load_or_create_chain()

    def _compute_hash(self, block):
        block_copy = dict(block)
        block_copy.pop("hash", None)
        payload = json.dumps(block_copy, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _load_or_create_chain(self):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # ✅ PERMANENT FIX - Table pehle banao, phir read karo
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blockchain_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER,
                timestamp REAL,
                user_id TEXT,
                action TEXT,
                details TEXT,
                previous_hash TEXT,
                hash TEXT
            )
        ''')
        conn.commit()

        cursor.execute(
            """
            SELECT block_index, timestamp, user_id, action, details, previous_hash, hash
            FROM blockchain_log
            ORDER BY block_index ASC
            """
        )
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            self.log_event("SYSTEM", "GENESIS", "Genesis block initialized")
            return

        for row in rows:
            self.chain.append(
                {
                    "index": row[0],
                    "timestamp": row[1],
                    "user_id": row[2],
                    "action": row[3],
                    "details": row[4],
                    "previous_hash": row[5],
                    "hash": row[6],
                }
            )

    def log_event(self, user_id, action, details):
        previous_hash = self.chain[-1]["hash"] if self.chain else "0"
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "user_id": str(user_id),
            "action": action,
            "details": details,
            "previous_hash": previous_hash,
        }
        block["hash"] = self._compute_hash(block)
        self.chain.append(block)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO blockchain_log
            (block_index, timestamp, user_id, action, details, previous_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                block["index"],
                block["timestamp"],
                block["user_id"],
                block["action"],
                block["details"],
                block["previous_hash"],
                block["hash"],
            ),
        )
        conn.commit()
        conn.close()
        return block

    def get_logs(self, user_id):
        user_id = str(user_id)
        return [b for b in self.chain if b["user_id"] == user_id or b["user_id"] == "SYSTEM"]

    def verify_chain(self):
        for i, block in enumerate(self.chain):
            expected_hash = self._compute_hash(block)
            if expected_hash != block["hash"]:
                return False
            if i == 0:
                if block["previous_hash"] != "0":
                    return False
            else:
                if block["previous_hash"] != self.chain[i - 1]["hash"]:
                    return False
        return True