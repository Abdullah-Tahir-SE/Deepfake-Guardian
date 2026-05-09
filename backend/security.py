import hashlib
import json
import time

def hash_password(password):
    """Returns SHA-256 hash of the given password string."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(stored_hash, provided_password):
    """Verifies a plain text password against expected SHA-256 hash."""
    return stored_hash == hash_password(provided_password)

class BlockchainLedger:
    def __init__(self):
        """Initializes a simple blockchain-like ledger for secure logging"""
        self.chain = []
        # Create Genesis Block
        self._add_block({"event": "Genesis Block Initialized", "timestamp": time.time()})

    def _add_block(self, data):
        """Creates a hash-linked block and appends it to the chain."""
        previous_hash = self.chain[-1]["hash"] if self.chain else "0"
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time.time(),
            "data": data,
            "previous_hash": previous_hash
        }
        # Produce SHA-256 hash of the dictionary block
        block_str = json.dumps(block, sort_keys=True).encode('utf-8')
        block_hash = hashlib.sha256(block_str).hexdigest()
        
        block["hash"] = block_hash
        self.chain.append(block)

    def record_access_attempt(self, username, success, details=""):
        """Records a gateway access attempt into the ledger."""
        self._add_block({
            "event": "Gateway Access Attempt",
            "username": username,
            "success": success,
            "details": details
        })

def generate_receipt(username, scan_results):
    """Generates a verifiable digital receipt for a successful scan."""
    timestamp = time.time()
    receipt_data = f"{username}|{timestamp}|{scan_results.get('confidence', 0)}"
    receipt_id = hashlib.sha256(receipt_data.encode('utf-8')).hexdigest()[:16]
    
    return {
        "user": username,
        "timestamp": timestamp,
        "scan_status": "Verified - Liveness Confirmed",
        "confidence": scan_results.get("confidence", 0),
        "receipt_id": receipt_id
    }
