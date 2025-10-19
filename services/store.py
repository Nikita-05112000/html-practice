import json
import os
from typing import Any, Dict


class Store:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(self.path):
            self.write_state({'stats': {
                'risky_emails_detected': 0,
                'urls_scanned': 0,
                'trainings_completed': 0,
                'alerts': []
            }})

    def read_state(self) -> Dict[str, Any]:
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {'stats': {
                'risky_emails_detected': 0,
                'urls_scanned': 0,
                'trainings_completed': 0,
                'alerts': []
            }}

    def write_state(self, data: Dict[str, Any]) -> None:
        tmp_path = f"{self.path}.tmp"
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, self.path)
