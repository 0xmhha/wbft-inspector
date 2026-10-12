import json
import unittest
from pathlib import Path
from generate import semantic


class ProfileTest(unittest.TestCase):
    def test_observation_strength(self):
        expected = {
            "WBFT: handle COMMIT message": ("HEALTH", {"phase": "COMMIT", "action": "handle"}),
            "WBFT: broadcast COMMIT message": ("SEND", {"phase": "COMMIT", "cause": "broadcast"}),
            "WBFT: COMMIT payload": ("HEALTH", {"phase": "COMMIT"}),
            "WBFT: accepted new COMMIT messages": ("MSG_OUTCOME", {"phase": "COMMIT", "outcome": "ACCEPT"}),
            "WBFT: received quorum of COMMIT messages": ("QUORUM", {"phase": "COMMIT", "what": "COMMIT"}),
            "WBFT: received F+1 ROUND-CHANGE messages": ("QUORUM", {"phase": "ROUND-CHANGE", "what": "F_PLUS_ONE"}),
            "WBFT: TIMER CHANGING ROUND": ("TIMER_FIRE", {"timer": "round"}),
            "WBFT: TIMER CHANGED ROUND": ("HEALTH", {}),
            "WBFT: block proposal committed": ("NEW_HEAD", {"path": "sealed_locally"}),
        }
        for phrase, value in expected.items():
            with self.subTest(phrase=phrase):
                self.assertEqual(semantic(phrase), value)

    def test_all_locations_and_duplicate_calls(self):
        p = json.loads((Path(__file__).parents[2] / "profiles/gstable@740526d03.json").read_text())
        self.assertEqual(sum(len(e["locations"]) for e in p["entries"]), 184)
        self.assertEqual(p["source"]["rows"], 184)
        errors = [e for e in p["entries"] if e["msg"] == "WBFT: Error Raw()"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(errors[0]["locations"]), 4)
        templates = [e for e in p["entries"] if e.get("template")]
        self.assertEqual(len(templates), 1)
        self.assertEqual(len(templates[0]["locations"]), 2)


if __name__ == "__main__":
    unittest.main()
