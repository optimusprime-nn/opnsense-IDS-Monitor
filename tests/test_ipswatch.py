import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipswatch import collect, config, detect, engine  # noqa: E402
from ipswatch.normalize import from_syslog_line, normalize  # noqa: E402
from ipswatch.store import Store  # noqa: E402

T0 = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def eve(src, dst, dport, sig, sid, sev=2, cat="Misc activity", action="allowed", t=0):
    return {
        "timestamp": (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "flow_id": 1000 + t, "in_iface": "igb0", "event_type": "alert",
        "src_ip": src, "src_port": 40000 + t % 1000, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
        "alert": {"action": action, "gid": 1, "signature_id": sid, "rev": 1,
                  "signature": sig, "category": cat, "severity": sev},
    }


def cfg_():
    return config.load(None)


class NormalizeTests(unittest.TestCase):
    def test_raw_eve(self):
        ev = normalize(eve("203.0.113.7", "192.168.1.10", 22, "ET SCAN SSH", 2001219))
        self.assertEqual(ev["sid"], 2001219)
        self.assertEqual(ev["ts"], "2026-10-19T12:00:00.000000+00:00")
        self.assertEqual(ev["action"], "allowed")

    def test_opnsense_api_flattened(self):
        row = {"timestamp": "2026-10-19T12:00:00.000000+0000", "src_ip": "1.2.3.4", "dest_ip": "10.0.0.5",
               "dest_port": 3389, "alert": "ET SCAN RDP", "alert_sid": 2023753, "alert_action": "blocked"}
        ev = normalize(row)
        self.assertEqual(ev["signature"], "ET SCAN RDP")
        self.assertEqual(ev["action"], "blocked")

    def test_syslog_line(self):
        line = "<14>Oct 19 12:00:00 fw suricata[1234]: " + json.dumps(eve("1.1.1.1", "10.0.0.1", 80, "x", 1))
        self.assertIsNotNone(normalize(from_syslog_line(line)))

    def test_non_alert_ignored(self):
        self.assertIsNone(normalize({"event_type": "flow", "src_ip": "1.1.1.1"}))


class DetectTests(unittest.TestCase):
    def run_events(self, raws, fw=None):
        c = cfg_()
        evs = [normalize(r) for r in raws]
        return {f["key"]: f for f in detect.analyze(evs, c.detect, fw)}

    def test_single_blocked_low_alert_not_flagged(self):
        out = self.run_events([eve("198.51.100.1", "192.168.1.10", 80, "ET SCAN probe", 1, sev=3, action="blocked")])
        self.assertEqual(out, {})

    def test_unblocked_high_sev_to_ssh_is_unwanted_access(self):
        out = self.run_events([eve("203.0.113.7", "192.168.1.10", 22, "ET EXPLOIT OpenSSH", 2, sev=1,
                                   cat="Attempted Administrator Privilege Gain")])
        f = out["inbound:203.0.113.7"]
        self.assertTrue(f["title"].startswith("Potential unwanted access"))
        self.assertIn(f["severity"], ("high", "critical"))

    def test_port_scan(self):
        raws = [eve("203.0.113.9", "192.168.1.10", p, "ET SCAN", 3, sev=3, action="blocked", t=i)
                for i, p in enumerate(range(1, 30))]
        f = self.run_events(raws)["inbound:203.0.113.9"]
        self.assertTrue(any("port scan" in r for r in f["reasons"]))
        self.assertTrue(f["title"].startswith("Blocked attack"))

    def test_internal_c2_is_compromise(self):
        out = self.run_events([eve("192.168.1.50", "185.100.87.1", 443, "ET MALWARE Cobalt Strike Beacon", 4,
                                   sev=1, cat="A Network Trojan was detected")])
        f = out["compromise:192.168.1.50"]
        self.assertGreaterEqual(f["score"], 80)

    def test_firewall_pass_correlation_escalates(self):
        raws = [eve("203.0.113.20", "192.168.1.10", 443, "ET SCAN Nmap", 5, sev=2, action="blocked")]
        c = cfg_()
        fw = detect.firewall_passes_by_src(
            [{"action": "pass", "src": "203.0.113.20", "dst": "192.168.1.10", "dstport": "443"},
             {"action": "block", "src": "203.0.113.20", "dst": "192.168.1.10", "dstport": "22"}], c.detect)
        f = self.run_events(raws, fw)["inbound:203.0.113.20"]
        self.assertTrue(f["title"].startswith("Potential unwanted access"))
        self.assertTrue(any("firewall PASSED 1" in r for r in f["reasons"]))

    def test_ignore_sid(self):
        c = cfg_()
        c.detect.ignore_sids = [2]
        ev = normalize(eve("203.0.113.7", "192.168.1.10", 22, "x", 2, sev=1))
        self.assertEqual(detect.analyze([ev], c.detect), [])


class PipelineTests(unittest.TestCase):
    def test_import_store_and_dedupe_notifications(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            path = os.path.join(d, "eve.json")
            with open(path, "w") as fh:
                for i in range(25):  # brute force on RDP that was not dropped
                    fh.write(json.dumps(eve("203.0.113.66", "192.168.1.20", 3389, "ET SCAN RDP brute", 7,
                                            sev=2, t=i)) + "\n")
                fh.write(json.dumps({"event_type": "stats"}) + "\n")
            c = cfg_()
            c.notify.min_severity = "low"
            store = Store(os.path.join(d, "t.db"))
            self.assertEqual(collect.import_file(path, store), 25)
            self.assertEqual(collect.import_file(path, store), 0)  # dedupe
            sent = engine.run_detection(c, store, None)
            self.assertEqual(len(sent), 1)
            self.assertEqual(engine.run_detection(c, store, None), [])  # no re-notify
            store.mark("inbound:203.0.113.66", status="false_positive")
            self.assertEqual(engine.run_detection(c, store, None), [])
            store.db.close()


if __name__ == "__main__":
    unittest.main()
