import unittest
from time import time
from unittest.mock import patch

from detector import ThreatDetector


class ThreatDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = ThreatDetector()

    def test_port_scan_detection(self):
        alerts = []

        for port in range(1000, 1015):
            alerts.extend(
                self.detector.analyze_packet(
                    "10.0.0.5",
                    "TCP",
                    destination_port=port,
                    tcp_flags="S"
                )
            )

        self.assertIn(
            "PORT_SCAN",
            [alert["alert_type"] for alert in alerts]
        )

    def test_flood_rules(self):
        cases = [
            ("TCP", 80, "S", 100, "SYN_FLOOD"),
            ("ICMP", None, "", 50, "ICMP_FLOOD"),
            ("UDP", 53, "", 100, "HIGH_DNS_TRAFFIC"),
        ]

        for protocol, port, flags, count, expected_type in cases:
            detector = ThreatDetector()
            alerts = []

            for _ in range(count):
                alerts.extend(
                    detector.analyze_packet(
                        "10.0.0.8",
                        protocol,
                        destination_port=port,
                        tcp_flags=flags
                    )
                )

            self.assertIn(
                expected_type,
                [alert["alert_type"] for alert in alerts]
            )

    def test_inactive_sources_are_removed_from_memory(self):
        self.detector.analyze_packet(
            "10.0.0.20",
            "ICMP"
        )

        self.detector.analyze_packet(
            "10.0.0.21",
            "TCP",
            destination_port=22,
            tcp_flags="S"
        )

        self.assertIn(
            "10.0.0.20",
            self.detector.icmp_packets
        )

        # Bütün zaman pencerelerinin dolduğu
        # bir anı taklit eder.
        self.detector.cleanup_inactive_sources(
            current_time=time() + 3600
        )

        self.assertEqual(
            len(self.detector.icmp_packets),
            0
        )

        self.assertEqual(
            len(self.detector.port_attempts),
            0
        )

        self.assertEqual(
            len(self.detector.syn_packets),
            0
        )

    def test_thresholds_can_be_set_from_environment(self):
        with patch.dict(
            "os.environ",
            {
                "NETWATCH_PORT_SCAN_PORT_LIMIT": "3",
                "NETWATCH_SYN_FLOOD_WINDOW": "invalid"
            }
        ):
            detector = ThreatDetector()

        self.assertEqual(
            detector.PORT_SCAN_PORT_LIMIT,
            3
        )

        # Geçersiz değer varsayılanı değiştirmez.
        self.assertEqual(
            detector.SYN_FLOOD_WINDOW,
            ThreatDetector.SYN_FLOOD_WINDOW
        )

        alerts = []

        for port in (22, 80, 443):
            alerts.extend(
                detector.analyze_packet(
                    "10.0.0.9",
                    "TCP",
                    destination_port=port,
                    tcp_flags="S"
                )
            )

        self.assertEqual(
            [alert["alert_type"] for alert in alerts],
            ["PORT_SCAN"]
        )

    def test_arp_spoofing_detection(self):
        self.assertIsNone(
            self.detector.analyze_arp_reply(
                "192.168.1.1",
                "aa:aa:aa:aa:aa:aa",
                current_time=1000
            )
        )

        # Aynı MAC tekrar duyurulursa sorun yoktur.
        self.assertIsNone(
            self.detector.analyze_arp_reply(
                "192.168.1.1",
                "AA:AA:AA:AA:AA:AA",
                current_time=1010
            )
        )

        alert = self.detector.analyze_arp_reply(
            "192.168.1.1",
            "bb:bb:bb:bb:bb:bb",
            current_time=1020
        )

        self.assertEqual(
            alert["alert_type"],
            "ARP_SPOOFING"
        )

        # Uzun süre sonra gelen değişiklik
        # normal bir IP değişimi sayılır.
        self.assertIsNone(
            self.detector.analyze_arp_reply(
                "192.168.1.50",
                "cc:cc:cc:cc:cc:cc",
                current_time=1000
            )
        )

        self.assertIsNone(
            self.detector.analyze_arp_reply(
                "192.168.1.50",
                "dd:dd:dd:dd:dd:dd",
                current_time=2000
            )
        )


if __name__ == "__main__":
    unittest.main()