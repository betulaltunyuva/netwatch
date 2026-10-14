import unittest
from unittest.mock import patch

from detector import ThreatDetector
from sniffer import SCAPY_AVAILABLE, NetworkMonitor


class NetworkMonitorTests(unittest.TestCase):
    def test_sample_mode_summary(self):
        monitor = NetworkMonitor()

        monitor.activate_sample_mode(
            "Test capture failure."
        )

        summary = monitor.get_summary()

        self.assertEqual(
            summary["data_mode"],
            "sample"
        )

        self.assertEqual(
            summary["total_packets"],
            48
        )

        self.assertEqual(
            summary["tcp_packets"],
            6
        )

        self.assertEqual(
            summary["udp_packets"],
            42
        )

        self.assertEqual(
            len(summary["recent_packets"]),
            10
        )

    def test_pending_records_are_written_as_one_batch(self):
        monitor = NetworkMonitor()

        monitor.pending_packets = [
            {"id": 1},
            {"id": 2}
        ]

        monitor.pending_alerts = [
            {"id": 3}
        ]

        with (
            patch(
                "sniffer.save_packets"
            ) as save_packets,
            patch(
                "sniffer.save_alerts"
            ) as save_alerts
        ):
            saved_count = monitor.flush_database(
                force=True
            )

        self.assertEqual(saved_count, 2)

        save_packets.assert_called_once_with(
            [{"id": 1}, {"id": 2}]
        )

        save_alerts.assert_called_once_with(
            [{"id": 3}]
        )

        self.assertEqual(
            monitor.pending_packets,
            []
        )

        self.assertEqual(
            monitor.pending_alerts,
            []
        )

    def test_failed_capture_thread_switches_to_sample_mode(self):
        class FailingSniffer:
            def __init__(self, **options):
                self.options = options
                self.thread = None

            def start(self):
                pass

            def join(self, timeout=None):
                # Scapy, thread içindeki hatayı
                # join() sırasında fırlatır.
                raise OSError(
                    "Npcap is not installed"
                )

        monitor = NetworkMonitor(
            interface="Ethernet"
        )

        with (
            patch(
                "sniffer.SCAPY_AVAILABLE",
                True
            ),
            patch(
                "sniffer.AsyncSniffer",
                FailingSniffer,
                create=True
            )
        ):
            started = monitor.start()

        self.assertFalse(started)

        self.assertEqual(
            monitor.sniffer.options["iface"],
            "Ethernet"
        )

        summary = monitor.get_summary()

        self.assertEqual(
            summary["data_mode"],
            "sample"
        )

        self.assertIn(
            "Npcap is not installed",
            " ".join(summary["alerts"])
        )

    def test_broken_packet_does_not_stop_capture(self):
        class BrokenPacket:
            def haslayer(self, layer):
                raise ValueError(
                    "Malformed packet"
                )

        monitor = NetworkMonitor()

        # Hata dışarı fırlatılırsa Scapy
        # yakalamayı tamamen durdurur.
        monitor.process_packet(
            BrokenPacket()
        )

        summary = monitor.get_summary()

        self.assertEqual(
            summary["skipped_packets"],
            1
        )

        self.assertIn(
            "1 packets could not be processed",
            " ".join(summary["alerts"])
        )

    def test_stopped_capture_thread_is_reported(self):
        class StoppedThread:
            def is_alive(self):
                return False

        class StoppedSniffer:
            thread = StoppedThread()
            exception = OSError(
                "Adapter disconnected"
            )

        monitor = NetworkMonitor()
        monitor.sniffer = StoppedSniffer()
        monitor.running = True

        summary = monitor.get_summary()

        self.assertEqual(
            summary["data_mode"],
            "unavailable"
        )

        self.assertIn(
            "Adapter disconnected",
            " ".join(summary["alerts"])
        )


@unittest.skipUnless(
    SCAPY_AVAILABLE,
    "Scapy is not installed."
)
class PacketProcessingTests(unittest.TestCase):
    def test_ipv6_packets_are_processed(self):
        from scapy.all import (
            Ether,
            ICMPv6EchoRequest,
            IPv6,
            TCP
        )

        monitor = NetworkMonitor()

        packets = [
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / IPv6(src="2001:db8::1", dst="2001:db8::2")
            / TCP(sport=50000, dport=443, flags="S"),

            Ether(dst="ff:ff:ff:ff:ff:ff")
            / IPv6(src="2001:db8::1", dst="2001:db8::2")
            / ICMPv6EchoRequest(),
        ]

        with patch(
            "sniffer.threat_detector",
            ThreatDetector()
        ):
            for packet in packets:
                monitor.process_packet(packet)

        summary = monitor.get_summary()

        self.assertEqual(summary["total_packets"], 2)
        self.assertEqual(summary["tcp_packets"], 1)
        self.assertEqual(summary["icmp_packets"], 1)
        self.assertEqual(summary["skipped_packets"], 0)

        self.assertEqual(
            monitor.pending_packets[0]["source_ip"],
            "2001:db8::1"
        )

        self.assertEqual(
            monitor.pending_packets[0]["destination_port"],
            443
        )

    def test_arp_spoofing_alert_is_queued(self):
        from scapy.all import ARP, Ether

        monitor = NetworkMonitor()

        replies = [
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op=2,
                psrc="192.168.1.1",
                hwsrc="aa:aa:aa:aa:aa:aa"
            ),

            Ether(dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op=2,
                psrc="192.168.1.1",
                hwsrc="bb:bb:bb:bb:bb:bb"
            ),
        ]

        with patch(
            "sniffer.threat_detector",
            ThreatDetector()
        ):
            for packet in replies:
                monitor.process_packet(packet)

        self.assertEqual(
            [
                alert["alert_type"]
                for alert in monitor.pending_alerts
            ],
            ["ARP_SPOOFING"]
        )

        # ARP paketleri IP trafiği olarak sayılmaz.
        self.assertEqual(
            monitor.get_summary()["total_packets"],
            0
        )


if __name__ == "__main__":
    unittest.main()