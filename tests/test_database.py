import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

import database

from device_manager import (
    get_devices_data,
    register_device
)

from export_manager import create_packet_csv
from packet_search import search_packets


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        self.original_data_dir = (
            database.DATA_DIR
        )

        self.original_database_path = (
            database.DATABASE_PATH
        )

        database.DATA_DIR = Path(
            self.temporary_directory.name
        )

        database.DATABASE_PATH = (
            database.DATA_DIR / "test.db"
        )

        database.init_database()

    def tearDown(self):
        database.DATA_DIR = (
            self.original_data_dir
        )

        database.DATABASE_PATH = (
            self.original_database_path
        )

        self.temporary_directory.cleanup()

    def test_packet_search_export_and_device_tracking(self):
        database.save_packets(
            [
                {
                    "captured_at":
                        "2026-09-12 12:00:00",
                    "source_ip":
                        "192.168.1.10",
                    "destination_ip":
                        "8.8.8.8",
                    "protocol":
                        "UDP",
                    "source_port":
                        50000,
                    "destination_port":
                        53,
                    "packet_length":
                        60
                }
            ]
        )

        result = search_packets(
            source_ip="192.168.1",
            protocol="udp",
            limit=10
        )

        self.assertEqual(
            result["summary"]["total_packets"],
            1
        )

        self.assertEqual(
            result["packets"][0][
                "destination_port"
            ],
            53
        )

        self.assertEqual(
            create_packet_csv()[
                "record_count"
            ],
            1
        )

        self.assertTrue(
            register_device(
                "192.168.1.10",
                "AA:BB:CC:DD:EE:FF",
                "2026-09-12 12:00:00"
            )
        )

        self.assertEqual(
            get_devices_data()[
                "summary"
            ]["total_devices"],
            1
        )

    def test_cleanup_deletes_only_old_records(self):
        database.save_packets(
            [
                {
                    "captured_at":
                        "2000-01-01 00:00:00",
                    "source_ip":
                        "10.0.0.1",
                    "destination_ip":
                        "10.0.0.2",
                    "protocol":
                        "TCP",
                    "source_port":
                        1000,
                    "destination_port":
                        80,
                    "packet_length":
                        40
                },
                {
                    "captured_at":
                        "2999-01-01 00:00:00",
                    "source_ip":
                        "10.0.0.1",
                    "destination_ip":
                        "10.0.0.2",
                    "protocol":
                        "TCP",
                    "source_port":
                        1001,
                    "destination_port":
                        443,
                    "packet_length":
                        40
                }
            ]
        )

        register_device(
            "192.168.1.20",
            seen_at="2000-01-01 00:00:00"
        )

        register_device(
            "192.168.1.21"
        )

        result = database.cleanup_old_records(
            days=30
        )

        self.assertEqual(
            result["deleted_packets"],
            1
        )

        self.assertEqual(
            result["deleted_devices"],
            1
        )

        self.assertEqual(
            [
                device["ip_address"]
                for device in get_devices_data()[
                    "devices"
                ]
            ],
            ["192.168.1.21"]
        )

        self.assertEqual(
            database.get_packet_count(),
            1
        )

    def test_device_packet_count_is_updated_on_save(self):
        register_device(
            "192.168.1.30"
        )

        packet = {
            "captured_at": "2026-09-12 12:00:00",
            "source_ip": "192.168.1.30",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "source_port": 50000,
            "destination_port": 53,
            "packet_length": 60
        }

        reply = dict(
            packet,
            source_ip="8.8.8.8",
            destination_ip="192.168.1.30"
        )

        database.save_packets(
            [packet, packet, reply]
        )

        device = get_devices_data()["devices"][0]

        self.assertEqual(
            device["packet_count"],
            3
        )

    def test_old_database_gets_packet_count_column(self):
        # packet_count sütunu olmayan eski şemayı oluşturur.
        old_database = (
            database.DATA_DIR / "old.db"
        )

        connection = sqlite3.connect(old_database)

        connection.executescript(
            """
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            INSERT INTO devices (
                ip_address, first_seen, last_seen
            )
            VALUES (
                '10.0.0.7',
                '2026-09-12 12:00:00',
                '2026-09-12 12:00:00'
            );
            """
        )

        connection.close()

        database.DATABASE_PATH = old_database
        database.init_database()

        database.save_packets(
            [
                {
                    "captured_at": "2026-09-12 12:00:00",
                    "source_ip": "10.0.0.7",
                    "destination_ip": "10.0.0.8",
                    "protocol": "TCP",
                    "source_port": 1000,
                    "destination_port": 80,
                    "packet_length": 40
                }
            ]
        )

        self.assertEqual(
            get_devices_data()["devices"][0][
                "packet_count"
            ],
            1
        )

    def test_missing_minutes_are_filled_with_zero(self):
        timeline = database.fill_missing_minutes(
            [
                {
                    "time_label": "2026-09-12 12:01",
                    "total_packets": 4,
                    "tcp_packets": 4,
                    "udp_packets": 0,
                    "icmp_packets": 0
                }
            ],
            minutes=3,
            now=datetime(2026, 9, 12, 12, 3, 30)
        )

        self.assertEqual(
            [
                (row["time_label"], row["total_packets"])
                for row in timeline
            ],
            [
                ("2026-09-12 12:00", 0),
                ("2026-09-12 12:01", 4),
                ("2026-09-12 12:02", 0),
                ("2026-09-12 12:03", 0)
            ]
        )


if __name__ == "__main__":
    unittest.main()