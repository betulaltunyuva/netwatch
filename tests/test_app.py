import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database


DEPENDENCIES_AVAILABLE = all(
    importlib.util.find_spec(package) is not None
    for package in (
        "flask",
        "flask_socketio"
    )
)


@unittest.skipUnless(
    DEPENDENCIES_AVAILABLE,
    "Flask dependencies are not installed."
)
class AppRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Testler gerçek data/netwatch.db dosyasına
        # dokunmasın diye geçici bir klasör kullanılır.
        cls.temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        cls.original_data_dir = database.DATA_DIR
        cls.original_database_path = (
            database.DATABASE_PATH
        )

        database.DATA_DIR = Path(
            cls.temporary_directory.name
        )

        database.DATABASE_PATH = (
            database.DATA_DIR / "test.db"
        )

        database.init_database()

        from app import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        database.DATA_DIR = cls.original_data_dir
        database.DATABASE_PATH = (
            cls.original_database_path
        )

        cls.temporary_directory.cleanup()

    def test_pages_are_available(self):
        paths = (
            "/",
            "/history",
            "/search",
            "/devices",
            "/exports"
        )

        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)

                self.assertEqual(
                    response.status_code,
                    200
                )

                self.assertEqual(
                    response.headers[
                        "X-Frame-Options"
                    ],
                    "DENY"
                )

    def test_json_endpoints_are_available(self):
        paths = (
            "/api/history?minutes=60",
            "/api/packets/search?limit=10",
            "/api/devices",
            "/api/exports/info"
        )

        for path in paths:
            with self.subTest(path=path):
                response = self.client.get(path)

                self.assertEqual(
                    response.status_code,
                    200
                )

                self.assertTrue(
                    response.is_json
                )

    def test_security_headers_are_set(self):
        response = self.client.get("/")

        policy = response.headers[
            "Content-Security-Policy"
        ]

        self.assertIn(
            "default-src 'self'",
            policy
        )

        self.assertIn(
            "frame-ancestors 'none'",
            policy
        )

    def test_unknown_host_is_rejected(self):
        # DNS rebinding saldırısında tarayıcı,
        # saldırganın alan adını Host olarak gönderir.
        response = self.client.get(
            "/api/devices",
            headers={
                "Host": "evil.example"
            }
        )

        self.assertEqual(
            response.status_code,
            400
        )

        local_response = self.client.get(
            "/api/devices",
            headers={
                "Host": "127.0.0.1:5000"
            }
        )

        self.assertEqual(
            local_response.status_code,
            200
        )

    def test_cleanup_endpoint_uses_requested_retention(self):
        cleanup_result = {
            "retention_days": 30,
            "deleted_packets": 5,
            "deleted_alerts": 1,
            "deleted_devices": 0
        }

        with patch(
            "app.cleanup_old_records",
            return_value=cleanup_result
        ) as cleanup:
            response = self.client.post(
                "/api/data/cleanup",
                json={
                    "retention_days": 30
                }
            )

        self.assertEqual(
            response.status_code,
            200
        )

        cleanup.assert_called_once_with(
            days=30
        )

        self.assertEqual(
            response.get_json()[
                "deleted_packets"
            ],
            5
        )

    def test_cleanup_rejects_cross_site_requests(self):
        with patch(
            "app.cleanup_old_records"
        ) as cleanup:
            # Başka bir sitenin gönderebileceği
            # sıradan HTML form isteği.
            form_response = self.client.post(
                "/api/data/cleanup",
                data="retention_days=1",
                content_type="text/plain"
            )

            foreign_origin_response = self.client.post(
                "/api/data/cleanup",
                json={
                    "retention_days": 1
                },
                headers={
                    "Origin": "http://evil.example"
                }
            )

        self.assertEqual(
            form_response.status_code,
            415
        )

        self.assertEqual(
            foreign_origin_response.status_code,
            403
        )

        cleanup.assert_not_called()


if __name__ == "__main__":
    unittest.main()