import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# Veritabanı klasörü NETWATCH_DATA_DIR ortam
# değişkeniyle değiştirilebilir.
DATA_DIR = Path(
    os.environ.get("NETWATCH_DATA_DIR", "").strip()
    or BASE_DIR / "data"
)
DATABASE_PATH = DATA_DIR / "netwatch.db"


def get_connection():
    """SQLite veritabanına bağlantı oluşturur."""

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA busy_timeout = 10000"
    )

    return connection


def init_database():
    """NetWatch için gerekli tabloları ve indeksleri oluşturur."""

    with get_connection() as connection:
        connection.execute(
            "PRAGMA journal_mode = WAL"
        )

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                captured_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                packet_length INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL
                    CHECK (
                        severity IN (
                            'LOW',
                            'MEDIUM',
                            'HIGH',
                            'CRITICAL'
                        )
                    ),
                message TEXT NOT NULL,
                source_ip TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                packet_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_packets_captured_at
                ON packets(captured_at);

            CREATE INDEX IF NOT EXISTS idx_packets_source_ip
                ON packets(source_ip);

            CREATE INDEX IF NOT EXISTS idx_packets_destination_ip
                ON packets(destination_ip);

            CREATE INDEX IF NOT EXISTS idx_packets_protocol
                ON packets(protocol);

            CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                ON alerts(created_at);

            CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
                ON alerts(source_ip);

            CREATE INDEX IF NOT EXISTS idx_alerts_type
                ON alerts(alert_type);
            """
        )

        migrate_device_packet_count(
            connection
        )


# Bir cihazın kaynak veya hedef olduğu paketleri sayar.
# İki ayrı sorgu kullanılır; böylece her biri kendi
# indeksini kullanabilir.
DEVICE_PACKET_COUNT_SQL = """
    (
        SELECT COUNT(*)
        FROM packets
        WHERE packets.source_ip = devices.ip_address
    )
    +
    (
        SELECT COUNT(*)
        FROM packets
        WHERE packets.destination_ip = devices.ip_address
            AND packets.source_ip != devices.ip_address
    )
"""


def migrate_device_packet_count(connection):
    """
    Eski veritabanlarına packet_count sütununu ekler
    ve mevcut paketlerden ilk değerleri hesaplar.
    """

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(devices)"
        )
    }

    if "packet_count" in columns:
        return

    connection.execute(
        """
        ALTER TABLE devices
        ADD COLUMN packet_count INTEGER NOT NULL DEFAULT 0
        """
    )

    recalculate_device_packet_counts(
        connection
    )


def recalculate_device_packet_counts(connection):
    """
    Cihazların paket sayılarını packets
    tablosundan yeniden hesaplar.
    """

    connection.execute(
        f"""
        UPDATE devices
        SET packet_count = {DEVICE_PACKET_COUNT_SQL}
        """
    )


def count_packets_by_ip(packets):
    """
    Her IP adresinin kaç pakette kaynak veya
    hedef olarak geçtiğini sayar.
    """

    counts = {}

    for packet in packets:
        source_ip = packet["source_ip"]
        destination_ip = packet["destination_ip"]

        counts[source_ip] = (
            counts.get(source_ip, 0) + 1
        )

        if destination_ip != source_ip:
            counts[destination_ip] = (
                counts.get(destination_ip, 0) + 1
            )

    return counts


def save_packets(packets):
    """Yakalanan paketleri packets tablosuna kaydeder."""

    if not packets:
        return

    with get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO packets (
                captured_at,
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                packet_length
            )
            VALUES (
                :captured_at,
                :source_ip,
                :destination_ip,
                :protocol,
                :source_port,
                :destination_port,
                :packet_length
            )
            """,
            packets
        )

        # Cihaz sayfasının her açılışta bütün paket
        # tablosunu taramaması için sayaç güncellenir.
        # Cihaz olarak kayıtlı olmayan IP adresleri
        # için UPDATE hiçbir satırı etkilemez.
        connection.executemany(
            """
            UPDATE devices
            SET packet_count = packet_count + ?
            WHERE ip_address = ?
            """,
            [
                (count, ip_value)
                for ip_value, count
                in count_packets_by_ip(packets).items()
            ]
        )


def save_alerts(alerts):
    """Güvenlik uyarılarını alerts tablosuna kaydeder."""

    if not alerts:
        return

    with get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO alerts (
                alert_type,
                severity,
                message,
                source_ip,
                created_at
            )
            VALUES (
                :alert_type,
                :severity,
                :message,
                :source_ip,
                :created_at
            )
            """,
            alerts
        )


def get_packet_count():
    """Veritabanındaki toplam paket sayısını döndürür."""

    with get_connection() as connection:
        result = connection.execute(
            """
            SELECT COUNT(*) AS packet_count
            FROM packets
            """
        ).fetchone()

        return result["packet_count"]


def get_alert_count():
    """Veritabanındaki toplam güvenlik uyarısı sayısını döndürür."""

    with get_connection() as connection:
        result = connection.execute(
            """
            SELECT COUNT(*) AS alert_count
            FROM alerts
            """
        ).fetchone()

        return result["alert_count"]


def normalize_minutes(minutes):
    """
    Dakika değerini 1 ile 1440 dakika
    arasında sınırlar.
    """

    try:
        minutes = int(minutes)

    except (TypeError, ValueError):
        minutes = 60

    return max(
        1,
        min(minutes, 1440)
    )


def get_traffic_history(minutes=60):
    """
    Belirlenen zaman aralığındaki paket sayılarını
    dakika dakika döndürür.
    """

    minutes = normalize_minutes(minutes)
    time_modifier = f"-{minutes} minutes"

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                substr(captured_at, 1, 16) AS time_label,
                COUNT(*) AS total_packets,

                SUM(
                    CASE
                        WHEN protocol = 'TCP' THEN 1
                        ELSE 0
                    END
                ) AS tcp_packets,

                SUM(
                    CASE
                        WHEN protocol = 'UDP' THEN 1
                        ELSE 0
                    END
                ) AS udp_packets,

                SUM(
                    CASE
                        WHEN protocol = 'ICMP' THEN 1
                        ELSE 0
                    END
                ) AS icmp_packets

            FROM packets

            WHERE captured_at >= datetime(
                'now',
                'localtime',
                ?
            )

            GROUP BY substr(captured_at, 1, 16)

            ORDER BY time_label ASC
            """,
            (time_modifier,)
        ).fetchall()

    return fill_missing_minutes(
        [
            dict(row)
            for row in rows
        ],
        minutes
    )


def fill_missing_minutes(timeline, minutes, now=None):
    """
    Paket görülmeyen dakikaları sıfır değerleriyle
    ekler. Böylece grafik boş aralıkları atlamak
    yerine sıfıra düşer.
    """

    if now is None:
        now = datetime.now()

    rows_by_label = {
        row["time_label"]: row
        for row in timeline
    }

    current_minute = now.replace(
        second=0,
        microsecond=0
    )

    filled_timeline = []

    for offset in range(minutes, -1, -1):
        time_label = (
            current_minute
            - timedelta(minutes=offset)
        ).strftime("%Y-%m-%d %H:%M")

        filled_timeline.append(
            rows_by_label.get(
                time_label,
                {
                    "time_label": time_label,
                    "total_packets": 0,
                    "tcp_packets": 0,
                    "udp_packets": 0,
                    "icmp_packets": 0,
                }
            )
        )

    return filled_timeline


def get_history_summary(minutes=60):
    """
    Seçilen zaman aralığındaki genel
    paket istatistiklerini döndürür.
    """

    minutes = normalize_minutes(minutes)
    time_modifier = f"-{minutes} minutes"

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_packets,

                COALESCE(
                    SUM(
                        CASE
                            WHEN protocol = 'TCP' THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS tcp_packets,

                COALESCE(
                    SUM(
                        CASE
                            WHEN protocol = 'UDP' THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS udp_packets,

                COALESCE(
                    SUM(
                        CASE
                            WHEN protocol = 'ICMP' THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS icmp_packets,

                COALESCE(
                    SUM(packet_length),
                    0
                ) AS total_bytes

            FROM packets

            WHERE captured_at >= datetime(
                'now',
                'localtime',
                ?
            )
            """,
            (time_modifier,)
        ).fetchone()

        return dict(row)


def get_recent_packets(minutes=60, limit=100):
    """Seçilen zaman aralığındaki son paketleri döndürür."""

    minutes = normalize_minutes(minutes)

    try:
        limit = int(limit)

    except (TypeError, ValueError):
        limit = 100

    limit = max(
        1,
        min(limit, 500)
    )

    time_modifier = f"-{minutes} minutes"

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                captured_at,
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                packet_length

            FROM packets

            WHERE captured_at >= datetime(
                'now',
                'localtime',
                ?
            )

            ORDER BY id DESC

            LIMIT ?
            """,
            (
                time_modifier,
                limit
            )
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]


def get_recent_alerts(minutes=60, limit=50):
    """
    Seçilen zaman aralığındaki son güvenlik
    uyarılarını döndürür.
    """

    minutes = normalize_minutes(minutes)

    try:
        limit = int(limit)

    except (TypeError, ValueError):
        limit = 50

    limit = max(
        1,
        min(limit, 100)
    )

    time_modifier = f"-{minutes} minutes"

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                alert_type,
                severity,
                message,
                source_ip,
                created_at

            FROM alerts

            WHERE created_at >= datetime(
                'now',
                'localtime',
                ?
            )

            ORDER BY id DESC

            LIMIT ?
            """,
            (
                time_modifier,
                limit
            )
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]


def get_history_data(minutes=60):
    """
    Trafik geçmişi sayfasında kullanılacak
    bütün verileri tek sözlükte toplar.
    """

    minutes = normalize_minutes(minutes)

    return {
        "minutes": minutes,
        "summary": get_history_summary(minutes),
        "timeline": get_traffic_history(minutes),
        "packets": get_recent_packets(
            minutes=minutes,
            limit=100
        ),
        "alerts": get_recent_alerts(
            minutes=minutes,
            limit=50
        ),
    }


def normalize_retention_days(days):
    """Saklama süresini 1 ile 365 gün arasında sınırlar."""

    try:
        days = int(days)

    except (TypeError, ValueError):
        days = 30

    return max(
        1,
        min(days, 365)
    )


def cleanup_old_records(days=30):
    """
    Seçilen süreden eski paket, güvenlik
    uyarısı ve cihaz kayıtlarını temizler.
    """

    days = normalize_retention_days(days)
    time_modifier = f"-{days} days"

    with get_connection() as connection:
        packet_cursor = connection.execute(
            """
            DELETE FROM packets
            WHERE captured_at < datetime(
                'now',
                'localtime',
                ?
            )
            """,
            (time_modifier,)
        )

        alert_cursor = connection.execute(
            """
            DELETE FROM alerts
            WHERE created_at < datetime(
                'now',
                'localtime',
                ?
            )
            """,
            (time_modifier,)
        )

        # Saklama süresi boyunca hiç görülmeyen
        # cihazlar da listeden kaldırılır.
        device_cursor = connection.execute(
            """
            DELETE FROM devices
            WHERE last_seen < datetime(
                'now',
                'localtime',
                ?
            )
            """,
            (time_modifier,)
        )

        deleted_packets = packet_cursor.rowcount
        deleted_alerts = alert_cursor.rowcount
        deleted_devices = device_cursor.rowcount

        # Silinen paketler cihaz sayaçlarından da düşülür.
        if deleted_packets:
            recalculate_device_packet_counts(
                connection
            )

    return {
        "retention_days": days,
        "deleted_packets": deleted_packets,
        "deleted_alerts": deleted_alerts,
        "deleted_devices": deleted_devices,
    }