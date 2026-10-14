from datetime import datetime
from ipaddress import ip_address

from database import get_connection


# Bir cihazın kaç saniye boyunca
# çevrimiçi kabul edileceğini belirler.
ONLINE_TIMEOUT_SECONDS = 120


def is_local_ip(ip_value):
    """
    IP adresinin yerel ve özel ağ adresi
    olup olmadığını kontrol eder.
    """

    try:
        parsed_ip = ip_address(
            str(ip_value).strip()
        )

    except ValueError:
        return False

    return (
        parsed_ip.version == 4
        and parsed_ip.is_private
        and not parsed_ip.is_loopback
        and not parsed_ip.is_multicast
        and not parsed_ip.is_unspecified
    )


def normalize_mac_address(mac_address):
    """
    MAC adresini standart biçime dönüştürür.
    """

    if not mac_address:
        return None

    clean_mac = str(
        mac_address
    ).strip().upper()

    if not clean_mac:
        return None

    return clean_mac[:17]


def normalize_seen_time(seen_at):
    """
    Cihazın görülme zamanını kontrol eder.
    """

    if not seen_at:
        return datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    try:
        parsed_time = datetime.strptime(
            str(seen_at),
            "%Y-%m-%d %H:%M:%S"
        )

        return parsed_time.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except ValueError:
        return datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )


def register_device(
    ip_value,
    mac_address=None,
    seen_at=None
):
    """
    Yerel ağdaki cihazı veritabanına kaydeder.

    Cihaz daha önce kaydedildiyse son görülme
    zamanını ve MAC adresini günceller.
    """

    if not is_local_ip(ip_value):
        return False

    clean_ip = str(
        ip_value
    ).strip()

    clean_mac = normalize_mac_address(
        mac_address
    )

    clean_seen_time = normalize_seen_time(
        seen_at
    )

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO devices (
                ip_address,
                mac_address,
                first_seen,
                last_seen
            )
            VALUES (
                ?,
                ?,
                ?,
                ?
            )

            ON CONFLICT(ip_address)
            DO UPDATE SET
                mac_address =
                    CASE
                        WHEN excluded.mac_address IS NOT NULL
                        THEN excluded.mac_address
                        ELSE devices.mac_address
                    END,

                last_seen = excluded.last_seen
            """,
            (
                clean_ip,
                clean_mac,
                clean_seen_time,
                clean_seen_time
            )
        )

    return True


def calculate_device_status(last_seen):
    """
    Son görülme zamanına göre cihazın
    çevrimiçi olup olmadığını hesaplar.
    """

    try:
        last_seen_time = datetime.strptime(
            last_seen,
            "%Y-%m-%d %H:%M:%S"
        )

    except (TypeError, ValueError):
        return "Offline"

    passed_seconds = (
        datetime.now() - last_seen_time
    ).total_seconds()

    if passed_seconds <= ONLINE_TIMEOUT_SECONDS:
        return "Online"

    return "Offline"


def get_devices():
    """
    Veritabanındaki yerel ağ cihazlarını döndürür.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                devices.id,
                devices.ip_address,
                devices.mac_address,
                devices.first_seen,
                devices.last_seen,
                devices.packet_count

            FROM devices

            ORDER BY devices.last_seen DESC
            """
        ).fetchall()

    devices = []

    for row in rows:
        device = dict(row)

        device["status"] = calculate_device_status(
            device["last_seen"]
        )

        devices.append(device)

    return devices


def get_device_summary(devices=None):
    """
    Toplam, çevrimiçi ve çevrimdışı
    cihaz sayılarını hesaplar.
    """

    if devices is None:
        devices = get_devices()

    total_devices = len(devices)

    online_devices = sum(
        1
        for device in devices
        if device["status"] == "Online"
    )

    offline_devices = (
        total_devices - online_devices
    )

    return {
        "total_devices": total_devices,
        "online_devices": online_devices,
        "offline_devices": offline_devices,
    }


def get_devices_data():
    """
    Cihazlar sayfasında kullanılacak
    bütün verileri tek sözlükte toplar.
    """

    devices = get_devices()

    return {
        "summary": get_device_summary(
            devices
        ),

        "devices": devices,

        "updated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
    }