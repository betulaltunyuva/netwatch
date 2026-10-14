import os
from collections import defaultdict, deque
from datetime import datetime
from time import time

from logger import get_logger


logger = get_logger(__name__)


class ThreatDetector:
    """
    Ağ paketlerini inceleyerek şüpheli etkinlikleri tespit eder.
    """

    # Port taraması ayarları.
    PORT_SCAN_WINDOW = 10
    PORT_SCAN_PORT_LIMIT = 15

    # SYN Flood ayarları.
    SYN_FLOOD_WINDOW = 5
    SYN_FLOOD_PACKET_LIMIT = 100

    # ICMP Flood ayarları.
    ICMP_FLOOD_WINDOW = 10
    ICMP_FLOOD_PACKET_LIMIT = 50

    # Yoğun DNS trafiği ayarları.
    DNS_TRAFFIC_WINDOW = 10
    DNS_PACKET_LIMIT = 100

    # Aynı uyarının tekrar oluşturulması için
    # geçmesi gereken süre.
    ALERT_COOLDOWN = 30

    # Aynı IP adresi için farklı bir MAC adresi bu süre
    # içinde görülürse ARP spoofing şüphesi oluşur.
    # Daha uzun aralıklar normal IP değişimi (DHCP) sayılır.
    ARP_SPOOF_WINDOW = 300

    # Eski IP kayıtlarının kaç saniyede bir
    # bellekten temizleneceğini belirler.
    STATE_CLEANUP_INTERVAL = 60

    # Ortam değişkeniyle değiştirilebilen eşikler.
    # Örnek: NETWATCH_PORT_SCAN_PORT_LIMIT=25
    CONFIGURABLE_SETTINGS = (
        "PORT_SCAN_WINDOW",
        "PORT_SCAN_PORT_LIMIT",
        "SYN_FLOOD_WINDOW",
        "SYN_FLOOD_PACKET_LIMIT",
        "ICMP_FLOOD_WINDOW",
        "ICMP_FLOOD_PACKET_LIMIT",
        "DNS_TRAFFIC_WINDOW",
        "DNS_PACKET_LIMIT",
        "ALERT_COOLDOWN",
        "ARP_SPOOF_WINDOW",
    )

    def __init__(self):
        self.load_settings_from_environment()

        # Kaynak IP adresinin bağlanmaya çalıştığı
        # hedef portları tutar.
        self.port_attempts = defaultdict(deque)

        # Kaynak IP adreslerinin gönderdiği
        # SYN paketlerinin zamanlarını tutar.
        self.syn_packets = defaultdict(deque)

        # Kaynak IP adreslerinin gönderdiği
        # ICMP paketlerinin zamanlarını tutar.
        self.icmp_packets = defaultdict(deque)

        # Kaynak IP adreslerinin gönderdiği
        # DNS paketlerinin zamanlarını tutar.
        self.dns_packets = defaultdict(deque)

        # En son oluşturulan uyarıların zamanlarını tutar.
        self.last_alert_times = {}

        # IP adresi -> (MAC adresi, son görülme zamanı)
        self.arp_table = {}

        self.last_state_cleanup = time()

    def load_settings_from_environment(self):
        """
        NETWATCH_<AYAR_ADI> ortam değişkenlerinde
        verilen pozitif tam sayıları eşik olarak kullanır.
        """

        for setting_name in self.CONFIGURABLE_SETTINGS:
            environment_name = f"NETWATCH_{setting_name}"
            raw_value = os.environ.get(environment_name)

            if raw_value is None:
                continue

            try:
                value = int(raw_value)

            except ValueError:
                value = 0

            if value <= 0:
                logger.warning(
                    "Ignoring invalid %s value: %r",
                    environment_name,
                    raw_value
                )

                continue

            setattr(
                self,
                setting_name,
                value
            )

    def cleanup_inactive_sources(self, current_time):
        """
        Zaman penceresi dolmuş IP adreslerini
        bellekten siler.

        Bu temizlik yapılmazsa çok sayıda farklı
        IP adresi gören uzun çalışan bir uygulamada
        bellek kullanımı sürekli artar.
        """

        tracked_events = (
            (
                self.port_attempts,
                self.PORT_SCAN_WINDOW,
                lambda event: event[0]
            ),
            (
                self.syn_packets,
                self.SYN_FLOOD_WINDOW,
                lambda event: event
            ),
            (
                self.icmp_packets,
                self.ICMP_FLOOD_WINDOW,
                lambda event: event
            ),
            (
                self.dns_packets,
                self.DNS_TRAFFIC_WINDOW,
                lambda event: event
            ),
        )

        for events_by_ip, window, get_time in tracked_events:
            minimum_time = current_time - window

            inactive_ips = [
                source_ip
                for source_ip, event_queue
                in events_by_ip.items()
                if (
                    not event_queue
                    or get_time(event_queue[-1]) < minimum_time
                )
            ]

            for source_ip in inactive_ips:
                del events_by_ip[source_ip]

        expired_alerts = [
            alert_key
            for alert_key, alert_time
            in self.last_alert_times.items()
            if current_time - alert_time >= self.ALERT_COOLDOWN
        ]

        for alert_key in expired_alerts:
            del self.last_alert_times[alert_key]

        expired_arp_entries = [
            ip_value
            for ip_value, (_, seen_time)
            in self.arp_table.items()
            if current_time - seen_time >= self.ARP_SPOOF_WINDOW
        ]

        for ip_value in expired_arp_entries:
            del self.arp_table[ip_value]

        self.last_state_cleanup = current_time

    def remove_old_times(self, event_queue, current_time, window):
        """
        Belirlenen zaman aralığının dışında kalan
        eski olayları listeden siler.
        """

        minimum_time = current_time - window

        while event_queue and event_queue[0] < minimum_time:
            event_queue.popleft()

    def remove_old_port_attempts(
        self,
        event_queue,
        current_time,
        window
    ):
        """
        Eski port bağlantı denemelerini listeden siler.
        """

        minimum_time = current_time - window

        while (
            event_queue
            and event_queue[0][0] < minimum_time
        ):
            event_queue.popleft()

    def can_create_alert(
        self,
        alert_type,
        source_ip,
        current_time
    ):
        """
        Aynı uyarının çok kısa sürede tekrar tekrar
        oluşturulmasını engeller.
        """

        alert_key = (
            alert_type,
            source_ip
        )

        last_alert_time = self.last_alert_times.get(
            alert_key
        )

        if last_alert_time is not None:
            passed_time = (
                current_time - last_alert_time
            )

            if passed_time < self.ALERT_COOLDOWN:
                return False

        self.last_alert_times[alert_key] = current_time

        return True

    def create_alert(
        self,
        alert_type,
        severity,
        message,
        source_ip
    ):
        """
        Standart uyarı sözlüğü oluşturur.
        """

        return {
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
            "source_ip": source_ip,
            "created_at": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        }

    def detect_port_scan(
        self,
        source_ip,
        destination_port,
        tcp_flags,
        current_time
    ):
        """
        Bir IP adresinin kısa sürede çok sayıda
        farklı porta SYN paketi gönderip göndermediğini kontrol eder.
        """

        if destination_port is None:
            return None

        # Yalnızca SYN içeren ancak ACK içermeyen
        # TCP paketlerini kontrol eder.
        is_syn_packet = (
            "S" in tcp_flags
            and "A" not in tcp_flags
        )

        if not is_syn_packet:
            return None

        attempts = self.port_attempts[source_ip]

        attempts.append(
            (
                current_time,
                destination_port
            )
        )

        self.remove_old_port_attempts(
            attempts,
            current_time,
            self.PORT_SCAN_WINDOW
        )

        unique_ports = {
            port
            for _, port in attempts
        }

        if (
            len(unique_ports)
            >= self.PORT_SCAN_PORT_LIMIT
        ):
            if self.can_create_alert(
                "PORT_SCAN",
                source_ip,
                current_time
            ):
                return self.create_alert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    message=(
                        "Possible port scan detected from "
                        f"{source_ip}. "
                        f"{len(unique_ports)} different ports "
                        f"were targeted within "
                        f"{self.PORT_SCAN_WINDOW} seconds."
                    ),
                    source_ip=source_ip
                )

        return None

    def detect_syn_flood(
        self,
        source_ip,
        tcp_flags,
        current_time
    ):
        """
        Bir IP adresinden kısa sürede çok fazla
        SYN paketi gelip gelmediğini kontrol eder.
        """

        is_syn_packet = (
            "S" in tcp_flags
            and "A" not in tcp_flags
        )

        if not is_syn_packet:
            return None

        syn_events = self.syn_packets[source_ip]

        syn_events.append(current_time)

        self.remove_old_times(
            syn_events,
            current_time,
            self.SYN_FLOOD_WINDOW
        )

        if (
            len(syn_events)
            >= self.SYN_FLOOD_PACKET_LIMIT
        ):
            if self.can_create_alert(
                "SYN_FLOOD",
                source_ip,
                current_time
            ):
                return self.create_alert(
                    alert_type="SYN_FLOOD",
                    severity="CRITICAL",
                    message=(
                        "Possible SYN Flood detected from "
                        f"{source_ip}. "
                        f"{len(syn_events)} SYN packets "
                        f"were observed within "
                        f"{self.SYN_FLOOD_WINDOW} seconds."
                    ),
                    source_ip=source_ip
                )

        return None

    def detect_icmp_flood(
        self,
        source_ip,
        current_time
    ):
        """
        Bir IP adresinden kısa sürede çok fazla
        ICMP paketi gelip gelmediğini kontrol eder.
        """

        icmp_events = self.icmp_packets[source_ip]

        icmp_events.append(current_time)

        self.remove_old_times(
            icmp_events,
            current_time,
            self.ICMP_FLOOD_WINDOW
        )

        if (
            len(icmp_events)
            >= self.ICMP_FLOOD_PACKET_LIMIT
        ):
            if self.can_create_alert(
                "ICMP_FLOOD",
                source_ip,
                current_time
            ):
                return self.create_alert(
                    alert_type="ICMP_FLOOD",
                    severity="HIGH",
                    message=(
                        "Possible ICMP Flood detected from "
                        f"{source_ip}. "
                        f"{len(icmp_events)} ICMP packets "
                        f"were observed within "
                        f"{self.ICMP_FLOOD_WINDOW} seconds."
                    ),
                    source_ip=source_ip
                )

        return None

    def detect_dns_traffic(
        self,
        source_ip,
        destination_port,
        current_time
    ):
        """
        Bir IP adresinin kısa sürede çok fazla
        DNS paketi gönderip göndermediğini kontrol eder.
        """

        if destination_port != 53:
            return None

        dns_events = self.dns_packets[source_ip]

        dns_events.append(current_time)

        self.remove_old_times(
            dns_events,
            current_time,
            self.DNS_TRAFFIC_WINDOW
        )

        if (
            len(dns_events)
            >= self.DNS_PACKET_LIMIT
        ):
            if self.can_create_alert(
                "HIGH_DNS_TRAFFIC",
                source_ip,
                current_time
            ):
                return self.create_alert(
                    alert_type="HIGH_DNS_TRAFFIC",
                    severity="MEDIUM",
                    message=(
                        "Unusually high DNS traffic detected from "
                        f"{source_ip}. "
                        f"{len(dns_events)} DNS packets "
                        f"were observed within "
                        f"{self.DNS_TRAFFIC_WINDOW} seconds."
                    ),
                    source_ip=source_ip
                )

        return None

    def analyze_arp_reply(
        self,
        ip_value,
        mac_address,
        current_time=None
    ):
        """
        ARP yanıtındaki IP-MAC eşleşmesini kontrol eder.

        Aynı IP adresi kısa süre içinde farklı bir MAC
        adresiyle duyurulursa, biri ağ trafiğini kendi
        üzerine yönlendirmeye çalışıyor olabilir.
        """

        if not ip_value or not mac_address:
            return None

        if current_time is None:
            current_time = time()

        mac_address = str(mac_address).upper()

        previous_entry = self.arp_table.get(ip_value)

        self.arp_table[ip_value] = (
            mac_address,
            current_time
        )

        if previous_entry is None:
            return None

        previous_mac, previous_time = previous_entry

        if (
            previous_mac == mac_address
            or current_time - previous_time
            >= self.ARP_SPOOF_WINDOW
        ):
            return None

        if not self.can_create_alert(
            "ARP_SPOOFING",
            ip_value,
            current_time
        ):
            return None

        return self.create_alert(
            alert_type="ARP_SPOOFING",
            severity="HIGH",
            message=(
                "Possible ARP spoofing detected. "
                f"{ip_value} changed from MAC "
                f"{previous_mac} to {mac_address}."
            ),
            source_ip=ip_value
        )

    def analyze_packet(
        self,
        source_ip,
        protocol,
        destination_port=None,
        tcp_flags=""
    ):
        """
        Bir paketi bütün saldırı kurallarına göre analiz eder.

        Bulunan uyarıları liste olarak döndürür.
        """

        current_time = time()
        detected_alerts = []

        if (
            current_time - self.last_state_cleanup
            >= self.STATE_CLEANUP_INTERVAL
        ):
            self.cleanup_inactive_sources(
                current_time
            )

        if protocol == "TCP":
            port_scan_alert = self.detect_port_scan(
                source_ip=source_ip,
                destination_port=destination_port,
                tcp_flags=tcp_flags,
                current_time=current_time
            )

            if port_scan_alert is not None:
                detected_alerts.append(
                    port_scan_alert
                )

            syn_flood_alert = self.detect_syn_flood(
                source_ip=source_ip,
                tcp_flags=tcp_flags,
                current_time=current_time
            )

            if syn_flood_alert is not None:
                detected_alerts.append(
                    syn_flood_alert
                )

        elif protocol == "ICMP":
            icmp_flood_alert = self.detect_icmp_flood(
                source_ip=source_ip,
                current_time=current_time
            )

            if icmp_flood_alert is not None:
                detected_alerts.append(
                    icmp_flood_alert
                )

        elif protocol == "UDP":
            dns_alert = self.detect_dns_traffic(
                source_ip=source_ip,
                destination_port=destination_port,
                current_time=current_time
            )

            if dns_alert is not None:
                detected_alerts.append(
                    dns_alert
                )

        return detected_alerts


# Uygulama boyunca kullanılacak tek saldırı tespit nesnesi.
threat_detector = ThreatDetector()