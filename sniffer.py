import os
from collections import Counter, deque
from datetime import datetime
from threading import Lock
from time import monotonic

from database import save_alerts, save_packets
from detector import threat_detector
from device_manager import is_local_ip, register_device
from logger import get_logger


logger = get_logger(__name__)


try:
    from scapy.all import (
        ARP,
        AsyncSniffer,
        Ether,
        ICMP,
        IP,
        IPv6,
        TCP,
        UDP
    )

    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = None

except Exception as error:
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(error)


class NetworkMonitor:
    """
    Ağ paketlerini arka planda yakalar.

    Paketleri analiz eder, veritabanına kaydeder,
    cihazları takip eder ve PCAP dışa aktarımı için
    ham paketleri bellekte tutar.
    """

    DEVICE_UPDATE_INTERVAL = 10
    RAW_PACKET_BUFFER_SIZE = 5000

    # Paketler veritabanına tek tek değil,
    # toplu olarak kaydedilir.
    DATABASE_BATCH_SIZE = 100
    DATABASE_FLUSH_INTERVAL = 1

    # Yakalama başladıktan sonra hata kontrolü
    # için beklenecek süre (saniye).
    CAPTURE_STARTUP_CHECK = 1

    def __init__(self, interface=None):
        self.lock = Lock()

        # Dinlenecek ağ arayüzü. Boş bırakılırsa
        # Scapy varsayılan arayüzü kullanır.
        self.interface = (
            interface
            or os.environ.get(
                "NETWATCH_INTERFACE",
                ""
            ).strip()
            or None
        )

        self.sniffer = None
        self.running = False
        self.sample_mode = False

        self.capture_error = None
        self.database_error = None
        self.detector_error = None
        self.device_error = None

        self.total_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0

        self.source_counter = Counter()
        self.port_counter = Counter()

        self.recent_packets = deque(
            maxlen=10
        )

        self.security_alerts = deque(
            maxlen=10
        )

        self.raw_packets = deque(
            maxlen=self.RAW_PACKET_BUFFER_SIZE
        )

        self.device_last_updates = {}

        # İşlenirken hata veren ve atlanan paket sayısı.
        self.skipped_packets = 0

        # Veritabanına kaydedilmeyi bekleyen veriler.
        self.pending_packets = []
        self.pending_alerts = []

        self.last_database_flush = monotonic()
        self.last_updated = datetime.now()

    def start(self):
        """Paket yakalamayı arka planda başlatır."""

        if self.running:
            return True

        if not SCAPY_AVAILABLE:
            self.activate_sample_mode(
                "Scapy could not be loaded. "
                "Live capture is unavailable. "
                f"Details: {SCAPY_IMPORT_ERROR or 'unknown error'}"
            )

            return False

        try:
            sniffer_options = {
                "prn": self.process_packet,
                "store": False,
            }

            if self.interface:
                sniffer_options["iface"] = (
                    self.interface
                )

            self.sniffer = AsyncSniffer(
                **sniffer_options
            )

            self.sniffer.start()

            # AsyncSniffer hataları arka plandaki
            # thread içinde yakalar ve start() hata
            # vermez. Npcap eksikliği veya yetki hatası
            # gibi sorunları görmek için kısa süre bekler.
            # Thread hata ile durduysa join() hatayı fırlatır.
            self.sniffer.join(
                timeout=self.CAPTURE_STARTUP_CHECK
            )

            if not self.is_capture_thread_alive():
                raise RuntimeError(
                    "Packet capture thread stopped unexpectedly."
                )

            self.running = True
            self.sample_mode = False
            self.capture_error = None

            logger.info(
                "Live packet capture started on %s.",
                self.interface or "the default interface"
            )

            return True

        except Exception as error:
            self.running = False

            self.activate_sample_mode(
                "Packet capture could not be started: "
                f"{error}"
            )

            logger.exception(
                "Packet capture could not be started"
            )

            return False

    def is_capture_thread_alive(self):
        """
        Paket yakalama thread'inin hâlâ
        çalışıp çalışmadığını kontrol eder.
        """

        if self.sniffer is None:
            return False

        capture_thread = getattr(
            self.sniffer,
            "thread",
            None
        )

        return (
            capture_thread is not None
            and capture_thread.is_alive()
        )

    def check_capture_health(self):
        """
        Yakalama sonradan beklenmedik şekilde
        durduysa durumu ve hata mesajını günceller.
        """

        if (
            not self.running
            or self.is_capture_thread_alive()
        ):
            return

        self.running = False

        error = getattr(
            self.sniffer,
            "exception",
            None
        )

        self.capture_error = (
            "Packet capture stopped unexpectedly"
            + (
                f": {error}"
                if error
                else "."
            )
        )

        logger.error(
            self.capture_error
        )

    def activate_sample_mode(self, reason):
        """
        Canlı paket yakalama çalışmadığında
        güvenli örnek verileri gösterir.
        """

        sample_packets = []

        for index in range(48):
            protocol = (
                "TCP"
                if index < 6
                else "UDP"
            )

            source_ip = (
                f"192.168.1.{(index % 5) + 2}"
            )

            destination_ip = (
                "8.8.8.8"
                if protocol == "UDP"
                else "93.184.216.34"
            )

            destination_port = (
                53
                if protocol == "UDP"
                else 443
            )

            sample_packets.append(
                {
                    "time": "--:--:--",
                    "source": source_ip,
                    "destination": destination_ip,
                    "protocol": protocol,
                    "length": 60 + (index % 8) * 12,
                    "destination_port": destination_port,
                }
            )

        with self.lock:
            self.running = False
            self.sample_mode = True

            self.total_packets = len(
                sample_packets
            )

            self.tcp_packets = 6
            self.udp_packets = 42
            self.icmp_packets = 0

            self.source_counter = Counter(
                packet["source"]
                for packet in sample_packets
            )

            self.port_counter = Counter(
                packet["destination_port"]
                for packet in sample_packets
            )

            self.recent_packets.clear()

            for packet in sample_packets[-10:]:
                self.recent_packets.append(
                    {
                        "time": packet["time"],
                        "source": packet["source"],
                        "destination": packet["destination"],
                        "protocol": packet["protocol"],
                        "length": packet["length"],
                    }
                )

            self.last_updated = datetime.now()

        self.capture_error = (
            f"{reason} Sample data is displayed."
        )

        logger.warning(
            self.capture_error
        )

    def stop(self):
        """Paket yakalamayı durdurur."""

        if (
            self.sniffer is not None
            and self.running
        ):
            try:
                self.sniffer.stop()

            except Exception:
                logger.exception(
                    "Packet capture could not be stopped correctly"
                )

        self.running = False

        # Program kapanırken bekleyen kayıtları kaydeder.
        self.flush_database(
            force=True
        )

    def track_device(
        self,
        source_ip,
        source_mac,
        seen_at
    ):
        """Yerel ağdaki kaynak cihazı kaydeder."""

        if not is_local_ip(source_ip):
            return

        current_time = monotonic()

        last_update = self.device_last_updates.get(
            source_ip,
            0
        )

        passed_time = (
            current_time - last_update
        )

        if passed_time < self.DEVICE_UPDATE_INTERVAL:
            return

        try:
            device_registered = register_device(
                ip_value=source_ip,
                mac_address=source_mac,
                seen_at=seen_at
            )

            if device_registered:
                self.device_last_updates[source_ip] = (
                    current_time
                )

            self.device_error = None

        except Exception as error:
            self.device_error = str(error)

            logger.exception(
                "Device tracking failed"
            )

    def process_packet(self, packet):
        """
        Yakalanan her ağ paketi için çalışır.

        Scapy, prn fonksiyonunda oluşan bir hatada
        yakalamayı tamamen durdurur. Bu yüzden tek bir
        bozuk paket yalnızca günlüğe yazılır ve atlanır.
        """

        try:
            self.handle_packet(packet)

        except Exception:
            self.skipped_packets += 1

            logger.exception(
                "Packet could not be processed and was skipped"
            )

    def handle_packet(self, packet):
        """Bir paketi analiz eder ve sayaçları günceller."""

        if packet.haslayer(ARP):
            self.handle_arp_packet(packet)
            return

        if packet.haslayer(IP):
            ip_layer = packet[IP]

        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]

        else:
            return

        captured_at = datetime.now()

        captured_at_text = captured_at.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        protocol = "OTHER"
        source_port = None
        destination_port = None
        source_mac = None
        tcp_flags = ""

        if packet.haslayer(Ether):
            source_mac = str(
                packet[Ether].src
            )

        if packet.haslayer(TCP):
            protocol = "TCP"

            source_port = int(
                packet[TCP].sport
            )

            destination_port = int(
                packet[TCP].dport
            )

            tcp_flags = str(
                packet[TCP].flags
            )

        elif packet.haslayer(UDP):
            protocol = "UDP"

            source_port = int(
                packet[UDP].sport
            )

            destination_port = int(
                packet[UDP].dport
            )

        elif is_icmp_packet(packet):
            protocol = "ICMP"

        packet_record = {
            "captured_at": captured_at_text,
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_length": len(packet),
        }

        recent_packet = {
            "time": captured_at.strftime(
                "%H:%M:%S"
            ),
            "source": ip_layer.src,
            "destination": ip_layer.dst,
            "protocol": protocol,
            "length": len(packet),
        }

        self.track_device(
            source_ip=ip_layer.src,
            source_mac=source_mac,
            seen_at=captured_at_text
        )

        try:
            detected_alerts = (
                threat_detector.analyze_packet(
                    source_ip=ip_layer.src,
                    protocol=protocol,
                    destination_port=destination_port,
                    tcp_flags=tcp_flags
                )
            )

            self.detector_error = None

        except Exception as error:
            detected_alerts = []
            self.detector_error = str(error)

            logger.exception(
                "Packet threat analysis failed"
            )

        # Kopyalama yavaş bir işlemdir; kilidi
        # tutmadan önce yapılır.
        raw_packet = packet.copy()

        with self.lock:
            self.total_packets += 1

            if protocol == "TCP":
                self.tcp_packets += 1

            elif protocol == "UDP":
                self.udp_packets += 1

            elif protocol == "ICMP":
                self.icmp_packets += 1

            self.source_counter[
                ip_layer.src
            ] += 1

            if destination_port is not None:
                self.port_counter[
                    destination_port
                ] += 1

            self.recent_packets.append(
                recent_packet
            )

            for alert in detected_alerts:
                self.security_alerts.appendleft(
                    alert
                )

            self.pending_packets.append(
                packet_record
            )

            self.pending_alerts.extend(
                detected_alerts
            )

            self.raw_packets.append(
                raw_packet
            )

            self.last_updated = captured_at

        # Veritabanına yazma işlemi yakalama thread'ini
        # yavaşlatmasın diye burada yapılmaz; app.py
        # içindeki arka plan döngüsü her saniye kaydeder.

    def handle_arp_packet(self, packet):
        """
        ARP yanıtlarını (is-at) ARP spoofing
        kuralına göre kontrol eder.
        """

        arp_layer = packet[ARP]

        # 2 = is-at (yanıt). İstekler kontrol edilmez.
        if int(arp_layer.op) != 2:
            return

        try:
            alert = threat_detector.analyze_arp_reply(
                ip_value=str(arp_layer.psrc),
                mac_address=str(arp_layer.hwsrc)
            )

            self.detector_error = None

        except Exception as error:
            alert = None
            self.detector_error = str(error)

            logger.exception(
                "ARP analysis failed"
            )

        if alert is None:
            return

        with self.lock:
            self.security_alerts.appendleft(
                alert
            )

            self.pending_alerts.append(
                alert
            )

    def flush_database(self, force=False):
        """
        Bekleyen paketleri ve uyarıları
        SQLite veritabanına toplu kaydeder.
        """

        current_time = monotonic()

        with self.lock:
            should_flush = (
                force
                or (
                    len(self.pending_packets)
                    >= self.DATABASE_BATCH_SIZE
                )
                or (
                    (
                        self.pending_packets
                        or self.pending_alerts
                    )
                    and (
                        current_time
                        - self.last_database_flush
                        >= self.DATABASE_FLUSH_INTERVAL
                    )
                )
            )

            if not should_flush:
                return 0

            packets_to_save = self.pending_packets
            alerts_to_save = self.pending_alerts

            self.pending_packets = []
            self.pending_alerts = []

            self.last_database_flush = (
                current_time
            )

        try:
            save_packets(
                packets_to_save
            )

            if alerts_to_save:
                save_alerts(
                    alerts_to_save
                )

            self.database_error = None

            return len(
                packets_to_save
            )

        except Exception as error:
            self.database_error = str(error)

            logger.exception(
                "Database batch write failed"
            )

            # Geçici bir veritabanı hatasında
            # kayıtların kaybolmasını engeller.
            with self.lock:
                self.pending_packets = (
                    packets_to_save
                    + self.pending_packets
                )

                self.pending_alerts = (
                    alerts_to_save
                    + self.pending_alerts
                )

            return 0

    def get_capture_packets(self):
        """
        PCAP dışa aktarımı için ham
        paketlerin kopyasını döndürür.
        """

        with self.lock:
            return [
                packet.copy()
                for packet in self.raw_packets
            ]

    def get_capture_packet_count(self):
        """
        PCAP dosyasına aktarılabilecek
        paket sayısını döndürür.
        """

        with self.lock:
            return len(
                self.raw_packets
            )

    def get_summary(self):
        """Canlı dashboard verilerini oluşturur."""

        self.check_capture_health()

        with self.lock:
            total_packets = (
                self.total_packets
            )

            tcp_packets = (
                self.tcp_packets
            )

            udp_packets = (
                self.udp_packets
            )

            icmp_packets = (
                self.icmp_packets
            )

            top_sources = [
                {
                    "ip": ip,
                    "packets": count
                }
                for ip, count
                in self.source_counter.most_common(5)
            ]

            top_ports = [
                {
                    "port": port,
                    "packets": count
                }
                for port, count
                in self.port_counter.most_common(5)
            ]

            recent_packets = list(
                self.recent_packets
            )

            security_alerts = list(
                self.security_alerts
            )

            last_updated = (
                self.last_updated.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

        alert_messages = []

        if self.capture_error:
            alert_messages.append(
                self.capture_error
            )

        if self.database_error:
            alert_messages.append(
                "Database error: "
                f"{self.database_error}"
            )

        if self.detector_error:
            alert_messages.append(
                "Detector error: "
                f"{self.detector_error}"
            )

        if self.device_error:
            alert_messages.append(
                "Device tracking error: "
                f"{self.device_error}"
            )

        if self.skipped_packets:
            alert_messages.append(
                f"{self.skipped_packets} packets could not "
                "be processed and were skipped. "
                "See logs/netwatch.log for details."
            )

        for alert in security_alerts:
            alert_messages.append(
                f"[{alert['severity']}] "
                f"{alert['message']}"
            )

        if (
            total_packets == 0
            and not self.capture_error
        ):
            alert_messages.append(
                "Waiting for network packets."
            )

        elif (
            total_packets > 0
            and not alert_messages
        ):
            alert_messages.append(
                "No suspicious activity detected."
            )

        if self.sample_mode:
            data_mode = "sample"

        elif self.running:
            data_mode = "live"

        else:
            data_mode = "unavailable"

        return {
            "total_packets": total_packets,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "icmp_packets": icmp_packets,
            "skipped_packets": self.skipped_packets,
            "alerts": alert_messages,
            "top_sources": top_sources,
            "top_ports": top_ports,
            "recent_packets": recent_packets,
            "last_updated": last_updated,
            "data_mode": data_mode,
            "interface": (
                self.interface
                or "default"
            ),
        }


def is_icmp_packet(packet):
    """
    Paketin ICMP (IPv4) veya ICMPv6
    içerip içermediğini kontrol eder.
    """

    if packet.haslayer(ICMP):
        return True

    # Scapy her ICMPv6 mesaj türü için ayrı bir
    # katman sınıfı kullanır (ICMPv6EchoRequest vb.).
    return any(
        layer.__name__.startswith("ICMPv6")
        for layer in packet.layers()
    )


# Uygulama boyunca kullanılacak tek ağ izleyicisi.
monitor = NetworkMonitor()
