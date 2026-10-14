import atexit
import os
import secrets
from time import monotonic

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_file
)

from flask_socketio import SocketIO

from database import (
    cleanup_old_records,
    get_history_data,
    init_database
)

from device_manager import get_devices_data

from export_manager import (
    create_alert_csv,
    create_packet_csv,
    create_pcap_export,
    get_export_information
)

from logger import get_logger
from packet_search import search_packets
from sniffer import monitor


logger = get_logger(__name__)


# Flask uygulamasını oluşturur.
app = Flask(__name__)


# Her çalıştırmada güvenli bir uygulama anahtarı üretir.
# İstenirse NETWATCH_SECRET_KEY ortam değişkeninden de alınabilir.
app.config["SECRET_KEY"] = (
    os.environ.get("NETWATCH_SECRET_KEY")
    or secrets.token_hex(32)
)


def get_server_port():
    """
    Sunucu portunu NETWATCH_PORT ortam
    değişkeninden okur. Geçersizse 5000 kullanır.
    """

    try:
        port = int(
            os.environ.get(
                "NETWATCH_PORT",
                5000
            )
        )

    except (TypeError, ValueError):
        return 5000

    if 1 <= port <= 65535:
        return port

    return 5000


def get_retention_days():
    """
    Otomatik veri temizliği için saklama süresini
    NETWATCH_RETENTION_DAYS ortam değişkeninden okur.
    0 verilirse otomatik temizlik kapatılır.
    """

    try:
        days = int(
            os.environ.get(
                "NETWATCH_RETENTION_DAYS",
                30
            )
        )

    except (TypeError, ValueError):
        return 30

    if days <= 0:
        return 0

    return min(days, 365)


SERVER_HOST = "127.0.0.1"
SERVER_PORT = get_server_port()

RETENTION_DAYS = get_retention_days()

# Otomatik temizliğin kaç saniyede bir çalışacağı.
CLEANUP_INTERVAL_SECONDS = 3600


# Yalnızca bu adlarla gelen isteklere yanıt verilir.
# Kötü niyetli bir sitenin alan adını 127.0.0.1'e
# yönlendirip (DNS rebinding) verileri okumasını engeller.
app.config["TRUSTED_HOSTS"] = [
    "127.0.0.1",
    "localhost"
]


# Uygulamaya yalnızca bu yerel adreslerden
# gelen tarayıcı isteklerine izin verilir.
ALLOWED_ORIGINS = [
    f"http://127.0.0.1:{SERVER_PORT}",
    f"http://localhost:{SERVER_PORT}"
]


CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self' "
        f"ws://127.0.0.1:{SERVER_PORT} "
        f"ws://localhost:{SERVER_PORT}",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    ]
)


# SocketIO bağlantısına sadece yerel adreslerden izin verir.
socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_ORIGINS
)


# Veritabanını ve tabloları oluşturur.
init_database()


@app.after_request
def add_security_headers(response):
    """
    Tarayıcı yanıtlarına temel
    güvenlik başlıklarını ekler.
    """

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    # Sayfaların yalnızca kendi dosyalarını
    # yüklemesine ve yerel sunucuya bağlanmasına
    # izin verir. Şablonlar satır içi script
    # kullandığı için 'unsafe-inline' gereklidir.
    response.headers[
        "Content-Security-Policy"
    ] = CONTENT_SECURITY_POLICY

    return response


@app.route("/")
def home():
    """Canlı ağ izleme sayfasını açar."""

    summary = monitor.get_summary()

    return render_template(
        "index.html",
        summary=summary
    )


@app.route("/history")
def history():
    """Trafik geçmişi sayfasını açar."""

    history_data = get_history_data(
        minutes=60
    )

    return render_template(
        "history.html",
        history=history_data
    )


@app.route("/api/history")
def history_api():
    """Trafik geçmişini JSON olarak döndürür."""

    minutes = request.args.get(
        "minutes",
        default=60
    )

    return jsonify(
        get_history_data(
            minutes=minutes
        )
    )


@app.route("/search")
def packet_search_page():
    """Gelişmiş paket arama sayfasını açar."""

    return render_template(
        "search.html"
    )


@app.route("/api/packets/search")
def packet_search_api():
    """
    Girilen filtrelere göre
    veritabanındaki paketleri arar.
    """

    result = search_packets(
        source_ip=request.args.get(
            "source_ip",
            default=""
        ),

        destination_ip=request.args.get(
            "destination_ip",
            default=""
        ),

        protocol=request.args.get(
            "protocol",
            default=""
        ),

        port=request.args.get(
            "port",
            default=""
        ),

        start_time=request.args.get(
            "start_time",
            default=""
        ),

        end_time=request.args.get(
            "end_time",
            default=""
        ),

        limit=request.args.get(
            "limit",
            default=100
        )
    )

    return jsonify(
        result
    )


@app.route("/devices")
def devices_page():
    """Yerel ağ cihazları sayfasını açar."""

    return render_template(
        "devices.html"
    )


@app.route("/api/devices")
def devices_api():
    """
    Yerel ağda tespit edilen cihazları
    JSON olarak döndürür.
    """

    return jsonify(
        get_devices_data()
    )


@app.route("/exports")
def exports_page():
    """Dışa aktarma sayfasını açar."""

    return render_template(
        "exports.html"
    )


@app.route("/api/exports/info")
def exports_information_api():
    """
    Dışa aktarılabilecek kayıt
    sayılarını JSON olarak döndürür.
    """

    export_information = (
        get_export_information()
    )

    export_information["pcap_packets"] = (
        monitor.get_capture_packet_count()
    )

    return jsonify(
        export_information
    )


@app.post("/api/data/cleanup")
def cleanup_data_api():
    """
    Belirlenen günden eski paket ve
    güvenlik uyarısı kayıtlarını temizler.
    """

    # Başka bir web sitesinin tarayıcı üzerinden
    # form göndererek kayıtları silmesini (CSRF)
    # engeller. Sitelerarası JSON istekleri
    # tarayıcının CORS kontrolüne takılır.
    if not request.is_json:
        abort(
            415,
            description=(
                "Cleanup requests must use "
                "application/json."
            )
        )

    origin = request.headers.get(
        "Origin"
    )

    if (
        origin is not None
        and origin not in ALLOWED_ORIGINS
    ):
        abort(
            403,
            description=(
                "Cross-origin cleanup requests "
                "are not allowed."
            )
        )

    request_data = request.get_json(
        silent=True
    ) or {}

    result = cleanup_old_records(
        days=request_data.get(
            "retention_days",
            30
        )
    )

    logger.info(
        "Old records cleaned: %s packets, %s alerts, %s devices",
        result["deleted_packets"],
        result["deleted_alerts"],
        result["deleted_devices"]
    )

    return jsonify(
        result
    )


@app.route("/export/packets.csv")
def export_packets_csv():
    """
    Kayıtlı paketleri CSV dosyası
    olarak indirir.
    """

    export_result = create_packet_csv(
        source_ip=request.args.get(
            "source_ip",
            default=""
        ),

        destination_ip=request.args.get(
            "destination_ip",
            default=""
        ),

        protocol=request.args.get(
            "protocol",
            default=""
        ),

        port=request.args.get(
            "port",
            default=""
        ),

        start_time=request.args.get(
            "start_time",
            default=""
        ),

        end_time=request.args.get(
            "end_time",
            default=""
        ),

        limit=request.args.get(
            "limit",
            default=50000
        )
    )

    return send_file(
        export_result["buffer"],
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name=export_result["filename"]
    )


@app.route("/export/alerts.csv")
def export_alerts_csv():
    """
    Güvenlik uyarılarını CSV
    dosyası olarak indirir.
    """

    export_result = create_alert_csv(
        limit=request.args.get(
            "limit",
            default=10000
        )
    )

    return send_file(
        export_result["buffer"],
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name=export_result["filename"]
    )


@app.route("/export/capture.pcap")
def export_capture_pcap():
    """
    Bellekte tutulan ham paketleri
    PCAP dosyası olarak indirir.
    """

    packets = (
        monitor.get_capture_packets()
    )

    export_result = create_pcap_export(
        packets
    )

    if export_result is None:
        abort(
            400,
            description=(
                "No captured packets are available "
                "for PCAP export."
            )
        )

    return send_file(
        export_result["buffer"],
        mimetype="application/vnd.tcpdump.pcap",
        as_attachment=True,
        download_name=export_result["filename"]
    )


def send_network_updates():
    """
    Canlı ağ verilerini her saniye
    bağlı tarayıcılara gönderir.
    """

    last_cleanup = 0.0

    while True:
        try:
            # Bekleyen veritabanı kayıtlarını kaydeder.
            monitor.flush_database()

            if (
                RETENTION_DAYS
                and monotonic() - last_cleanup
                >= CLEANUP_INTERVAL_SECONDS
            ):
                last_cleanup = monotonic()
                run_automatic_cleanup()

            summary = monitor.get_summary()

            socketio.emit(
                "network_update",
                summary
            )

        except Exception:
            # Tek bir hata canlı güncellemeleri
            # tamamen durdurmamalıdır.
            logger.exception(
                "Live update loop failed"
            )

        socketio.sleep(1)


def run_automatic_cleanup():
    """
    NETWATCH_RETENTION_DAYS süresinden eski
    kayıtları otomatik olarak temizler.
    """

    result = cleanup_old_records(
        days=RETENTION_DAYS
    )

    if (
        result["deleted_packets"]
        or result["deleted_alerts"]
        or result["deleted_devices"]
    ):
        logger.info(
            "Automatic cleanup (%s days): "
            "%s packets, %s alerts, %s devices",
            RETENTION_DAYS,
            result["deleted_packets"],
            result["deleted_alerts"],
            result["deleted_devices"]
        )

    return result


# Uygulama kapanırken paket yakalamayı durdurur
# ve bekleyen kayıtları veritabanına yazar.
atexit.register(
    monitor.stop
)


if __name__ == "__main__":
    monitor.start()

    socketio.start_background_task(
        send_network_updates
    )

    print(
        "NetWatch is running at "
        f"http://{SERVER_HOST}:{SERVER_PORT}"
    )

    socketio.run(
        app,
        host=SERVER_HOST,
        port=SERVER_PORT,
        debug=(
            os.environ.get(
                "NETWATCH_DEBUG",
                "0"
            ) == "1"
        ),
        use_reloader=False,

        # Uygulama yalnızca 127.0.0.1 üzerinde dinler.
        # Bu ayar olmadan Flask-SocketIO, terminal
        # dışında (IDE, arka plan, servis) başlatılınca
        # hata vererek kapanır.
        allow_unsafe_werkzeug=True
    )