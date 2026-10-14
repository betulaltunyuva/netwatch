# NetWatch — Geliştirme Notları

Projede yapılan iyileştirmelerin ve sırada bekleyen işlerin listesi.
Bir madde tamamlandığında `[x]` olarak işaretleyip "Yapılanlar" bölümüne taşı.

---

## ✅ Yapılanlar

### 1. tur (commit edilmemiş değişikliklerde mevcuttu)

- [x] **Ağ arayüzü seçimi** — `NETWATCH_INTERFACE` ortam değişkeni (`sniffer.py`)
- [x] **Port ayarı** — `NETWATCH_PORT`; CORS izinli adresleri porta göre oluşturuluyor (`app.py`)
- [x] **Yakalama hatası tespiti** — Npcap eksikse / yetki yoksa 1 sn içinde örnek veri moduna geçiş; yakalama sonradan durursa mod "Unavailable" oluyor
- [x] **CSRF koruması** — `/api/data/cleanup` yalnızca JSON ve yerel `Origin` kabul ediyor
- [x] **Detector bellek sızıntısı** — pasif IP kayıtları 60 sn'de bir temizleniyor (`detector.py`)
- [x] **GitHub Actions CI** — `.github/workflows/tests.yml` (Python 3.10 ve 3.12)
- [x] `requirements.txt` kodlaması düzeltildi (UTF-16 → UTF-8)

### 2. tur (2026-10-14)

- [x] **DNS rebinding koruması** — `TRUSTED_HOSTS = ["127.0.0.1", "localhost"]`. Kötü niyetli bir site
      alan adını 127.0.0.1'e yönlendirerek paket/cihaz verilerini okuyamaz; bilinmeyen Host → 400 (`app.py`)
- [x] **Content-Security-Policy başlığı** — sayfalar yalnızca yerel script yükleyebilir ve yalnızca yerel sunucuya bağlanabilir
- [x] **Bozuk paket yakalamayı durdurmuyor** — Scapy, `prn` içindeki hatada yakalamayı tamamen kapatıyordu.
      Artık `process_packet` hatayı loglayıp paketi atlıyor; atlanan sayı dashboard'da gösteriliyor (`sniffer.py`)
- [x] **Canlı yayın döngüsü korumalı** — `send_network_updates` içindeki bir hata artık güncellemeleri kalıcı olarak durdurmuyor
- [x] **Otomatik veri saklama** — `NETWATCH_RETENTION_DAYS` (varsayılan 30, `0` = kapalı). Saatte bir eski kayıtlar siliniyor;
      veritabanı artık sınırsız büyümüyor
- [x] **Pasif cihaz temizliği** — temizlik işlemi, saklama süresi boyunca görülmeyen cihazları da siliyor (`database.py`)
- [x] **Performans** — ham paket kopyası (`packet.copy()`) kilit dışında yapılıyor; kilit daha kısa süre tutuluyor
- [x] Testler 13 → 16 (Host doğrulama, güvenlik başlıkları, bozuk paket, cihaz temizliği)

### 3. tur (2026-10-14)

- [x] **Testler gerçek veritabanına dokunmuyor** — `NETWATCH_DATA_DIR` ortam değişkeni eklendi;
      `tests/test_app.py` artık geçici klasör kullanıyor (`database.py`)
- [x] **Veritabanı yazımı sniffer thread'inden çıkarıldı** — paketler artık yalnızca arka plan döngüsünde
      (saniyede bir) kaydediliyor; yavaş disk paket kaybına yol açmıyor (`sniffer.py`)
- [x] **Hızlı cihaz listesi** — `devices.packet_count` sütunu eklendi, paket kaydedilirken artırılıyor.
      Eski veritabanlarında sütun otomatik ekleniyor ve mevcut paketlerden dolduruluyor; temizlikten sonra yeniden hesaplanıyor
- [x] **IPv6 desteği** — IPv6 ve ICMPv6 paketleri yakalanıyor, sayılıyor, kaydediliyor ve tespit kurallarından geçiyor.
      Uzun adresler tabloları taşırmasın diye CSS'e `overflow-wrap` eklendi
- [x] **Ayarlanabilir tespit eşikleri** — `NETWATCH_<AYAR>` ortam değişkenleri (ör. `NETWATCH_PORT_SCAN_PORT_LIMIT=25`);
      geçersiz değerler loglanıp yok sayılıyor (`detector.py`)
- [x] **ARP spoofing tespiti** — aynı IP 5 dk içinde farklı bir MAC ile duyurulursa HIGH uyarısı.
      Daha uzun aralıklar normal DHCP değişimi sayılıyor
- [x] **Geçmiş grafiğindeki boşluklar** — paket olmayan dakikalar 0 olarak dolduruluyor
- [x] Kullanılmayan `sniffer.get_live_summary()` kaldırıldı
- [x] Testler 16 → 23

---

## 🔜 Yapılacaklar (öncelik sırasıyla)

### Orta öncelik

- [ ] **Temizlik sonrası VACUUM** — silme işlemi dosya boyutunu küçültmüyor. Büyük silmelerden sonra
      `VACUUM` (veya `PRAGMA auto_vacuum = INCREMENTAL`) çalıştırılabilir; Exports sayfasında DB boyutu gösterilebilir.
- [ ] **Daha fazla tespit kuralı** — UDP port taraması, dağıtık SYN flood (hedef bazlı sayım),
      şüpheli port listesi (23, 445, 3389 vb.). Yanlış alarm riskine dikkat.
- [ ] **Eşikleri arayüzden düzenleme** — veritabanındaki `settings` tablosu hâlâ kullanılmıyor; eşikler oraya
      kaydedilip bir ayarlar sayfasından değiştirilebilir (şu an yalnızca ortam değişkeniyle).
- [ ] **IPv6 cihaz keşfi** — `device_manager.is_local_ip` yalnızca IPv4 kabul ediyor; IPv6 cihazlar Devices sayfasında görünmüyor.
- [ ] **Bekleyen kayıtlara üst sınır** — veritabanı uzun süre yazılamazsa `pending_packets` bellekte sınırsız büyüyebilir.

### Düşük öncelik / fikirler

- [ ] PCAP dışa aktarımını diske geçici dosya yazmadan bellekte yapmak (`export_manager.create_pcap_export`)
- [ ] CSV formül enjeksiyonuna karşı `=`, `+`, `-`, `@` ile başlayan hücreleri kaçırmak
- [ ] Logları ayrıca konsola da yazmak (geliştirme sırasında kolaylık)
- [ ] Masaüstü / e-posta bildirimleri (CRITICAL uyarılar için)
- [ ] Docker desteği (Linux'ta `--net=host` ve `NET_RAW` yetkisi gerekir)
- [ ] Uygulama ağa açılacaksa: kimlik doğrulama + üretim sunucusu (şu an yalnızca 127.0.0.1'de çalıştığı için gerekmiyor)

---

## 📝 Notlar

- Testleri çalıştırmak: `venv\Scripts\python -m unittest discover -s tests -v`
- Yeni ortam değişkeni eklenince README'deki **Configuration** tablosunu da güncelle.
- Otomatik temizlik varsayılan olarak açık (30 gün). Verileri daha uzun saklamak için
  `NETWATCH_RETENTION_DAYS` değerini artır veya `0` yap.
