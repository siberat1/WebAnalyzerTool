# WebAnalyzerTool

## 👥 Takım Üyeleri
- Berat Nurlu

## 🛠 Açıklama
**WebAnalyzerTool**, modern web uygulamalarında sıkça karşılaşılan güvenlik açıklarını otomatik olarak tespit etmek üzere geliştirilmiş gelişmiş bir tarama ve analiz aracıdır. Araç; XSS (Cross-Site Scripting), SQL Injection, CSRF, güvensiz header yapılandırmaları, JavaScript kaynaklı güvenlik riskleri ve dosya yükleme açıklıkları gibi birçok zafiyeti tarayabilir. Asenkron yapı kullanılarak yüksek performanslı tarama yapılırken, bulunan zafiyetler JSON ve HTML raporu olarak çıktı verilir. Otomatik oturum açma desteği ve özelleştirilebilir payload dosyaları sayesinde test süreci maksimum esneklikle yürütülür.

## 🎯 Hedefler
- Web uygulamalarındaki temel güvenlik açıklarının tespiti
- Otomatikleştirilmiş form, URL, path ve JavaScript tabanlı parametre testleri
- Gelişmiş XSS ve SQL Injection payload analizi
- Güvensiz HTTP header konfigürasyonlarının raporlanması
- Özelleştirilebilir payload desteği ile kapsamlı tarama yapılması
- Otomatik giriş mekanizması ile oturumlu sayfaların test edilebilmesi
- HTML ve JSON formatlarında raporlama
- Güvenlik farkındalığı ve hızlı güvenlik testi süreçlerine katkı sağlama

## 🔗 Bağlantılar
- 📦 [Payload Dosyaları Örneği](payloads/xss.txt)
- 📘 [HTML Rapor Şablonu](report_template.html)
- 📝 [JSON Sonuç Çıktısı](scan_results.json)
- 🌐 [Proje Web Sitesi (opsiyonel)](https://github.com/kullaniciadi/WebAnalyzerTool)
- 🧪 Kullanım Örneği:
  ```bash
  python3 WebAnalyzerTool.py https://hedefsite.com --depth 3 --xss-payloads payloads/xss.txt --sql-payloads payloads/sql.txt --report-output output/report.html
  ```

## 🚀 Özellikler
- [x] Asenkron tarama (aiohttp)
- [x] Otomatik CSRF, XSS, SQLi, File Upload, JS analizleri
- [x] Renkli terminal çıktısı (colorama)
- [x] Gelişmiş form ve parametre analiz motoru
- [x] Güzel HTML raporlama (jinja2 destekli)

## 📂 Kurulum
```bash
git clone https://github.com/siberat1/WebAnalyzerTool.git
cd WebAnalyzerTool
pip install -r requirements.txt
```

## 🧑‍💻 Kullanım
```bash
python3 WebAnalyzerTool.py <URL> [seçenekler]
```

### Temel Seçenekler:
- `--depth`: Maksimum tarama derinliği
- `--xss-payloads`: XSS payload dosyası
- `--sql-payloads`: SQLi payload dosyası
- `--auth-url`: Otomatik giriş yapılacak URL
- `--auth-data`: Giriş formu JSON verisi
- `--report-output`: HTML rapor çıkışı

---

> ⚠️ Bu araç yalnızca eğitim ve güvenlik testleri amacıyla kullanılmalıdır. Yetkisiz sistemlerde kullanımı hukuka aykırıdır.
