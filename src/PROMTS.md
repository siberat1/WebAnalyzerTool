# Kapsamlı Web Güvenliği Aracı Komutları ve Kullanım Kılavuzu

Bu kılavuz, web uygulamalarının güvenlik duruşunu geliştirmek için aracınızın nasıl kullanılacağına dair ayrıntılı bir referans sunar. Komut satırı işlemleri, gelişmiş yapılandırmalar, CI/CD entegrasyonu ve sorun giderme konularını kapsar.

## 1. Araca Giriş

Aracınız, modern web uygulamaları ve API'lerindeki kritik güvenlik zorluklarını ele almak üzere tasarlanmıştır. Temel amacı, güvenlik açıklarını tespit etmek ve azaltmaya yardımcı olmaktır. Araç, saldırıları simüle ederek, uygulama yanıtlarını analiz ederek ve potansiyel güvenlik zayıflıkları hakkında eyleme geçirilebilir istihbarat sağlayarak çalışır.

- **Dinamik Uygulama Güvenlik Testi (DAST)**: Aracınız, çalışan uygulamaları tarayarak ve canlı API'lere istekler göndererek güvenlik kusurlarını aktif olarak test eden bir DAST aracı olarak sınıflandırılır.
- **Otomatik Tarama**: Sürekli izleme sağlar ve güvenlik açığı değerlendirmesi için gereken zamanı ve kaynakları önemli ölçüde azaltır. Otomasyon, saldırı yüzeyinin otomatik olarak haritalandırılmasını, en son kritik güvenlik açıklarının taranmasını ve iş riskini değerlendirmek için istismarı desteklemeyi mümkün kılar.

## 2. Web Güvenliğinde Temel Kavramlar

Yaygın web uygulaması güvenlik açıklarını anlamak, etkili güvenlik testi için çok önemlidir. **OWASP Top 10**, en kritik 10 web uygulaması güvenlik riskini özetleyen temel bir kaynaktır. Aracınızın yetenekleriyle ilgili bazı temel güvenlik açıkları:

- **A01: Bozuk Erişim Kontrolü**: Yanlış uygulanan erişim kısıtlamaları nedeniyle saldırganların hassas dosyalara, verilere veya işlevlere yetkisiz erişim sağlaması.
- **A02: Kriptografik Hatalar**: Zayıf şifreleme, sabit kodlanmış sırlar veya güncel olmayan algoritmalar nedeniyle hassas verilerin açığa çıkması.
- **A03: Enjeksiyon**:
  - **SQL Enjeksiyonu (SQLi)**: Kötü amaçlı SQL sorgularının girdi verileri aracılığıyla eklenmesi, veritabanı verilerinin okunmasına, değiştirilmesine veya silinmesine olanak tanır.
  - **Siteler Arası Komut Dosyası Çalıştırma (XSS)**: Güvenilen web sitelerine kötü amaçlı istemci tarafı komut dosyalarının enjekte edilmesi.
- **A05: Güvenlik Yanlış Yapılandırması**: Güvenli olmayan yapılandırmalardan kaynaklanan güvenlik açıkları.
- **A07: Kimlik ve Kimlik Doğrulama Hataları**: Zayıf parola politikaları veya kaba kuvvet saldırılarına karşı savunmasızlık.
- **A10: Sunucu Taraflı İstek Sahteciliği (SSRF)**: Saldırganın istenmeyen bir hedefe istek göndermesi.

**Tablo 1: Desteklenen Güvenlik Açığı Türleri ve OWASP Top 10 Eşleştirmesi**

| Güvenlik Açığı Türü | OWASP Top 10 Kategorisi | Tespit Yöntemi | Tipik Ciddiyet |
|---------------------|-------------------------|----------------|----------------|
| Bozuk Erişim Kontrolü | A01:2021 | Oturum yönetimi kusurlarının analizi, yetkisiz kaynak erişimi | Yüksek |
| Kriptografik Hatalar | A02:2021 | Zayıf şifreleme algoritmalarının tespiti | Yüksek |
| SQL Enjeksiyonu | A03:2021 | Girdi alanlarında enjeksiyon kalıpları için aktif tarama | Kritik |
| Siteler Arası Komut Dosyası (XSS) | A03:2021 | Yansıyan, depolanan ve DOM bağlamlarında komut dosyası enjeksiyonu | Yüksek |
| Güvenlik Yanlış Yapılandırması | A05:2021 | Güvenli olmayan varsayılan değerlerin tespiti | Orta |
| Kimlik ve Kimlik Doğrulama Hataları | A07:2021 | Zayıf parola politikaları, kaba kuvvet testi | Yüksek |
| Sunucu Taraflı İstek Sahteciliği (SSRF) | A10:2021 | Doğrulanmamış URL'lerin tespiti | Yüksek |

## 3. Başlarken: Kurulum ve Temel Kullanım

Güvenlik değerlendirmesine başlamak için:

- **Ön Koşullar**: Java tabanlı araçlar için Java Runtime Environment 1.8 veya üzeri gereklidir.
- **Kurulum**: İşletim sistemine özgü yükleyiciyi çalıştırın.
- **Temel Tarama**: `-quickurl http://example.com/ -quickout /path/to/report.xml` komutuyla hızlı bir tarama başlatılır.
- **GUI'siz Mod**: `-cmd` bayrağı ile otomatik komut dosyaları için çalıştırılabilir.
- **Çıktı**: Renk kodlu uyarılar ve bulguların özeti.

## 4. Komut Satırı Arayüzü (CLI) Referansı

CLI, otomasyon ve iş akışlarına entegrasyon için birincil yöntemdir.

### Genel Sözdizimi ve Temel Seçenekler
- `-h` / `-help`: Tüm komut satırı seçeneklerini listeler.
- `-version`: Aracın sürümünü bildirir.
- `-cmd`: Satır içi modda çalıştırır.
- `-daemon`: Arka planda, GUI olmadan çalıştırır.

### Tarama İşlemleri
- **Hedef Belirleme**: `-quickurl <target_url>`
- **Tarama Modları**: Hızlı veya kapsamlı taramalar.
- **Kimlik Doğrulama**: Uzun süreli taramalar için oturum yönetimi.

### Rapor Oluşturma
- **Çıktı Formatları**: `-quickout <file.html/json/md/xml>`
- **Özelleştirme**: Ciddiyet seviyelerine veya güvenlik açığı türlerine göre filtreleme.

### Yapılandırma Geçersiz Kılmaları
- **Doğrudan**: `-config api.key=12345`
- **Dosya ile**: `-configfile <path>`

### Eklenti Yönetimi
- `-addoninstall <addOnId>`, `-addonupdate`, `-addonlist`, `-addonuninstall <addOnId>`

**Tablo 2: Temel CLI Komutları ve Parametreleri**

| Komut/Parametre | Sözdizimi Örneği | Açıklama | Kategori |
|-----------------|------------------|----------|----------|
| -h / -help | [araç_adı] -h | Tüm seçenekleri görüntüler | Genel |
| -version | [araç_adı] -version | Sürümü bildirir | Genel |
| -cmd | [araç_adı] -cmd -quickurl http://example.com/ | Satır içi modda çalıştırır | Genel |
| -daemon | [araç_adı] -daemon | Daemon modunda başlatır | Genel |
| -quickurl | [araç_adı] -quickurl http://target.com/ | Hedef URL’yi belirtir | Tarama |
| -quickout | [araç_adı] -quickurl http://target.com/ -quickout report.html | Çıktı dosyasını belirtir | Raporlama |
| -config | [araç_adı] -config api.key=12345 | Yapılandırma ayarını geçersiz kılar | Yapılandırma |
| -configfile | [araç_adı] -configfile /path/to/config.json | Yapılandırma dosyasını yükler | Yapılandırma |
| -addoninstall | [araç_adı] -addoninstall 1001 | Eklenti yükler | Eklenti Yönetimi |

## 5. Gelişmiş Yapılandırma ve Özelleştirme

### Yapılandırma Dosyaları
- **Format**: JSON veya YAML.
- **Kapsam**: Tarama profilleri ve bağlamlar tanımlanabilir.
- **İçe/Dışa Aktarma**: En iyi uygulamaların paylaşımı için.

### Kimlik Doğrulama Yönetimi
- **Türler**: Form tabanlı, API anahtarları, oturum belirteçleri.
- **Oturum Sürdürme**: Kimlik doğrulama hatalarını önler.

### Kapsam Tanımı ve Optimizasyonu
- **Kurallar**: Dahil etme/hariç tutma, düzenli ifadeler, URL kalıpları.
- **Derinlik ve Süre**: Maksimum bağlantı derinliği ve tarama süresi.

### Performans Ayarı
- **Bellek Tahsisi**: `-Xmx` ile ayarlanabilir.
- **CPU Kullanımı**: JavaScript analizi devre dışı bırakılabilir.
- **Ağ**: Kaynak havuzları ve hız sınırlaması.

**Tablo 3: Temel Yapılandırma Dosyası Parametreleri**

| Kategori | Parametre Adı | Açıklama | Örnek Değer |
|----------|---------------|----------|-------------|
| Kimlik Doğrulama | authentication.type | Kimlik doğrulama yöntemi | "form_based" |
| Kimlik Doğrulama | authentication.url | Oturum açma URL’si | "http://example.com/login" |
| Kapsam | scope.include_urls | Taramaya dahil URL’ler | ["http://example.com/.*"] |
| Kapsam | scope.exclude_urls | Taramadan hariç URL’ler | ["http://example.com/admin/.*"] |
| Performans | performance.max_concurrent_tasks | Maksimum eşzamanlı istek | 10 |
| Raporlama | report.format | Çıktı formatı | "html" |

## 6. CI/CD Boru Hatları ile Entegrasyon

### Faydalar
- **Hız**: Hızlı kod entegrasyonu ve dağıtımı.
- **Kalite**: Hataların ve güvenlik açıklarının engellenmesi.
- **Proaktif Güvenlik**: Erken tespit ve azaltma.
- **Uyumluluk**: Otomatik uyumluluk testleri.

### Entegrasyon Örnekleri
- **Platformlar**: Jenkins, GitLab CI, GitHub Actions.
- **Komutlar**: `-cmd` veya `-daemon` ile otomatik taramalar.

### Güvenli Sır Yönetimi
- **Tavsiye**: Sırları ortam değişkenleriyle yönetin, sabit kodlamadan kaçının.

## 7. Sorun Giderme ve En İyi Uygulamalar

### Yaygın Sorunlar ve Çözümler
- **Bağlantı Hataları**: Hedefin çalıştığını, güvenlik duvarını ve ağ yolunu kontrol edin.
- **Performans Darboğazları**: Bellek tahsisini optimize edin, kapsamı daraltın.
- **Kimlik Doğrulama Sorunları**: Doğru yapılandırma ve oturum yönetimi.
- **Örümcek Döngüleri**: Maksimum süre veya derinlik belirleyin.

### Teşhis Adımları
- **Loglar**: Hata mesajları için logları inceleyin.
- **İstatistikler**: `stats.network.send.failure`, `stats.auth.failure` gibi.
- **Harici Araçlar**: `curl` ile sorun izolasyonu.

### En İyi Uygulamalar
- **Güncellemeler**: Aracı ve eklentileri güncel tutun.
- **Dokümantasyon**: Resmi kılavuz ve SSS’ye başvurun.
- **Topluluk**: Forumlar ve sohbet platformlarına katılın.

**Tablo 4: Yaygın Sorun Giderme Senaryoları**

| Sorun | Belirtiler | Olası Nedenler | Çözüm Adımları |
|-------|------------|----------------|----------------|
| Hedefe Bağlanılamıyor | Tarama başarısız olur | Hedef kapalı, güvenlik duvarı engelliyor | Hedefin çalıştığını doğrulayın, güvenlik duvarını kontrol edin |
| Tarama Yavaş | Yüksek CPU/bellek kullanımı | Ağır yük, pahalı özellikler | Bellek tahsisini optimize edin, kapsamı daraltın |
| Kimlik Doğrulama Hataları | Eksik sonuçlar | Yanlış yapılandırma | Kimlik bilgilerini doğrulayın, oturum süresini yönetin |

## 8. Güvenlik Çerçeveleriyle Uyum

### OWASP Web Güvenliği Test Kılavuzu (WSTG)
- **Aşama**: Özellikle “Dağıtım Sırasında” sızma testi ve yapılandırma yönetimi.
- **Katkı**: Güvenli tasarım ilkelerini iyileştirir.

### NIST Siber Güvenlik Çerçevesi
- **Tanımla**: Riskleri anlamak için tarama sonuçları.
- **Koru**: Güvenlik açıklarını belirleyerek katkı.
- **Tespit Et**: Otomatik tarama ile tehdit tespiti.
- **Yanıt Ver**: Ayrıntılı raporlar ve düzeltme rehberliği.

## 9. Ek Kaynaklar ve Topluluk Desteği
- **Dokümantasyon**: Resmi kılavuzlar ve API belgeleri.
- **SSS**: Yaygın sorular ve çözümler.
- **Topluluk**: Forumlar, Slack kanalları, sorun takipçileri.

## Sonuçlar

Aracınız, dinamik uygulama güvenlik testi için güçlü bir araçtır. Otomasyon, CI/CD entegrasyonu ve kapsamlı yapılandırma seçenekleriyle, güvenlik açıklarını erken tespit eder ve düzeltme maliyetlerini azaltır. SAST, SCA ve WAF’lerle tamamlayıcı bir ekosistemde en etkili şekilde çalışır. Topluluk desteği ve düzenli güncellemeler, aracın modern tehdit ortamında sürekli alaka düzeyini sağlar.
