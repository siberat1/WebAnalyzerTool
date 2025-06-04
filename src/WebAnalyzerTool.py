# Gerekli kütüphaneleri içe aktarıyoruz
# argparse: Komut satırı argümanlarını işlemek için
# asyncio: Asenkron programlama için
# json: JSON formatında veri işleme
# logging: Hata ve bilgi mesajlarını kaydetmek için
# re: Düzenli ifadelerle (regex) string işleme
# urllib.parse: URL'leri ayrıştırmak ve işlemek için
# aiohttp: Asenkron HTTP istekleri için
# BeautifulSoup: HTML ve XML ayrıştırma için
# dataclasses: Veri sınıfları oluşturmak için
# functools.wraps: Dekoratörlerde fonksiyon meta verilerini korumak için
# jinja2: HTML şablonları oluşturmak için
# os: Dosya sistemi işlemleri için
# time: Zamanla ilgili işlemler için
# colorama: Konsolda renkli çıktılar için
# tabulate: Tablo formatında veri gösterimi için
import argparse
import asyncio
import json
import logging
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import aiohttp
from bs4 import BeautifulSoup
from dataclasses import dataclass
from functools import wraps
from jinja2 import Environment, FileSystemLoader, Template
import os
import time
from colorama import init, Fore, Style
from tabulate import tabulate

# Colorama'nın otomatik sıfırlama özelliğini başlatıyoruz (renkli çıktılar için)
init(autoreset=True)

# Varsayılan HTML rapor şablonunu tanımlıyoruz
# Bu şablon, tarama sonuçlarını HTML formatında göstermek için kullanılacak
DEFAULT_TEMPLATE = """
<html>
<head>
    <title>Security Scan Report</title>
    <style>table { border-collapse: collapse; } th, td { border: 1px solid black; padding: 5px; }</style>
</head>
<body>
    <h1>Security Scan Report - {{ date }}</h1>
    <table>
        <tr><th>Type</th><th>URL</th><th>Method</th><th>Parameter</th><th>Payload</th></tr>
        {% for result in results %}
        <tr>
            <td>{{ result.type|e }}</td>
            <td>{{ result.url|e }}</td>
            <td>{{ result.method|e }}</td>
            <td>{{ result.parameter|e or 'N/A' }}</td>
            <td>{{ result.payload|e }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

# Config sınıfı: Tarayıcının yapılandırma ayarlarını tutar
@dataclass
class Config:
    # XSS ve SQL enjeksiyonu için varsayılan payload'lar tanımlanıyor
    PAYLOADS_XSS: List[str] = None
    PAYLOADS_SQL: List[str] = None
    USER_AGENT: str = "SecurityScanner/1.0"  # HTTP isteklerinde kullanılacak kullanıcı ajanı
    TIMEOUT: int = 10  # HTTP istekleri için zaman aşımı süresi (saniye)
    MAX_CONCURRENT: int = 50  # Aynı anda yapılabilecek maksimum eşzamanlı istek sayısı
    MAX_DEPTH: int = 5  # Web tarayıcısının tarama derinliği (link takibi sınırı)
    RATE_LIMIT: int = 10  # Saniyede yapılacak maksimum istek sayısı (hız sınırlama)
    PROXY: str = None  # Proxy sunucusu URL'si (opsiyonel)
    AUTH_URL: str = None  # Kimlik doğrulama URL'si (opsiyonel)
    AUTH_DATA: Dict[str, str] = None  # Kimlik doğrulama için veri (opsiyonel)
    REPORT_TEMPLATE: str = "report_template.html"  # HTML rapor şablonu dosya adı

    # __post_init__: Config sınıfı başlatıldığında çalışır
    def __post_init__(self):
        # Eğer XSS payload'ları belirtilmemişse varsayılanları kullanıyoruz
        if self.PAYLOADS_XSS is None:
            self.PAYLOADS_XSS = [
                "<script>alert('XSS')</script>",
                "';alert('XSS');//",
                "\"><script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
            ]
        # Eğer SQL payload'ları belirtilmemişse varsayılanları kullanıyoruz
        if self.PAYLOADS_SQL is None:
            self.PAYLOADS_SQL = [
                "' OR 1=1 --",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL, username, password FROM users --",
                "1; WAITFOR DELAY '0:0:5' --",
            ]

# ColoredStreamHandler sınıfı: Log mesajlarını renklendirmek için özelleştirilmiş bir logging handler
class ColoredStreamHandler(logging.StreamHandler):
    # Log seviyelerine göre renk tanımları
    LEVEL_COLORS = {
        logging.DEBUG: Fore.LIGHTBLACK_EX,
        logging.INFO: Fore.BLUE,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.YELLOW,
        logging.CRITICAL: Fore.RED
    }

    # emit: Log mesajlarını formatlayıp renkli şekilde konsola yazdırır
    def emit(self, record):
        try:
            msg = self.format(record)
            color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)
            # Eğer mesajda XSS, SQL gibi güvenlik açıkları geçiyorsa kırmızı renkte göster
            if any(vuln in msg.lower() for vuln in ['xss', 'sql injection', 'csrf', 'file upload', 'header issue', 'javascript issue']):
                color = Fore.RED
            print(f"{color}{msg}{Style.RESET_ALL}")
        except Exception:
            self.handleError(record)

# Utils sınıfı: Yardımcı fonksiyonları içerir (URL işleme, parametre çıkarma vb.)
class Utils:
    # is_same_domain: Verilen URL'nin hedef domain ile aynı olup olmadığını kontrol eder
    @staticmethod
    def is_same_domain(url: str, domain: str) -> bool:
        return urlparse(url).netloc == domain

    # extract_form_params: HTML formundan input parametrelerini çıkarır
    @staticmethod
    def extract_form_params(form: BeautifulSoup) -> Dict[str, str]:
        params = {}
        for tag in form.find_all(['input', 'textarea', 'select']):
            name = tag.get('name')
            if name:
                params[name] = tag.get('value', '')
        return params

    # extract_query_params: URL'deki sorgu (query) parametrelerini çıkarır
    @staticmethod
    def extract_query_params(url: str) -> Dict[str, List[str]]:
        return parse_qs(urlparse(url).query)

    # extract_path_params: URL yolundan (path) dinamik parametreleri çıkarır
    @staticmethod
    def extract_path_params(url: str) -> Dict[str, str]:
        path = urlparse(url).path
        segments = path.split('/')
        params = {}
        for i, seg in enumerate(segments):
            if seg and (seg.isdigit() or (seg.isalnum() and len(seg) > 5)):
                params[f"path_param_{i}"] = seg
        return params

    # extract_js_params: HTML içindeki JavaScript kodundan parametre isimlerini çıkarır
    @staticmethod
    def extract_js_params(html: str) -> Set[str]:
        params = set()
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')
        param_patterns = [
            r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
            r'\bdata-[a-zA-Z0-9_]+',
            r'\bvar\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        ]
        for script in scripts:
            if script.string:
                for pattern in param_patterns:
                    matches = re.findall(pattern, script.string)
                    params.update(matches)
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
        for comment in comments:
            matches = re.findall(r'[\?&]([a-zA-Z_][a-zA-Z0-9_]*)=', comment)
            params.update(matches)
        return params

    # sanitize_url: URL'yi temizler ve temel URL ile birleştirir
    @staticmethod
    def sanitize_url(url: str, base_url: str) -> str:
        return urljoin(base_url, url.strip())

    # rate_limit: HTTP isteklerini hız sınırlamasına tabi tutar
    @staticmethod
    def rate_limit(semaphore: asyncio.Semaphore, rate: int):
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                async with semaphore:
                    result = await func(*args, **kwargs)
                    await asyncio.sleep(1 / rate)
                    return result
                return wrapper
        return decorator

    # has_file_upload: Formda dosya yükleme alanı olup olmadığını kontrol eder
    @staticmethod
    def has_file_upload(form: BeautifulSoup) -> bool:
        return bool(form.find('input', type='file'))

# Detector sınıfı: Güvenlik açıklarını tespit eden fonksiyonları içerir
class Detector:
    # check_xss: XSS (Cross-Site Scripting) açığını kontrol eder
    @staticmethod
    async def check_xss(response_text: str, payload: str) -> bool:
        patterns = [
            rf"<script[^>]*>.*{re.escape(payload)}.*</script>",
            rf"on\w+=[\'\"]{re.escape(payload)}[\'\"]",
            rf"javascript:{re.escape(payload)}",
        ]
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return payload in response_text

    # check_sql_injection: SQL enjeksiyon açığını kontrol eder
    @staticmethod
    async def check_sql_injection(response_text: str, original_text: str, payload: str) -> bool:
        error_patterns = [
            r"mysql_fetch",
            r"sql syntax",
            r"unclosed quotation",
            r"unknown column",
        ]
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE) and pattern not in original_text:
                return True
        return False

    # check_csrf_protection: Formda CSRF koruması olup olmadığını kontrol eder
    @staticmethod
    def check_csrf_protection(form: BeautifulSoup) -> bool:
        return bool(form.find('input', {'name': re.compile(r'csrf|token', re.I)}))

    # analyze_headers: HTTP başlıklarını analiz eder ve eksik güvenlik başlıklarını tespit eder
    @staticmethod
    def analyze_headers(headers: Dict[str, str]) -> List[str]:
        issues = []
        if 'Content-Security-Policy' not in headers:
            issues.append("Missing Content-Security-Policy header")
        if 'X-Frame-Options' not in headers:
            issues.append("Missing X-Frame-Options header")
        if 'X-Content-Type-Options' not in headers:
            issues.append("Missing X-Content-Type-Options header")
        return issues

    # basic_js_analysis: JavaScript kodunda tehlikeli fonksiyonları (eval, document.write) kontrol eder
    @staticmethod
    def basic_js_analysis(html: str) -> List[str]:
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')
        issues = []
        for script in scripts:
            if script.string and 'eval(' in script.string:
                issues.append("Use of eval() detected in JavaScript")
            if script.string and 'document.write' in script.string:
                issues.append("Use of document.write() detected in JavaScript")
        return issues

# SecurityTester sınıfı: Web uygulamasını güvenlik açıkları için test eder
class SecurityTester:
    # __init__: Sınıfı başlatır, HTTP oturumu, yapılandırma ve dedektör alır
    def __init__(self, session: aiohttp.ClientSession, config: Config, detector: Detector):
        self.session = session
        self.config = config
        self.detector = detector

    # test_form: HTML formlarını XSS, SQL enjeksiyonu, CSRF ve dosya yükleme açıkları için test eder
    async def test_form(self, url: str, method: str, params: Dict[str, str], form: BeautifulSoup) -> List[Dict]:
        results = []
        for param in params:
            for payload in self.config.PAYLOADS_XSS:
                test_params = {k: payload if k == param else v for k, v in params.items()}
                try:
                    if method.lower() == 'post':
                        async with self.session.post(url, data=test_params) as response:
                            text = await response.text()
                            if await self.detector.check_xss(text, payload):
                                results.append({
                                    'type': 'XSS',
                                    'url': url,
                                    'method': method,
                                    'parameter': param,
                                    'payload': payload
                                })
                    else:
                        async with self.session.get(url, params=test_params) as response:
                            text = await response.text()
                            if await self.detector.check_xss(text, payload):
                                results.append({
                                    'type': 'XSS',
                                    'url': url,
                                    'method': method,
                                    'parameter': param,
                                    'payload': payload
                                })
                except aiohttp.ClientError as e:
                    logging.error(f"Form XSS test failed for {url}: {e}")

            for payload in self.config.PAYLOADS_SQL:
                test_params = {k: payload if k == param else v for k, v in params.items()}
                try:
                    if method.lower() == 'post':
                        async with self.session.post(url, data=test_params) as response:
                            text = await response.text()
                            original_text = await (await self.session.get(url)).text()
                            if await self.detector.check_sql_injection(text, original_text, payload):
                                results.append({
                                    'type': 'SQL Injection',
                                    'url': url,
                                    'method': method,
                                    'parameter': param,
                                    'payload': payload
                                })
                    else:
                        async with self.session.get(url, params=test_params) as response:
                            text = await response.text()
                            original_text = await (await self.session.get(url)).text()
                            if await self.detector.check_sql_injection(text, original_text, payload):
                                results.append({
                                    'type': 'SQL Injection',
                                    'url': url,
                                    'method': method,
                                    'parameter': param,
                                    'payload': payload
                                })
                except aiohttp.ClientError as e:
                    logging.error(f"Form SQL test failed for {url}: {e}")

        if not self.detector.check_csrf_protection(form):
            results.append({
                'type': 'CSRF',
                'url': url,
                'method': method,
                'parameter': None,
                'payload': 'No CSRF token detected'
            })

        if Utils.has_file_upload(form):
            file_payload = {'file': ('test.php', b'<?php echo "Vulnerable"; ?>', 'application/php')}
            try:
                async with self.session.post(url, data=file_payload) as response:
                    text = await response.text()
                    if 'Vulnerable' in text:
                        results.append({
                            'type': 'File Upload',
                            'url': url,
                            'method': method,
                            'parameter': 'file',
                            'payload': 'Malicious PHP file'
                        })
            except aiohttp.ClientError as e:
                logging.error(f"File upload test failed for {url}: {e}")

        return results

    # test_query_params: URL sorgu parametrelerini XSS ve SQL enjeksiyonu için test eder
    async def test_query_params(self, url: str, query_params: Dict[str, List[str]]) -> List[Dict]:
        results = []
        parsed_url = urlparse(url)
        try:
            async with self.session.get(url) as response:
                original_text = await response.text()
        except aiohttp.ClientError as e:
            logging.error(f"Failed to fetch original page {url} for query param testing: {e}")
            original_text = ""

        for param in query_params:
            for payload in self.config.PAYLOADS_XSS:
                test_params = {k: [payload] if k == param else v for k, v in query_params.items()}
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
                try:
                    async with self.session.get(test_url) as response:
                        text = await response.text()
                        if await self.detector.check_xss(text, payload):
                            results.append({
                                'type': 'XSS',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                except aiohttp.ClientError as e:
                    logging.error(f"Query XSS test failed for {test_url}: {e}")

            for payload in self.config.PAYLOADS_SQL:
                test_params = {k: [payload] if k == param else v for k, v in query_params.items()}
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params, doseq=True)))
                try:
                    async with self.session.get(test_url) as response:
                        text = await response.text()
                        if await self.detector.check_sql_injection(text, original_text, payload):
                            results.append({
                                'type': 'SQL Injection',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                except aiohttp.ClientError as e:
                    logging.error(f"Query SQL test failed for {test_url}: {e}")
        return results

    # test_path_params: URL yol parametrelerini XSS ve SQL enjeksiyonu için test eder
    async def test_path_params(self, url: str, path_params: Dict[str, str]) -> List[Dict]:
        results = []
        parsed_url = urlparse(url)
        try:
            async with self.session.get(url) as response:
                original_text = await response.text()
        except aiohttp.ClientError as e:
            logging.error(f"Failed to fetch original page {url} for path param testing: {e}")
            original_text = ""

        for param in path_params:
            for payload in self.config.PAYLOADS_XSS:
                test_params = {param: payload}
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params)))
                try:
                    async with self.session.get(test_url) as response:
                        text = await response.text()
                        if await self.detector.check_xss(text, payload):
                            results.append({
                                'type': 'XSS',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                except aiohttp.ClientError as e:
                    logging.error(f"Path XSS test failed for {test_url}: {e}")

            for payload in self.config.PAYLOADS_SQL:
                test_params = {param: payload}
                test_url = urlunparse(parsed_url._replace(query=urlencode(test_params)))
                try:
                    async with self.session.get(test_url) as response:
                        text = await response.text()
                        if await self.detector.check_sql_injection(text, original_text, payload):
                            results.append({
                                'type': 'SQL Injection',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                except aiohttp.ClientError as e:
                    logging.error(f"Path SQL test failed for {test_url}: {e}")
        return results

    # test_js_params: JavaScript parametrelerini XSS ve SQL enjeksiyonu için test eder
    async def test_js_params(self, url: str, js_params: Set[str]) -> List[Dict]:
        results = []
        try:
            async with self.session.get(url) as response:
                original_text = await response.text()
        except aiohttp.ClientError as e:
            logging.error(f"Failed to fetch original page {url} for JS param testing: {e}")
            original_text = ""

        for param in js_params:
            for payload in self.config.PAYLOADS_XSS:
                test_params = {param: payload}
                test_url = urlunparse(urlparse(url)._replace(query=urlencode(test_params)))
                try:
                    async with self.session.get(test_url) as response:
                        text = await response.text()
                        if await self.detector.check_xss(text, payload):
                            results.append({
                                'type': 'XSS',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                except aiohttp.ClientError as e:
                    logging.error(f"JS XSS test failed for {test_url}: {e}")

            for payload in self.config.PAYLOADS_SQL:
                test_params = {param: payload}
                test_url = urlunparse(urlparse(url)._replace(query=urlencode(test_params)))
                try:
                    async with self.session.get(test_url) as response:
                        text = await response.text()
                        if await self.detector.check_sql_injection(text, original_text, payload):
                            results.append({
                                'type': 'SQL Injection',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            })
                except aiohttp.ClientError as e:
                    logging.error(f"JS SQL test failed for {test_url}: {e}")
        return results

# Crawler sınıfı: Web sitesini tarar ve güvenlik testlerini gerçekleştirir
class Crawler:
    # __init__: Tarayıcıyı başlatır, başlangıç URL'si, yapılandırma ve HTTP oturumu alır
    def __init__(self, start_url: str, config: Config, session: aiohttp.ClientSession):
        self.start_url = start_url
        self.config = config
        self.session = session
        self.visited: Set[str] = set()  # Ziyaret edilen URL'lerin kümesi
        self.to_visit: List[Tuple[str, int]] = [(start_url, 0)]  # Ziyaret edilecek URL'ler ve derinlik
        self.domain = urlparse(start_url).netloc  # Hedef domain
        self.tester = SecurityTester(session, config, Detector())  # Güvenlik test cihazı
        self.results: List[Dict] = []  # Bulunan güvenlik açıklarının listesi
        self.semaphore = asyncio.Semaphore(config.MAX_CONCURRENT)  # Eşzamanlı istek sınırı
        self.rate_semaphore = asyncio.Semaphore(config.RATE_LIMIT)  # Hız sınırlama semaforu

    # fetch_page: Belirtilen URL'den sayfayı getirir ve HTML ile başlıkları döndürür
    async def fetch_page(self, url: str) -> Tuple[str, Dict[str, str]]:
        @Utils.rate_limit(self.rate_semaphore, self.config.RATE_LIMIT)
        async def _fetch():
            try:
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=self.config.TIMEOUT)) as response:
                    return await response.text(), dict(response.headers)
            except aiohttp.ClientError as e:
                logging.error(f"Failed to fetch {url}: {e}")
                return "", {}
        return await _fetch()

    # crawl: Web sitesini tarar ve güvenlik testlerini yürütür
    async def crawl(self) -> List[Dict]:
        tasks = []
        while self.to_visit:
            url, depth = self.to_visit.pop(0)
            if url in self.visited or depth > self.config.MAX_DEPTH:
                logging.debug(f"Skipped {url} (Depth: {depth}, Visited: {url in self.visited})")
                continue
            self.visited.add(url)
            logging.info(f"Crawling: {url} (Depth: {depth}, Queue size: {len(self.to_visit)})")
            tasks.append(self.process_page(url, depth))
            if len(tasks) >= self.config.MAX_CONCURRENT or not self.to_visit:
                try:
                    await asyncio.gather(*tasks, return_exceptions=True)
                except Exception as e:
                    logging.error(f"Error during task execution: {e}")
                tasks = []
        return self.results

    # process_page: Tek bir sayfayı işler, bağlantıları ve parametreleri analiz eder
    async def process_page(self, url: str, depth: int):
        html, headers = await self.fetch_page(url)
        if not html:
            return

        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception as e:
            logging.error(f"Failed to parse HTML for {url}: {e}")
            return

        for link in soup.find_all('a', href=True):
            href = Utils.sanitize_url(link['href'], url)
            if Utils.is_same_domain(href, self.domain) and href not in self.visited:
                next_depth = depth + 1
                if next_depth <= self.config.MAX_DEPTH:
                    self.to_visit.append((href, next_depth))
                else:
                    logging.debug(f"Skipped {href} (Depth {next_depth} exceeds MAX_DEPTH {self.config.MAX_DEPTH})")

        all_params = {}
        for form in soup.find_all('form'):
            action = form.get('action')
            method = form.get('method', 'get')
            if action:
                form_url = Utils.sanitize_url(action, url)
                form_params = Utils.extract_form_params(form)
                all_params.update(form_params)
                try:
                    form_results = await self.tester.test_form(form_url, method, form_params, form)
                    self.results.extend(form_results)
                except Exception as e:
                    logging.error(f"Error testing form at {form_url}: {e}")

        query_params = Utils.extract_query_params(url)
        for param in query_params:
            all_params[param] = query_params[param][0]
        if query_params:
            try:
                query_results = await self.tester.test_query_params(url, query_params)
                self.results.extend(query_results)
            except Exception as e:
                logging.error(f"Error testing query params at {url}: {e}")

        path_params = Utils.extract_path_params(url)
        all_params.update(path_params)
        if path_params:
            try:
                path_results = await self.tester.test_path_params(url, path_params)
                self.results.extend(path_results)
            except Exception as e:
                logging.error(f"Error testing path params at {url}: {e}")

        js_params = Utils.extract_js_params(html)
        for param in js_params:
            all_params[param] = ""
        if js_params:
            try:
                js_results = await self.tester.test_js_params(url, js_params)
                self.results.extend(js_results)
            except Exception as e:
                logging.error(f"Error testing JS params at {url}: {e}")

        if all_params:
            logging.info(f"Parameters found at {url}: {list(all_params.keys())}")

        header_issues = self.tester.detector.analyze_headers(headers)
        for issue in header_issues:
            self.results.append({
                'type': 'Header Issue',
                'url': url,
                'method': 'N/A',
                'parameter': None,
                'payload': issue
            })

        js_issues = self.tester.detector.basic_js_analysis(html)
        for issue in js_issues:
            self.results.append({
                'type': 'JavaScript Issue',
                'url': url,
                'method': 'N/A',
                'parameter': None,
                'payload': issue
            })

# Authenticator sınıfı: Kimlik doğrulama işlemlerini gerçekleştirir
class Authenticator:
    # __init__: Kimlik doğrulama için gerekli bilgileri alır
    def __init__(self, session: aiohttp.ClientSession, auth_url: str, auth_data: Dict[str, str]):
        self.session = session
        self.auth_url = auth_url
        self.auth_data = auth_data

    # login: Kimlik doğrulama URL'sine POST isteği gönderir
    async def login(self):
        try:
            async with self.session.post(self.auth_url, data=self.auth_data) as response:
                if response.status == 200:
                    logging.info("Login successful")
                else:
                    logging.warning(f"Login failed with status {response.status}")
        except aiohttp.ClientError as e:
            logging.error(f"Login failed: {e}")

# Reporter sınıfı: Tarama sonuçlarını HTML raporu olarak kaydeder
class Reporter:
    # __init__: Rapor şablonunu ve çıktı dosyasını ayarlar
    def __init__(self, template_file: str, output_file: str):
        self.template_file = template_file
        self.output_file = output_file
        self.env = None
        self.template = None
        if os.path.isfile(template_file):
            self.env = Environment(loader=FileSystemLoader(os.path.dirname(template_file)))
            self.template = self.env.get_template(os.path.basename(template_file))
        else:
            logging.warning(f"Template file {template_file} not found. Using default template.")
            self.template = Template(DEFAULT_TEMPLATE)

    # generate_report: Tarama sonuçlarını HTML dosyasına dönüştürür
    def generate_report(self, results: List[Dict]):
        try:
            html_content = self.template.render(results=results, date=time.strftime("%Y-%m-%d %H:%M:%S"))
            with open(self.output_file, 'w') as f:
                f.write(html_content)
            logging.info(f"Report generated: {self.output_file}")
        except Exception as e:
            logging.error(f"Failed to generate report: {e}")

# main fonksiyonu: Programın ana giriş noktası
async def main():
    # Komut satırı argümanlarını tanımlıyoruz
    parser = argparse.ArgumentParser(description="Advanced Security Scanning Tool")
    parser.add_argument("url", help="Starting URL to scan")
    parser.add_argument("--depth", type=int, default=5, help="Maximum crawl depth")
    parser.add_argument("--xss-payloads", type=str, help="File containing custom XSS payloads")
    parser.add_argument("--sql-payloads", type=str, help="File containing custom SQL payloads")
    parser.add_argument("--output", type=str, default="scan_results.json", help="Output file for results")
    parser.add_argument("--proxy", type=str, help="Proxy URL (e.g., http://localhost:8080)")
    parser.add_argument("--auth-url", type=str, help="Authentication URL for login")
    parser.add_argument("--auth-data", type=str, help="Authentication data in JSON format")
    parser.add_argument("--report-template", type=str, default="report_template.html", help="HTML template for report")
    parser.add_argument("--report-output", type=str, default="scan_report.html", help="Output file for HTML report")
    args = parser.parse_args()

    # Loglama ayarlarını yapılandırıyoruz (dosyaya ve konsola renkli çıktı)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("security_scan.log"),
            ColoredStreamHandler()
        ]
    )

    # Yapılandırma nesnesini oluşturuyoruz
    config = Config()
    config.MAX_DEPTH = args.depth
    if args.xss_payloads:
        try:
            with open(args.xss_payloads, 'r') as f:
                config.PAYLOADS_XSS = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logging.warning(f"XSS payload file {args.xss_payloads} not found. Using defaults.")
    if args.sql_payloads:
        try:
            with open(args.sql_payloads, 'r') as f:
                config.PAYLOADS_SQL = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logging.warning(f"SQL payload file {args.sql_payloads} not found. Using defaults.")

    if args.proxy:
        config.PROXY = args.proxy
    if args.auth_url and args.auth_data:
        try:
            config.AUTH_URL = args.auth_url
            config.AUTH_DATA = json.loads(args.auth_data)
        except json.JSONDecodeError as e:
            logging.error(f"Invalid auth data: {e}")
            return

    # HTTP oturumu oluşturuyoruz
    connector = aiohttp.TCPConnector(limit=config.MAX_CONCURRENT)
    session_args = {'headers': {"User-Agent": config.USER_AGENT}, 'connector': connector}
    if config.PROXY:
        session_args['proxy'] = config.PROXY

    async with aiohttp.ClientSession(**session_args) as session:
        if config.AUTH_URL and config.AUTH_DATA:
            authenticator = Authenticator(session, config.AUTH_URL, config.AUTH_DATA)
            await authenticator.login()

        # Tarayıcıyı başlatıp tarama işlemini gerçekleştiriyoruz
        crawler = Crawler(args.url, config, session)
        results = await crawler.crawl()

        # Sonuçları JSON dosyasına kaydediyoruz
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            logging.info(f"Results saved to {args.output}")
        except IOError as e:
            logging.error(f"Failed to save results: {e}")

        # Konsolda tablo formatında sonuçları gösteriyoruz
        if results:
            table_data = [
                [r['type'], r['url'], r['method'], r['parameter'] or 'N/A', r['payload']]
                for r in results
            ]
            headers = ["Type", "URL", "Method", "Parameter", "Payload"]
            print(Fore.CYAN + "\n=== Vulnerability Report ===")
            print(Fore.CYAN + tabulate(table_data, headers=headers, tablefmt="grid"))
        else:
            print(Fore.GREEN + "\nNo vulnerabilities found.")

        # HTML raporu oluşturuyoruz
        try:
            reporter = Reporter(args.report_template, args.report_output)
            reporter.generate_report(results)
        except Exception as e:
            logging.error(f"Unexpected error during report generation: {e}")

# Programın giriş noktası
if __name__ == "__main__":
    asyncio.run(main())
