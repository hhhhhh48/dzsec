from flask import Flask, render_template, request
import requests
import ssl
import socket
import re
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

RECOMMENDATIONS = {
    'HSTS': {
        'title': 'Strict-Transport-Security (HSTS)',
        'issue': 'الموقع لا يجبر المتصفح على استخدام HTTPS دائماً، مما يجعله عرضة لهجمات SSL Stripping.',
        'fix': "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        'severity': 'عالية'
    },
    'CSP': {
        'title': 'Content-Security-Policy (CSP)',
        'issue': 'بدون CSP، الموقع عرضة لهجمات XSS (حقن أكواد JavaScript ضارة).',
        'fix': "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        'severity': 'حرجة'
    },
    'X-Frame-Options': {
        'title': 'X-Frame-Options',
        'issue': 'الموقع يمكن تضمينه داخل iframe، مما يجعله عرضة لهجمات Clickjacking.',
        'fix': "X-Frame-Options: DENY",
        'severity': 'متوسطة'
    },
    'X-Content-Type-Options': {
        'title': 'X-Content-Type-Options',
        'issue': 'المتصفح قد يحاول تخمين نوع الملفات، مما يسمح بهجمات MIME Sniffing.',
        'fix': "X-Content-Type-Options: nosniff",
        'severity': 'متوسطة'
    },
    'Referrer-Policy': {
        'title': 'Referrer-Policy',
        'issue': 'معلومات حساسة قد تُسرّب عبر Referrer Header عند الانتقال لمواقع أخرى.',
        'fix': "Referrer-Policy: strict-origin-when-cross-origin",
        'severity': 'منخفضة'
    },
    'Permissions-Policy': {
        'title': 'Permissions-Policy',
        'issue': 'الكاميرا والمايك والموقع الجغرافي غير مقيّدة، مما قد يُستغل.',
        'fix': "Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()",
        'severity': 'متوسطة'
    },
    'COOP': {
        'title': 'Cross-Origin-Opener-Policy (COOP)',
        'issue': 'النطاق ليس معزولاً عن النوافذ الأخرى، مما يسمح بهجمات XS-Leaks.',
        'fix': "Cross-Origin-Opener-Policy: same-origin",
        'severity': 'متوسطة'
    },
    'CORP': {
        'title': 'Cross-Origin-Resource-Policy (CORP)',
        'issue': 'الموارد غير محمية من الاستخدام من قبل مواقع أخرى.',
        'fix': "Cross-Origin-Resource-Policy: same-origin",
        'severity': 'متوسطة'
    }
}

HEADER_NAMES = {
    'Strict-Transport-Security': 'HSTS',
    'Content-Security-Policy': 'CSP',
    'X-Frame-Options': 'X-Frame-Options',
    'X-Content-Type-Options': 'X-Content-Type-Options',
    'Referrer-Policy': 'Referrer-Policy',
    'Permissions-Policy': 'Permissions-Policy',
    'Cross-Origin-Opener-Policy': 'COOP',
    'Cross-Origin-Resource-Policy': 'CORP',
}


def check_wordpress_and_files(url, hostname):
    """فحص WordPress والملفات الحساسة"""
    findings = {
        'is_wordpress': False,
        'wp_version': None,
        'sensitive_files': [],
        'xmlrpc_enabled': False,
        'risk_count': 0,
    }

    headers = {'User-Agent': 'Mozilla/5.0 (compatible; DZSec-Scanner)'}

    try:
        response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
        content = response.text.lower()

        wp_signals = ['wp-content', 'wp-includes', 'wp-json', '/wordpress']
        if any(signal in content for signal in wp_signals):
            findings['is_wordpress'] = True

        match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', response.text)
        if match:
            findings['wp_version'] = match.group(1)
    except:
        pass

    sensitive_paths = [
        ('/wp-config.php.bak', 'نسخة احتياطية من إعدادات WordPress'),
        ('/wp-config.php~', 'نسخة احتياطية من إعدادات WordPress'),
        ('/wp-config.php.old', 'نسخة قديمة من إعدادات WordPress'),
        ('/.env', 'ملف البيئة (يحتوي كلمات مرور)'),
        ('/.env.backup', 'نسخة احتياطية من ملف البيئة'),
        ('/backup.zip', 'نسخة احتياطية كاملة'),
        ('/backup.sql', 'نسخة احتياطية من قاعدة البيانات'),
        ('/database.sql', 'نسخة من قاعدة البيانات'),
        ('/.git/config', 'ملف إعدادات Git'),
        ('/phpinfo.php', 'ملف معلومات PHP'),
    ]

    for path, description in sensitive_paths:
        try:
            check_url = url.rstrip('/') + path
            r = requests.get(check_url, timeout=5, headers=headers, allow_redirects=False)

            if r.status_code == 200 and len(r.content) > 0:
                findings['sensitive_files'].append({
                    'path': path,
                    'description': description,
                    'status': 'exposed',
                })
                findings['risk_count'] += 1
            elif r.status_code == 403:
                findings['sensitive_files'].append({
                    'path': path,
                    'description': description,
                    'status': 'protected',
                })
        except:
            pass

    if findings['is_wordpress']:
        try:
            xmlrpc_url = url.rstrip('/') + '/xmlrpc.php'
            r = requests.get(xmlrpc_url, timeout=5, headers=headers)
            if r.status_code == 200:
                findings['xmlrpc_enabled'] = True
                findings['risk_count'] += 1
        except:
            pass

    return findings


def check_site(url):
    if not url.startswith('http'):
        url = 'https://' + url
    parsed = urlparse(url)
    hostname = parsed.hostname

    score = 0
    max_score = 150
    https_ok = False
    ssl_ok = False
    ssl_days = 0
    headers_found = {}
    missing_headers = []
    details = {}
    final_url = url

    try:
        response = requests.get(url, timeout=15, allow_redirects=True)
        headers = response.headers
        final_url = response.url

        if response.url.startswith("https://"):
            https_ok = True
            score += 20

        if https_ok:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=8) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        ssl_days = (expire_date - datetime.now()).days
                        if ssl_days > 0:
                            ssl_ok = True
            except:
                pass

        weights = {
            'Strict-Transport-Security': 30,
            'Content-Security-Policy': 30,
            'X-Frame-Options': 15,
            'X-Content-Type-Options': 10,
            'Referrer-Policy': 10,
            'Permissions-Policy': 10,
            'Cross-Origin-Opener-Policy': 10,
            'Cross-Origin-Resource-Policy': 10,
        }

        for header, points in weights.items():
            key = HEADER_NAMES[header]
            if header in headers:
                headers_found[key] = headers[header]
                score += points
                details[key] = True
            else:
                details[key] = False
                missing_headers.append(key)

    except Exception:
        return None

    percentage = (score / max_score) * 100

    if percentage >= 95:
        grade, grade_text = "A+", "ممتاز"
    elif percentage >= 85:
        grade, grade_text = "A", "ممتاز"
    elif percentage >= 75:
        grade, grade_text = "B", "جيد"
    elif percentage >= 65:
        grade, grade_text = "C", "مقبول"
    elif percentage >= 50:
        grade, grade_text = "D", "ضعيف"
    else:
        grade, grade_text = "F", "خطر"

    recommendations = []
    for key in missing_headers:
        if key in RECOMMENDATIONS:
            recommendations.append(RECOMMENDATIONS[key])

    severity_order = {'حرجة': 0, 'عالية': 1, 'متوسطة': 2, 'منخفضة': 3}
    recommendations.sort(key=lambda x: severity_order.get(x['severity'], 4))

    # فحص WordPress والملفات الحساسة
    wp_findings = check_wordpress_and_files(url, hostname)

    return {
        'url': hostname,
        'final_url': final_url,
        'score': score,
        'max_score': max_score,
        'percentage': round(percentage, 1),
        'grade': grade,
        'grade_text': grade_text,
        'https': https_ok,
        'ssl': ssl_ok,
        'ssl_days': ssl_days,
        'headers_found': headers_found,
        'details': details,
        'recommendations': recommendations,
        'missing_count': len(missing_headers),
        'wordpress': wp_findings,
        'date': datetime.now().strftime('%Y-%m-%d %H:%M')
    }


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()
    if not url:
        return render_template('index.html', error="الرجاء إدخال رابط الموقع")
    result = check_site(url)
    if not result:
        return render_template('index.html', error="فشل الاتصال بالموقع. تأكد من الرابط.")
    return render_template('result.html', r=result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
