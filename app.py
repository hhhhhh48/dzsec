from flask import Flask, render_template, request
import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

# ============ التوصيات المفصلة ============
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

    except Exception as e:
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

    # بناء قائمة التوصيات المفصلة
    recommendations = []
    for key in missing_headers:
        if key in RECOMMENDATIONS:
            recommendations.append(RECOMMENDATIONS[key])

    # ترتيب حسب الخطورة
    severity_order = {'حرجة': 0, 'عالية': 1, 'متوسطة': 2, 'منخفضة': 3}
    recommendations.sort(key=lambda x: severity_order.get(x['severity'], 4))

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
