import re
import socket
import ssl
import hashlib
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
import requests

# Common suspicious top-level domains frequently abused in phishing
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz',
    '.work', '.click', '.loan', '.fit', '.date', '.racing', '.surf',
    '.cam', '.country', '.stream', '.gdn', '.mom', '.win'
}

# High-risk keywords often used in scam/phishing domains and URLs
HIGH_RISK_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'account', 'banking',
    'security', 'secure', 'wallet', 'update', 'confirm', 'credential',
    'password', 'billing', 'support', 'appleid', 'paypal', 'netflix',
    'chase', 'wellsfargo', 'irs', 'suspension', 'recover'
]

# Known URL shortener services that hide actual destinations
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy'
}

# Known test threat hashes (for demonstration: EICAR test string, known demo samples)
KNOWN_THREAT_HASHES = {
    # EICAR Standard Antivirus Test File
    '44d88612fea8a8f36de82e1278abb02f': 'EICAR Standard Antivirus Test String (MD5)',
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f': 'EICAR Standard Antivirus Test String (SHA256)',
    # Educational test ransomware sample signatures
    'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa': 'WannaCry Ransomware Indicator Test Sample (SHA256)',
    '84c82835a5d21bbcf75a61706d8ab549': 'WannaCry Dropper Test Hash (MD5)',
    '512301c535c88255c9a252fdf70b7a03': 'Mirai Botnet Binary Test Hash (MD5)',
    '7b4a242c7f46327b8782a17056cd619f': 'Emotet Trojan Test Sample (MD5)'
}

# High-risk executable/script extensions
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.ps1',
    '.msi', '.hta', '.jar', '.com', '.pif', '.reg', '.iso', '.dll'
}

# Ransomware indicators
RANSOMWARE_EXTENSIONS = {
    '.locked', '.crypto', '.crypt', '.locky', '.cerber', '.wannacry'
}


def clean_domain(target):
    """Extract domain or IP from an input string or URL."""
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        # Prepend scheme for urlparse if missing
        parsed = urlparse('https://' + target)
    else:
        parsed = urlparse(target)
    
    netloc = parsed.netloc.split(':')[0]
    return netloc.strip().lower()


def check_ip_nature(host):
    """
    Check if a host is an IP address using python's ipaddress library.
    Returns (is_ip, ip_type_str, is_dangerous_flag)
    """
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_private:
            return True, 'Private IP (Local Network)', True
        elif ip_obj.is_loopback:
            return True, 'Loopback / Localhost', True
        elif ip_obj.is_reserved:
            return True, 'Reserved IP Address', True
        else:
            return True, 'Public Raw IP Address', True
    except ValueError:
        return False, 'Domain Name (FQDN)', False


def inspect_ssl_certificate(domain, port=443, timeout=4):
    """
    Inspect SSL/TLS certificate using python's ssl and socket libraries.
    """
    result = {
        'has_ssl': False,
        'valid': False,
        'issuer': 'Unknown',
        'subject': 'Unknown',
        'valid_from': None,
        'valid_to': None,
        'days_remaining': 0,
        'protocol': None,
        'cipher': None,
        'error': None
    }
    
    try:
        context = ssl.create_default_context()
        context.timeout = timeout
        
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
                
                result['has_ssl'] = True
                result['protocol'] = protocol
                result['cipher'] = cipher[0] if cipher else 'Unknown'
                
                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                result['issuer'] = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'Trusted CA'
                
                # Extract Subject
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                result['subject'] = subject_dict.get('commonName') or domain
                
                # Dates
                not_after_str = cert.get('notAfter')
                not_before_str = cert.get('notBefore')
                
                if not_after_str:
                    # Format: 'May 15 12:00:00 2026 GMT'
                    expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    result['valid_to'] = expiry_date.strftime('%Y-%m-%d')
                    
                    now = datetime.utcnow()
                    days_left = (expiry_date - now).days
                    result['days_remaining'] = days_left
                    result['valid'] = (days_left > 0)
                
                if not_before_str:
                    start_date = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                    result['valid_from'] = start_date.strftime('%Y-%m-%d')

    except ssl.SSLCertVerificationError as e:
        result['has_ssl'] = True
        result['valid'] = False
        result['error'] = f'SSL Certificate Invalid or Untrusted ({str(e.verify_message)})'
    except socket.timeout:
        result['error'] = 'Connection timed out while checking SSL.'
    except socket.gaierror:
        result['error'] = 'Domain could not be resolved in DNS.'
    except Exception as e:
        result['error'] = f'SSL Handshake Failed: {str(e)}'
        
    return result


def analyze_url(url_input):
    """
    Comprehensive URL threat analysis using socket, ssl, requests, and ipaddress.
    """
    raw_input = url_input.strip()
    if not raw_input.startswith(('http://', 'https://')):
        # Default to checking https:// if protocol omitted
        check_url = 'https://' + raw_input
        had_protocol = False
    else:
        check_url = raw_input
        had_protocol = True
        
    parsed = urlparse(check_url)
    domain = parsed.netloc.split(':')[0].strip().lower()
    path = parsed.path.lower()
    full_url = parsed.geturl()
    scheme = parsed.scheme.lower()
    
    score = 100
    threat_flags = []
    positive_flags = []
    details = {}
    
    # 1. IP Address Check using `ipaddress` library
    is_ip, ip_type, is_ip_risk = check_ip_nature(domain)
    details['is_ip_address'] = is_ip
    details['ip_type'] = ip_type
    
    if is_ip:
        score -= 30
        threat_flags.append({
            'title': 'Raw IP Address in URL',
            'severity': 'high',
            'desc': f'Uses direct IP address ({domain} - {ip_type}) instead of a verified domain name. Legitimate websites almost always use registered domain names.'
        })
    else:
        positive_flags.append('Uses a registered domain name (not a suspicious bare IP).')

    # 2. Protocol Check (HTTPS vs HTTP)
    details['protocol'] = scheme.upper()
    if scheme == 'http':
        score -= 20
        threat_flags.append({
            'title': 'Unencrypted Connection (HTTP)',
            'severity': 'medium',
            'desc': 'Website uses unencrypted HTTP. Any data, passwords, or personal info you send can be intercepted.'
        })
    elif scheme == 'https':
        positive_flags.append('Uses HTTPS protocol for encrypted communication.')

    # 3. DNS Host Resolution using `socket` library
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(domain)
        details['resolved_ip'] = resolved_ip
        positive_flags.append(f'Domain successfully resolved to IP: {resolved_ip}')
    except socket.gaierror:
        score -= 35
        threat_flags.append({
            'title': 'Unresolved Domain (DNS Failure)',
            'severity': 'high',
            'desc': f'The domain "{domain}" does not exist or has no active DNS records. Often indicates a fake or abandoned link.'
        })

    # 4. URL Length & Structure Checks
    if len(full_url) > 75:
        score -= 10
        threat_flags.append({
            'title': 'Excessively Long URL',
            'severity': 'low',
            'desc': f'URL is {len(full_url)} characters long. Attackers often use long URLs to hide deceptive subdomains on mobile viewports.'
        })
        
    if '@' in check_url:
        score -= 35
        threat_flags.append({
            'title': 'Contains "@" Character',
            'severity': 'high',
            'desc': 'The "@" character in URLs can be used to trick browsers into ignoring everything preceding it and loading a malicious server.'
        })

    # 5. Suspicious TLD Check
    domain_tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    if domain_tld in SUSPICIOUS_TLDS:
        score -= 20
        threat_flags.append({
            'title': f'High-Risk Domain Extension ({domain_tld})',
            'severity': 'medium',
            'desc': f'The extension "{domain_tld}" is frequently used by scammers due to cheap registration and lack of verification.'
        })

    # 6. Hyphen & Subdomain Stuffing
    hyphen_count = domain.count('-')
    if hyphen_count >= 3:
        score -= 15
        threat_flags.append({
            'title': 'Multiple Hyphens in Domain',
            'severity': 'medium',
            'desc': f'Domain contains {hyphen_count} hyphens (e.g., trying to mimic official brand names like paypal-account-verify).'
        })
        
    subdomains = domain.split('.')
    if len(subdomains) >= 4 and not is_ip:
        score -= 15
        threat_flags.append({
            'title': 'Excessive Subdomains',
            'severity': 'medium',
            'desc': f'Domain contains {len(subdomains)} segments. Attackers create subdomains like "paypal.com.user-verify.com" to mislead users.'
        })

    # 7. Keyword Fishing
    found_keywords = [kw for kw in HIGH_RISK_KEYWORDS if kw in full_url.lower()]
    if found_keywords and (len(subdomains) >= 3 or hyphen_count >= 2 or is_ip):
        score -= 20
        threat_flags.append({
            'title': 'Sensitive Security Keywords in Suspicious URL',
            'severity': 'medium',
            'desc': f'URL contains high-risk authentication keywords: {", ".join(found_keywords[:3])}.'
        })
    details['detected_keywords'] = found_keywords

    # 8. SSL / TLS Certificate Inspection (using `ssl` and `socket`)
    ssl_info = inspect_ssl_certificate(domain)
    details['ssl_info'] = ssl_info
    
    if ssl_info['has_ssl']:
        if ssl_info['valid']:
            positive_flags.append(f'Valid SSL Certificate issued by {ssl_info["issuer"]} ({ssl_info["days_remaining"]} days remaining).')
            if ssl_info['days_remaining'] < 10:
                score -= 10
                threat_flags.append({
                    'title': 'SSL Certificate Expiring Soon',
                    'severity': 'low',
                    'desc': f'Certificate expires in only {ssl_info["days_remaining"]} days.'
                })
        else:
            score -= 35
            threat_flags.append({
                'title': 'Invalid or Untrusted SSL Certificate',
                'severity': 'high',
                'desc': ssl_info['error'] or 'The SSL certificate is invalid, expired, or self-signed.'
            })
    else:
        if scheme == 'https':
            score -= 30
            threat_flags.append({
                'title': 'SSL Connection Failed',
                'severity': 'high',
                'desc': ssl_info['error'] or 'Could not establish secure TLS connection to the server.'
            })

    # 9. HTTP Response & Security Headers Check (using `requests` with safety timeout)
    try:
        resp = requests.head(check_url, timeout=3, allow_redirects=True, headers={'User-Agent': 'TrustGuard-Security-Scanner/1.0'})
        details['http_status'] = resp.status_code
        
        # Check security headers
        sec_headers = {
            'Strict-Transport-Security': resp.headers.get('Strict-Transport-Security') is not None,
            'X-Content-Type-Options': resp.headers.get('X-Content-Type-Options') is not None,
            'X-Frame-Options': resp.headers.get('X-Frame-Options') is not None,
            'Content-Security-Policy': resp.headers.get('Content-Security-Policy') is not None
        }
        details['security_headers'] = sec_headers
        
        if sec_headers['Strict-Transport-Security']:
            positive_flags.append('HSTS (Strict-Transport-Security) is enabled to enforce encrypted connections.')
        if sec_headers['X-Frame-Options']:
            positive_flags.append('Anti-Clickjacking protection (X-Frame-Options) detected.')
            
    except requests.exceptions.RequestException:
        details['http_status'] = 'Unreachable / Blocked'
        # Do not excessively penalize if unreachable since local test domains may not respond

    # Normalize final score between 0 and 100
    final_score = max(5, min(100, score))
    
    # Determine final trust status
    if final_score >= 80:
        status = 'safe'
        status_label = 'SAFE'
        color = '#0F9D58'
        summary = 'Website appears legitimate with active encryption and standard domain safety indicators.'
        recommendation = 'Safe to browse. Continue exercising standard online privacy precautions.'
    elif final_score >= 50:
        status = 'suspicious'
        status_label = 'SUSPICIOUS'
        color = '#DD6B20'
        summary = 'Caution advised. Website has suspicious indicators, weak security configuration, or unusual URL structure.'
        recommendation = 'Proceed with caution. Do NOT enter sensitive passwords, financial information, or credit card details.'
    else:
        status = 'dangerous'
        status_label = 'DANGEROUS'
        color = '#DC3545'
        summary = 'High threat level. Strong likelihood of phishing, fraud, fake domain imitation, or severe security flaw.'
        recommendation = 'Do NOT visit this link or interact with the page. Close your browser tab immediately.'

    return {
        'target': url_input,
        'domain': domain,
        'status': status,
        'status_label': status_label,
        'status_color': color,
        'trust_score': final_score,
        'summary': summary,
        'recommendation': recommendation,
        'threat_flags': threat_flags,
        'positive_flags': positive_flags,
        'details': details
    }


def analyze_message(text):
    """
    Rule-based Phishing and Scam Message Detection.
    Evaluates urgency triggers, financial baits, credential harvesting phrases,
    impersonation keywords, and embedded link risks.
    """
    clean_text = text.strip()
    if not clean_text:
        return {
            'status': 'safe',
            'trust_score': 100,
            'summary': 'Empty message provided.',
            'threat_flags': [],
            'recommendation': 'No text to analyze.'
        }

    lower_text = clean_text.lower()
    threat_points = 0
    flags = []

    # Category 1: Extreme Urgency & Threat Triggers
    urgency_patterns = [
        (r'\b(urgent|immediately|act now|hurry|final notice|immediate action)\b', 'Artificial urgency created to induce panic'),
        (r'\b(24 hours|within 24 hours|12 hours|48 hours|today only|expires today)\b', 'Short countdown timer / artificial deadline'),
        (r'\b(suspended|frozen|terminated|locked|disabled|blocked|restricted)\b', 'Account suspension or block threat'),
        (r'\b(arrest|police|legal action|law enforcement|court|fbi|customs|fine|warrant)\b', 'Law enforcement or legal intimidation tactic')
    ]
    for pattern, desc in urgency_patterns:
        match = re.search(pattern, lower_text)
        if match:
            threat_points += 20
            flags.append({
                'title': 'High Urgency / Coercion',
                'matched': match.group(0),
                'desc': desc
            })
            break

    # Category 2: Financial Baits & Lottery Scams
    financial_patterns = [
        (r'\b(lottery|won|winner|jackpot|cash prize|million dollars|inheritance|beneficiary)\b', 'Unsolicited prize or lottery claim'),
        (r'\b(crypto|bitcoin|eth|airdrop|double your money|guaranteed return|investment profit)\b', 'Cryptocurrency or high-yield investment scam lure'),
        (r'\b(tax refund|irs refund|unclaimed funds|stimulus|payout)\b', 'Fake government or tax refund bait')
    ]
    for pattern, desc in financial_patterns:
        match = re.search(pattern, lower_text)
        if match:
            threat_points += 25
            flags.append({
                'title': 'Financial / Reward Bait',
                'matched': match.group(0),
                'desc': desc
            })
            break

    # Category 3: Credential Harvesting & Sensitive Info Requests
    credential_patterns = [
        (r'\b(verify your (account|password|pin|identity|details)|confirm your password|enter your otp|send your otp)\b', 'Direct solicitation of credentials or OTP'),
        (r'\b(credit card|cvv|expiry date|social security|ssn|bank details|account number)\b', 'Request for sensitive financial or identification data'),
        (r'\b(login to verify|click here to verify|reset your password now)\b', 'Call-to-action redirecting to credential entry')
    ]
    for pattern, desc in credential_patterns:
        match = re.search(pattern, lower_text)
        if match:
            threat_points += 30
            flags.append({
                'title': 'Credential Harvesting Attempt',
                'matched': match.group(0),
                'desc': desc
            })
            break

    # Category 4: Impersonation / Spoofed Brands
    brands = ['paypal', 'netflix', 'amazon', 'apple', 'microsoft', 'google', 'chase', 'wells fargo', 'fedex', 'ups', 'dhl', 'usps']
    detected_brands = [b for b in brands if b in lower_text]
    if detected_brands and (threat_points > 0):
        threat_points += 15
        flags.append({
            'title': 'Brand Impersonation',
            'matched': ', '.join(detected_brands),
            'desc': f'Message mimics well-known brand(s): {", ".join(detected_brands).title()}. Scammers often pose as trusted companies.'
        })

    # Category 5: Embedded Links & Shorteners
    # Extract URLs from message
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    if urls:
        for u in urls:
            u_domain = clean_domain(u)
            if any(shortener in u_domain for shortener in URL_SHORTENERS):
                threat_points += 20
                flags.append({
                    'title': 'Hidden / Shortened Link',
                    'matched': u,
                    'desc': 'Message uses a URL shortener to disguise the actual destination website.'
                })
                break
            elif any(u_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                threat_points += 25
                flags.append({
                    'title': 'Suspicious Link Extension',
                    'matched': u,
                    'desc': f'Link points to a suspicious top-level domain.'
                })
                break
            else:
                threat_points += 10
                flags.append({
                    'title': 'Contains External Link',
                    'matched': u,
                    'desc': 'Unsolicited links in messages should be verified before clicking.'
                })
                break

    # Calculate Trust Score (starts at 100, drops with threat points)
    trust_score = max(10, 100 - threat_points)
    
    if trust_score >= 80:
        status = 'safe'
        status_label = 'SAFE'
        color = '#0F9D58'
        summary = 'No prominent phishing or social engineering patterns detected.'
        recommendation = 'Message appears low-risk. Always remain cautious with unsolicited communications.'
    elif trust_score >= 50:
        status = 'suspicious'
        status_label = 'SUSPICIOUS'
        color = '#DD6B20'
        summary = 'Contains suspicious phrasing, urgency, or links typical of unsolicited outreach or spam.'
        recommendation = 'Exercise caution. Do not click links or send information until independently verified.'
    else:
        status = 'dangerous'
        status_label = 'DANGEROUS'
        color = '#DC3545'
        summary = 'High probability of phishing or scam. Multiple social engineering indicators triggered.'
        recommendation = 'DO NOT reply, click links, or share any OTP or personal information. Delete and report this message.'

    return {
        'target': (clean_text[:60] + '...') if len(clean_text) > 60 else clean_text,
        'full_text': clean_text,
        'status': status,
        'status_label': status_label,
        'status_color': color,
        'trust_score': trust_score,
        'summary': summary,
        'recommendation': recommendation,
        'threat_flags': flags,
        'extracted_urls': urls
    }


def analyze_file_data(file_bytes, filename='unknown_file'):
    """
    Compute cryptographic hashes (MD5, SHA-1, SHA-256) using hashlib and check integrity.
    """
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha1_hash = hashlib.sha1(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    score = 100
    threat_flags = []
    positive_flags = []
    
    file_size_kb = round(len(file_bytes) / 1024, 2)
    ext = ('.' + filename.split('.')[-1].lower()) if '.' in filename else ''
    
    # Check against known malicious signatures
    matched_threat = None
    if md5_hash in KNOWN_THREAT_HASHES:
        matched_threat = KNOWN_THREAT_HASHES[md5_hash]
    elif sha256_hash in KNOWN_THREAT_HASHES:
        matched_threat = KNOWN_THREAT_HASHES[sha256_hash]

    # Also check for EICAR signature bytes in content
    if b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' in file_bytes:
        matched_threat = 'EICAR Standard Antivirus Test Signature detected in file contents'

    if matched_threat:
        score = 0
        threat_flags.append({
            'title': 'Known Malicious Signature Detected',
            'severity': 'high',
            'desc': f'Threat indicator identified: {matched_threat}.'
        })
    else:
        positive_flags.append('No match found in known threat signature index.')

    # Check for ransomware extensions
    if ext in RANSOMWARE_EXTENSIONS:
        score -= 50
        threat_flags.append({
            'title': 'Ransomware Encrypted File Extension',
            'severity': 'high',
            'desc': f'File extension ({ext}) is associated with known ransomware encryption.'
        })

    # Check for dangerous extension
    if ext in DANGEROUS_EXTENSIONS:
        score -= 25
        threat_flags.append({
            'title': f'Executable / Script File Extension ({ext})',
            'severity': 'medium',
            'desc': f'Files with {ext} extension can execute code directly on your operating system.'
        })

    # Check for double extensions (e.g. invoice.pdf.exe)
    parts = filename.lower().split('.')
    if len(parts) >= 3 and ('.' + parts[-1]) in DANGEROUS_EXTENSIONS:
        score -= 35
        threat_flags.append({
            'title': 'Deceptive Double File Extension',
            'severity': 'high',
            'desc': f'File uses a disguised extension pattern ({parts[-2]}.{parts[-1]}) commonly used to trick users into running executables.'
        })

    # Check for embedded malicious commands in text/script files
    try:
        sample_text = file_bytes[:4096].decode('utf-8', errors='ignore').lower()
        if any(term in sample_text for term in ['powershell -enc', 'invoke-expression', 'wscript.shell', 'mimikatz', 'cmd.exe /c powershell']):
            score -= 30
            threat_flags.append({
                'title': 'Suspicious Script Commands Detected',
                'severity': 'high',
                'desc': 'Contains obfuscated PowerShell or shell command invocation patterns.'
            })
    except Exception:
        pass

    final_score = max(0, min(100, score))
    
    if final_score >= 80:
        status = 'safe'
        status_label = 'SAFE'
        color = '#0F9D58'
        summary = 'File hash computed cleanly with no known malicious signature or extension anomalies.'
        recommendation = 'File appears clean based on cryptographic hash fingerprint analysis.'
    elif final_score >= 50:
        status = 'suspicious'
        status_label = 'SUSPICIOUS'
        color = '#DD6B20'
        summary = 'Potentially dangerous file type, executable script, or unverified binary detected.'
        recommendation = 'Verify the source of this file before executing or opening it.'
    else:
        status = 'dangerous'
        status_label = 'DANGEROUS'
        color = '#DC3545'
        summary = 'Known threat signature or disguised malicious payload detected.'
        recommendation = 'Do NOT run or open this file. Quarantine or delete it immediately.'

    return {
        'filename': filename,
        'file_size_kb': file_size_kb,
        'md5': md5_hash,
        'sha1': sha1_hash,
        'sha256': sha256_hash,
        'status': status,
        'status_label': status_label,
        'status_color': color,
        'trust_score': final_score,
        'summary': summary,
        'recommendation': recommendation,
        'threat_flags': threat_flags,
        'positive_flags': positive_flags
    }


def inspect_ssl_domain(domain_input):
    """
    Dedicated SSL/TLS certificate inspector for domains.
    Provides detailed cryptographic analysis with plain-English explanation.
    """
    clean = clean_domain(domain_input)
    ssl_result = inspect_ssl_certificate(clean)
    
    score = 100
    threat_flags = []
    positive_flags = []
    
    if not ssl_result['has_ssl']:
        score = 0
        status = 'dangerous'
        status_label = 'DANGEROUS'
        color = '#DC3545'
        summary = f'No valid SSL/TLS certificate found for {clean}. Connection cannot be secured.'
        recommendation = 'Do not transmit sensitive passwords or credit card numbers to this site.'
        threat_flags.append({
            'title': 'No Active SSL/TLS Encryption',
            'desc': ssl_result['error'] or 'Port 443 closed or SSL handshake rejected.'
        })
    elif not ssl_result['valid']:
        score = 25
        status = 'dangerous'
        status_label = 'DANGEROUS'
        color = '#DC3545'
        summary = f'SSL certificate is invalid, expired, or self-signed ({ssl_result["error"]}).'
        recommendation = 'Your connection is not private. Attackers could intercept your traffic.'
        threat_flags.append({
            'title': 'Untrusted / Invalid Certificate',
            'desc': ssl_result['error']
        })
    else:
        positive_flags.append(f'Certificate issued by recognized authority: {ssl_result["issuer"]}')
        positive_flags.append(f'Protocol: {ssl_result["protocol"]} ({ssl_result["cipher"]})')
        
        days = ssl_result['days_remaining']
        if days < 15:
            score = 65
            status = 'suspicious'
            status_label = 'SUSPICIOUS'
            color = '#DD6B20'
            summary = f'SSL Certificate is valid but expires in {days} day(s).'
            recommendation = 'Administrator needs to renew the certificate soon.'
            threat_flags.append({
                'title': 'Certificate Near Expiration',
                'desc': f'Only {days} days until certificate expires ({ssl_result["valid_to"]}).'
            })
        else:
            status = 'safe'
            status_label = 'SAFE'
            color = '#0F9D58'
            summary = f'Strong SSL/TLS encryption active. Issued by {ssl_result["issuer"]}, valid for {days} days.'
            recommendation = 'Secure encrypted connection established. Traffic is safe from eavesdropping.'
            positive_flags.append(f'Valid until {ssl_result["valid_to"]} ({days} days remaining)')

    return {
        'domain': clean,
        'status': status,
        'status_label': status_label,
        'status_color': color,
        'trust_score': score,
        'summary': summary,
        'recommendation': recommendation,
        'details': ssl_result,
        'threat_flags': threat_flags,
        'positive_flags': positive_flags
    }


def analyze_hash_string(hash_str):
    """Analyze a pasted hash string directly."""
    clean_h = hash_str.strip().lower()
    length = len(clean_h)
    
    hash_type = 'Unknown'
    if length == 32:
        hash_type = 'MD5'
    elif length == 40:
        hash_type = 'SHA-1'
    elif length == 64:
        hash_type = 'SHA-256'
    else:
        return {
            'status': 'suspicious',
            'status_label': 'SUSPICIOUS',
            'status_color': '#DD6B20',
            'trust_score': 50,
            'summary': f'Invalid hash length ({length} characters). Standard hashes are 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters.',
            'threat_flags': [{'title': 'Invalid Format', 'desc': 'Check that you pasted a valid hexadecimal hash string.'}],
            'positive_flags': [],
            'recommendation': 'Provide a standard 32, 40, or 64 character cryptographic hash.'
        }
        
    matched = KNOWN_THREAT_HASHES.get(clean_h)
    if matched:
        return {
            'hash': clean_h,
            'hash_type': hash_type,
            'status': 'dangerous',
            'status_label': 'DANGEROUS',
            'status_color': '#DC3545',
            'trust_score': 0,
            'summary': f'Identified as a known malicious threat sample: {matched}',
            'recommendation': 'This hash is flagged in threat intelligence records. Avoid associated files.',
            'threat_flags': [{'title': 'Known Malicious Signature', 'desc': matched}],
            'positive_flags': []
        }
    else:
        return {
            'hash': clean_h,
            'hash_type': hash_type,
            'status': 'safe',
            'status_label': 'SAFE',
            'status_color': '#0F9D58',
            'trust_score': 95,
            'summary': f'Valid {hash_type} cryptographic fingerprint. No matches found in known threat blacklist.',
            'recommendation': 'Hash format is authentic and clear of known threat indicators in local database.',
            'threat_flags': [],
            'positive_flags': [f'Valid {hash_type} digest syntax', 'No match in malicious signatures database']
        }


