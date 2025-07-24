import re
import tldextract
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import whois
from datetime import datetime

def extract_url_features(url):
    """
    Extract features from URL for phishing detection
    """
    features = {}
    
    try:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_question_marks'] = url.count('?')
        features['num_equal_signs'] = url.count('=')
        features['num_at_signs'] = url.count('@')
        
        # Protocol features
        features['uses_https'] = parsed.scheme == 'https'
        features['has_port'] = parsed.port is not None
        
        # Domain features
        features['domain_length'] = len(extracted.domain) if extracted.domain else 0
        features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
        
        # Check if domain is an IP address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        features['has_ip'] = bool(re.match(ip_pattern, extracted.domain or ''))
        
        # Path features
        path = parsed.path or ''
        features['path_length'] = len(path)
        features['path_depth'] = len([p for p in path.split('/') if p])
        
        # Query parameters
        query_params = parse_qs(parsed.query)
        features['num_query_params'] = len(query_params)
        
        # Check for suspicious patterns
        features['has_suspicious_keywords'] = any(
            keyword in url.lower() for keyword in [
                'secure', 'account', 'update', 'verify', 'login', 'banking'
            ]
        )
        
        # Domain age (simplified - would need actual whois lookup)
        try:
            domain_info = whois.whois(extracted.domain + '.' + extracted.suffix)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age_days = (datetime.now() - creation_date).days
                features['domain_age_days'] = age_days
                features['is_new_domain'] = age_days < 30
            else:
                features['domain_age_days'] = -1
                features['is_new_domain'] = True
        except:
            features['domain_age_days'] = -1
            features['is_new_domain'] = True
        
    except Exception as e:
        # Set default values if extraction fails
        features.update({
            'url_length': len(url),
            'num_dots': 0,
            'num_hyphens': 0,
            'num_underscores': 0,
            'num_slashes': 0,
            'num_question_marks': 0,
            'num_equal_signs': 0,
            'num_at_signs': 0,
            'uses_https': False,
            'has_port': False,
            'domain_length': 0,
            'subdomain_count': 0,
            'has_ip': False,
            'path_length': 0,
            'path_depth': 0,
            'num_query_params': 0,
            'has_suspicious_keywords': False,
            'domain_age_days': -1,
            'is_new_domain': True
        })
    
    return features

def extract_email_features(email_content):
    """
    Extract features from email content for phishing detection
    """
    features = {}
    
    try:
        # Basic content features
        features['content_length'] = len(email_content)
        features['num_lines'] = len(email_content.split('\n'))
        features['num_words'] = len(email_content.split())
        
        # URL features
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_content)
        features['num_urls'] = len(urls)
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        features['has_url_shortener'] = any(
            shortener in email_content.lower() for shortener in shorteners
        )
        
        # Suspicious phrases
        urgent_phrases = [
            'urgent', 'immediate action', 'act now', 'expires today',
            'verify now', 'click here now', 'limited time'
        ]
        email_lower = email_content.lower()
        features['num_urgent_phrases'] = sum(
            1 for phrase in urgent_phrases if phrase in email_lower
        )
        
        # Generic greetings
        generic_greetings = ['dear customer', 'dear user', 'dear member']
        features['has_generic_greeting'] = any(
            greeting in email_lower for greeting in generic_greetings
        )
        
        # Requests for sensitive information
        sensitive_keywords = [
            'password', 'social security', 'credit card', 'bank account',
            'personal information', 'ssn', 'pin'
        ]
        features['num_sensitive_requests'] = sum(
            1 for keyword in sensitive_keywords if keyword in email_lower
        )
        
        # Check for spelling errors (simplified)
        common_errors = ['recieve', 'seperate', 'teh', 'youre', 'loose']
        features['num_spelling_errors'] = sum(
            1 for error in common_errors if error in email_lower
        )
        
        # HTML content detection
        features['contains_html'] = bool(re.search(r'<[^>]+>', email_content))
        
        # Suspicious attachments mentioned
        attachment_extensions = ['.exe', '.zip', '.rar', '.scr', '.bat', '.com']
        features['mentions_suspicious_attachment'] = any(
            ext in email_lower for ext in attachment_extensions
        )
        
    except Exception as e:
        # Set default values if extraction fails
        features.update({
            'content_length': len(email_content),
            'num_lines': 0,
            'num_words': 0,
            'num_urls': 0,
            'has_url_shortener': False,
            'num_urgent_phrases': 0,
            'has_generic_greeting': False,
            'num_sensitive_requests': 0,
            'num_spelling_errors': 0,
            'contains_html': False,
            'mentions_suspicious_attachment': False
        })
    
    return features

def extract_html_features(html_content, filename):
    """
    Extract features from HTML content for phishing detection
    """
    features = {}
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Basic HTML features
        features['html_length'] = len(html_content)
        features['filename'] = filename
        
        # Title features
        title = soup.find('title')
        features['has_title'] = title is not None
        features['title_length'] = len(title.get_text()) if title else 0
        
        # Form features
        forms = soup.find_all('form')
        features['num_forms'] = len(forms)
        
        password_inputs = soup.find_all('input', {'type': 'password'})
        features['has_password_field'] = len(password_inputs) > 0
        features['num_password_fields'] = len(password_inputs)
        
        # Check form actions
        external_form_actions = 0
        for form in forms:
            action = form.get('action', '') if hasattr(form, 'get') else ''
            if isinstance(action, str) and action.startswith('http'):
                external_form_actions += 1
        features['num_external_form_actions'] = external_form_actions
        
        # Script features
        scripts = soup.find_all('script')
        features['num_scripts'] = len(scripts)
        
        external_scripts = 0
        for script in scripts:
            src = script.get('src', '') if hasattr(script, 'get') else ''
            if isinstance(src, str) and src.startswith('http'):
                external_scripts += 1
        features['num_external_scripts'] = external_scripts
        
        # Link features
        links = soup.find_all('a')
        features['num_links'] = len(links)
        
        external_links = 0
        for link in links:
            href = link.get('href', '') if hasattr(link, 'get') else ''
            if isinstance(href, str) and href.startswith('http'):
                external_links += 1
        features['num_external_links'] = external_links
        
        # Image features
        images = soup.find_all('img')
        features['num_images'] = len(images)
        
        # Check for hidden elements
        hidden_elements = soup.find_all(attrs={'style': re.compile(r'display\s*:\s*none', re.I)})
        hidden_elements += soup.find_all(attrs={'style': re.compile(r'visibility\s*:\s*hidden', re.I)})
        features['num_hidden_elements'] = len(hidden_elements)
        
        # Check for suspicious content
        html_text = soup.get_text().lower()
        
        # Login form indicators
        login_keywords = ['username', 'password', 'login', 'sign in', 'email']
        features['num_login_keywords'] = sum(
            1 for keyword in login_keywords if keyword in html_text
        )
        
        # Brand impersonation check
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix']
        features['mentions_popular_brand'] = any(
            brand in html_text for brand in brands
        )
        
        # Obfuscated JavaScript detection
        obfuscation_patterns = ['eval(', 'unescape(', 'fromcharcode', 'decode(']
        features['has_obfuscated_js'] = any(
            pattern in html_content.lower() for pattern in obfuscation_patterns
        )
        
        # Meta refresh redirect
        meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
        features['has_meta_refresh'] = meta_refresh is not None
        
    except Exception as e:
        # Set default values if extraction fails
        features.update({
            'html_length': len(html_content),
            'filename': filename,
            'has_title': False,
            'title_length': 0,
            'num_forms': 0,
            'has_password_field': False,
            'num_password_fields': 0,
            'num_external_form_actions': 0,
            'num_scripts': 0,
            'num_external_scripts': 0,
            'num_links': 0,
            'num_external_links': 0,
            'num_images': 0,
            'num_hidden_elements': 0,
            'num_login_keywords': 0,
            'mentions_popular_brand': False,
            'has_obfuscated_js': False,
            'has_meta_refresh': False
        })
    
    return features
