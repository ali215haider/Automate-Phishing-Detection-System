import re
import json
import tldextract
from urllib.parse import urlparse, parse_qs
from utils.feature_extraction import extract_url_features, extract_email_features, extract_html_features
from utils.blacklist import check_blacklist, check_whitelist
from utils.ml_model import predict_phishing

def analyze_url(url):
    """
    Comprehensive URL analysis combining rule-based and ML detection
    """
    result = {
        'result': 'safe',
        'confidence': 0.0,
        'method': 'rules',
        'details': {
            'features': {},
            'rules_triggered': [],
            'blacklist_match': False,
            'whitelist_match': False
        }
    }
    
    try:
        # Extract features
        features = extract_url_features(url)
        result['details']['features'] = features
        
        # Check whitelist first
        domain = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
        if check_whitelist(domain):
            result['details']['whitelist_match'] = True
            result['confidence'] = 0.95
            return result
        
        # Check blacklist
        if check_blacklist(domain):
            result['result'] = 'phishing'
            result['confidence'] = 0.95
            result['method'] = 'blacklist'
            result['details']['blacklist_match'] = True
            return result
        
        # Apply rule-based detection
        rules_score = 0
        triggered_rules = []
        
        # Rule 1: URL length
        if features['url_length'] > 100:
            rules_score += 0.3
            triggered_rules.append('Long URL (>100 chars)')
        
        # Rule 2: Number of dots
        if features['num_dots'] > 4:
            rules_score += 0.2
            triggered_rules.append('Too many subdomains')
        
        # Rule 3: Contains '@' symbol
        if '@' in url:
            rules_score += 0.4
            triggered_rules.append('Contains @ symbol')
        
        # Rule 4: IP address instead of domain
        if features['has_ip']:
            rules_score += 0.5
            triggered_rules.append('Uses IP address instead of domain')
        
        # Rule 5: No HTTPS
        if not features['uses_https']:
            rules_score += 0.2
            triggered_rules.append('No HTTPS encryption')
        
        # Rule 6: Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.cc']
        extracted = tldextract.extract(url)
        if f".{extracted.suffix}" in suspicious_tlds:
            rules_score += 0.3
            triggered_rules.append('Suspicious TLD')
        
        # Rule 7: URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
        if any(shortener in url.lower() for shortener in shorteners):
            rules_score += 0.3
            triggered_rules.append('URL shortener detected')
        
        # Rule 8: Suspicious keywords
        suspicious_keywords = ['secure', 'account', 'update', 'verify', 'login', 'banking', 'paypal']
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            rules_score += 0.2
            triggered_rules.append('Contains suspicious keywords')
        
        result['details']['rules_triggered'] = triggered_rules
        
        # Use ML model for final prediction
        try:
            ml_prediction = predict_phishing(features)
            result['method'] = 'ml'
            result['confidence'] = ml_prediction['confidence']
            
            # Combine rules and ML
            combined_score = (rules_score + ml_prediction['confidence']) / 2
            
            if combined_score > 0.7:
                result['result'] = 'phishing'
            elif combined_score > 0.4:
                result['result'] = 'suspicious'
            else:
                result['result'] = 'safe'
                
            result['confidence'] = combined_score
            
        except Exception as e:
            # Fallback to rules-based detection
            result['method'] = 'rules'
            result['confidence'] = rules_score
            
            if rules_score > 0.6:
                result['result'] = 'phishing'
            elif rules_score > 0.3:
                result['result'] = 'suspicious'
        
    except Exception as e:
        result['result'] = 'error'
        result['details']['error'] = str(e)
    
    return result

def analyze_email(email_content):
    """
    Email content analysis for phishing detection
    """
    result = {
        'result': 'safe',
        'confidence': 0.0,
        'method': 'rules',
        'details': {
            'features': {},
            'rules_triggered': [],
            'suspicious_urls': []
        }
    }
    
    try:
        # Extract features
        features = extract_email_features(email_content)
        result['details']['features'] = features
        
        # Apply rule-based detection
        rules_score = 0
        triggered_rules = []
        
        # Rule 1: Urgent language
        urgent_phrases = [
            'urgent', 'immediate action', 'account suspended', 'verify now',
            'act now', 'expires today', 'limited time', 'click here now',
            'your account will be closed', 'suspended', 'locked'
        ]
        
        email_lower = email_content.lower()
        urgent_count = sum(1 for phrase in urgent_phrases if phrase in email_lower)
        if urgent_count >= 2:
            rules_score += 0.4
            triggered_rules.append(f'Urgent language detected ({urgent_count} phrases)')
        
        # Rule 2: Generic greetings
        generic_greetings = ['dear customer', 'dear user', 'dear member', 'hello there']
        if any(greeting in email_lower for greeting in generic_greetings):
            rules_score += 0.2
            triggered_rules.append('Generic greeting used')
        
        # Rule 3: Spelling/grammar errors (simplified check)
        common_errors = ['recieve', 'seperate', 'teh', 'youre account', 'loose', 'there account']
        error_count = sum(1 for error in common_errors if error in email_lower)
        if error_count > 0:
            rules_score += 0.3
            triggered_rules.append(f'Spelling errors detected ({error_count})')
        
        # Rule 4: Suspicious URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_content)
        
        suspicious_urls = []
        for url in urls:
            url_analysis = analyze_url(url)
            if url_analysis['result'] in ['phishing', 'suspicious']:
                suspicious_urls.append(url)
        
        if suspicious_urls:
            rules_score += 0.5
            triggered_rules.append(f'Suspicious URLs found ({len(suspicious_urls)})')
            result['details']['suspicious_urls'] = suspicious_urls
        
        # Rule 5: Requests for sensitive information
        sensitive_requests = [
            'password', 'social security', 'credit card', 'bank account',
            'personal information', 'confirm your identity', 'verify your account'
        ]
        
        sensitive_count = sum(1 for request in sensitive_requests if request in email_lower)
        if sensitive_count >= 2:
            rules_score += 0.3
            triggered_rules.append('Requests sensitive information')
        
        result['details']['rules_triggered'] = triggered_rules
        result['confidence'] = min(rules_score, 1.0)
        
        if rules_score > 0.6:
            result['result'] = 'phishing'
        elif rules_score > 0.3:
            result['result'] = 'suspicious'
        
    except Exception as e:
        result['result'] = 'error'
        result['details']['error'] = str(e)
    
    return result

def analyze_html_file(html_content, filename):
    """
    HTML file analysis for phishing detection
    """
    result = {
        'result': 'safe',
        'confidence': 0.0,
        'method': 'rules',
        'details': {
            'features': {},
            'rules_triggered': [],
            'suspicious_elements': []
        }
    }
    
    try:
        # Extract features
        features = extract_html_features(html_content, filename)
        result['details']['features'] = features
        
        # Apply rule-based detection
        rules_score = 0
        triggered_rules = []
        suspicious_elements = []
        
        # Rule 1: Hidden/invisible elements
        html_lower = html_content.lower()
        if 'display:none' in html_lower or 'visibility:hidden' in html_lower:
            rules_score += 0.3
            triggered_rules.append('Hidden elements detected')
            suspicious_elements.append('Hidden CSS elements')
        
        # Rule 2: Suspicious form actions
        form_pattern = r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>'
        forms = re.findall(form_pattern, html_content, re.IGNORECASE)
        
        for form_action in forms:
            if form_action.startswith('http') and 'localhost' not in form_action:
                # Analyze the form action URL
                url_analysis = analyze_url(form_action)
                if url_analysis['result'] in ['phishing', 'suspicious']:
                    rules_score += 0.4
                    triggered_rules.append('Suspicious form action URL')
                    suspicious_elements.append(f'Form action: {form_action}')
        
        # Rule 3: External scripts from suspicious domains
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        scripts = re.findall(script_pattern, html_content, re.IGNORECASE)
        
        for script_src in scripts:
            if script_src.startswith('http'):
                domain = tldextract.extract(script_src).domain
                if check_blacklist(domain):
                    rules_score += 0.5
                    triggered_rules.append('Script from blacklisted domain')
                    suspicious_elements.append(f'Script: {script_src}')
        
        # Rule 4: Password input fields without HTTPS
        if '<input' in html_lower and 'type="password"' in html_lower:
            # Check if any forms don't use HTTPS
            if any(not action.startswith('https://') for action in forms if action.startswith('http')):
                rules_score += 0.4
                triggered_rules.append('Password field without HTTPS')
        
        # Rule 5: Fake login forms
        login_indicators = ['username', 'password', 'login', 'sign in', 'email']
        login_count = sum(1 for indicator in login_indicators if indicator in html_lower)
        
        if login_count >= 3:
            # This looks like a login form - check if it's legitimate
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).lower()
                # Check for impersonation of popular services
                impersonated_services = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook']
                if any(service in title for service in impersonated_services):
                    rules_score += 0.3
                    triggered_rules.append('Possible service impersonation')
        
        # Rule 6: Obfuscated JavaScript
        if 'eval(' in html_content or 'unescape(' in html_content or 'fromcharcode' in html_lower:
            rules_score += 0.4
            triggered_rules.append('Obfuscated JavaScript detected')
            suspicious_elements.append('Obfuscated code')
        
        result['details']['rules_triggered'] = triggered_rules
        result['details']['suspicious_elements'] = suspicious_elements
        result['confidence'] = min(rules_score, 1.0)
        
        if rules_score > 0.6:
            result['result'] = 'phishing'
        elif rules_score > 0.3:
            result['result'] = 'suspicious'
        
    except Exception as e:
        result['result'] = 'error'
        result['details']['error'] = str(e)
    
    return result
