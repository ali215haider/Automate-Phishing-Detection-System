import os
import tldextract
from models import BlacklistDomain, WhitelistDomain

def load_blacklist_from_file():
    """Load blacklist domains from file"""
    blacklist = set()
    blacklist_file = os.path.join('data', 'blacklist.txt')
    
    if os.path.exists(blacklist_file):
        try:
            with open(blacklist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        blacklist.add(domain)
        except Exception as e:
            print(f"Error loading blacklist file: {e}")
    
    return blacklist

def load_whitelist_from_file():
    """Load whitelist domains from file"""
    whitelist = set()
    whitelist_file = os.path.join('data', 'whitelist.txt')
    
    if os.path.exists(whitelist_file):
        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        whitelist.add(domain)
        except Exception as e:
            print(f"Error loading whitelist file: {e}")
    
    return whitelist

# Load blacklist and whitelist on module import
_blacklist_cache = load_blacklist_from_file()
_whitelist_cache = load_whitelist_from_file()

def check_blacklist(domain):
    """
    Check if a domain is in the blacklist
    Checks both file-based blacklist and database blacklist
    """
    if not domain:
        return False
    
    domain = domain.lower().strip()
    
    # Extract the main domain
    extracted = tldextract.extract(domain)
    main_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else domain
    
    # Check file-based blacklist
    if domain in _blacklist_cache or main_domain in _blacklist_cache:
        return True
    
    # Check database blacklist
    try:
        from app import db
        blacklist_entry = BlacklistDomain.query.filter(
            db.or_(
                BlacklistDomain.domain == domain,
                BlacklistDomain.domain == main_domain
            )
        ).filter_by(is_active=True).first()
        
        return blacklist_entry is not None
    except Exception as e:
        print(f"Error checking database blacklist: {e}")
        return False

def check_whitelist(domain):
    """
    Check if a domain is in the whitelist
    Checks both file-based whitelist and database whitelist
    """
    if not domain:
        return False
    
    domain = domain.lower().strip()
    
    # Extract the main domain
    extracted = tldextract.extract(domain)
    main_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else domain
    
    # Check file-based whitelist
    if domain in _whitelist_cache or main_domain in _whitelist_cache:
        return True
    
    # Check database whitelist
    try:
        from app import db
        whitelist_entry = WhitelistDomain.query.filter(
            db.or_(
                WhitelistDomain.domain == domain,
                WhitelistDomain.domain == main_domain
            )
        ).filter_by(is_active=True).first()
        
        return whitelist_entry is not None
    except Exception as e:
        print(f"Error checking database whitelist: {e}")
        return False

def add_to_blacklist(domain, source='manual'):
    """Add a domain to the database blacklist"""
    try:
        from app import db
        domain = domain.lower().strip()
        
        # Check if already exists
        existing = BlacklistDomain.query.filter_by(domain=domain).first()
        if not existing:
            new_entry = BlacklistDomain()
            new_entry.domain = domain
            new_entry.source = source
            db.session.add(new_entry)
            db.session.commit()
            return True
        else:
            # Reactivate if it was deactivated
            if not existing.is_active:
                existing.is_active = True
                db.session.commit()
            return True
    except Exception as e:
        print(f"Error adding to blacklist: {e}")
        return False

def add_to_whitelist(domain):
    """Add a domain to the database whitelist"""
    try:
        from app import db
        domain = domain.lower().strip()
        
        # Check if already exists
        existing = WhitelistDomain.query.filter_by(domain=domain).first()
        if not existing:
            new_entry = WhitelistDomain()
            new_entry.domain = domain
            db.session.add(new_entry)
            db.session.commit()
            return True
        else:
            # Reactivate if it was deactivated
            if not existing.is_active:
                existing.is_active = True
                db.session.commit()
            return True
    except Exception as e:
        print(f"Error adding to whitelist: {e}")
        return False

def refresh_cache():
    """Refresh the cached blacklist and whitelist from files"""
    global _blacklist_cache, _whitelist_cache
    _blacklist_cache = load_blacklist_from_file()
    _whitelist_cache = load_whitelist_from_file()
