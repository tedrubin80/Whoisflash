from flask import Flask, render_template, request, jsonify, send_file
import whois
import dns.resolver
import requests
import json
import re
import subprocess
import threading
import time
from datetime import datetime
import sqlite3
import os
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from geopy.geocoders import Nominatim

app = Flask(__name__)

# Database setup for caching
def init_db():
    conn = sqlite3.connect('whois_cache.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS whois_cache
                 (domain TEXT PRIMARY KEY, data TEXT, timestamp REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS dns_cache
                 (domain TEXT PRIMARY KEY, data TEXT, timestamp REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS geo_cache
                 (ip TEXT PRIMARY KEY, data TEXT, timestamp REAL)''')
    conn.commit()
    conn.close()

init_db()

class DomainIntelligence:
    def __init__(self):
        self.privacy_services = {
            'whoisguard': 'Namecheap WhoisGuard',
            'domains by proxy': 'GoDaddy Domains By Proxy',
            'perfect privacy': 'Perfect Privacy LLC',
            'contact privacy': 'Contact Privacy Inc.',
            'redacted for privacy': 'ICANN Privacy Redaction',
            'withheldforprivacy': 'Withheld for Privacy ehf',
            'domainprivacygroup': 'Domain Privacy Group'
        }
        
        self.us_regions = {
            'US', 'USA', 'UNITED STATES', 'CALIFORNIA', 'NEW YORK', 'TEXAS', 
            'FLORIDA', 'ILLINOIS', 'PENNSYLVANIA', 'OHIO', 'GEORGIA', 'NORTH CAROLINA'
        }
        
    def is_us_based(self, text):
        """Check if domain/contact is US-based"""
        if not text:
            return False
        text_upper = text.upper()
        return any(region in text_upper for region in self.us_regions)
    
    def extract_emails(self, text):
        """Extract all email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(email_pattern, str(text))))
    
    def is_privacy_protected(self, text):
        """Check if email/contact is privacy protected"""
        if not text:
            return False, None
        text_lower = text.lower()
        for keyword, service in self.privacy_services.items():
            if keyword in text_lower:
                return True, service
        return False, None
    
    def get_cached_whois(self, domain):
        """Get cached WHOIS data or fetch new"""
        conn = sqlite3.connect('whois_cache.db')
        c = conn.cursor()
        c.execute("SELECT data, timestamp FROM whois_cache WHERE domain=?", (domain,))
        result = c.fetchone()
        
        # Cache for 24 hours
        if result and (time.time() - result[1]) < 86400:
            conn.close()
            return json.loads(result[0])
        
        try:
            w = whois.whois(domain)
            data = {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'emails': w.emails if w.emails else [],
                'registrant_country': getattr(w, 'country', None),
                'status': w.status if w.status else [],
                'raw': str(w)
            }
            
            # Cache the result
            c.execute("INSERT OR REPLACE INTO whois_cache VALUES (?, ?, ?)",
                     (domain, json.dumps(data), time.time()))
            conn.commit()
            conn.close()
            return data
        except Exception as e:
            conn.close()
            return {'error': str(e), 'domain': domain}
    
    def get_dns_records(self, domain):
        """Get comprehensive DNS records"""
        conn = sqlite3.connect('dns_cache.db')
        c = conn.cursor()
        c.execute("SELECT data, timestamp FROM dns_cache WHERE domain=?", (domain,))
        result = c.fetchone()
        
        # Cache for 6 hours
        if result and (time.time() - result[1]) < 21600:
            conn.close()
            return json.loads(result[0])
        
        dns_data = {'domain': domain, 'records': {}}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_data['records'][record_type] = [str(rdata) for rdata in answers]
            except:
                dns_data['records'][record_type] = []
        
        # Parse SOA for last update info
        if dns_data['records'].get('SOA'):
            soa = dns_data['records']['SOA'][0].split()
            if len(soa) >= 3:
                serial = soa[2]
                if len(serial) == 10 and serial.isdigit():
                    year, month, day, rev = serial[:4], serial[4:6], serial[6:8], serial[8:]
                    dns_data['last_update'] = f"{year}-{month}-{day} (rev {rev})"
                dns_data['serial'] = serial
        
        # Get DIG-like information
        try:
            dig_output = subprocess.run(['dig', '+short', domain], 
                                      capture_output=True, text=True, timeout=10)
            dns_data['dig_output'] = dig_output.stdout.strip()
        except:
            dns_data['dig_output'] = "DIG command not available"
        
        # Cache the result
        c.execute("INSERT OR REPLACE INTO dns_cache VALUES (?, ?, ?)",
                 (domain, json.dumps(dns_data), time.time()))
        conn.commit()
        conn.close()
        return dns_data
    
    def get_ip_geolocation(self, ip):
        """Get geolocation for IP address"""
        if not ip or ip == 'Unknown':
            return {'country': 'Unknown', 'region': 'Unknown', 'city': 'Unknown'}
        
        conn = sqlite3.connect('whois_cache.db')
        c = conn.cursor()
        c.execute("SELECT data FROM geo_cache WHERE ip=?", (ip,))
        result = c.fetchone()
        
        if result:
            conn.close()
            return json.loads(result[0])
        
        try:
            # Try ipapi.co first
            response = requests.get(f'http://ipapi.co/{ip}/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                geo_info = {
                    'country': data.get('country_name', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('org', 'Unknown')
                }
                
                # Cache the result
                c.execute("INSERT OR REPLACE INTO geo_cache VALUES (?, ?)",
                         (ip, json.dumps(geo_info)))
                conn.commit()
                conn.close()
                return geo_info
        except:
            pass
        
        conn.close()
        return {'country': 'Unknown', 'region': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
    
    def analyze_domain_comprehensive(self, domain):
        """Comprehensive domain analysis optimized for threat intelligence"""
        start_time = time.time()
        
        # Main domain WHOIS
        main_whois = self.get_cached_whois(domain)
        if 'error' in main_whois:
            return {'error': f"Failed to get WHOIS for {domain}: {main_whois['error']}"}
        
        # DNS Analysis
        dns_data = self.get_dns_records(domain)
        
        # Extract and analyze emails
        all_emails = self.extract_emails(main_whois.get('raw', ''))
        email_analysis = []
        
        for email in all_emails:
            email_domain = email.split('@')[1] if '@' in email else None
            is_privacy, privacy_service = self.is_privacy_protected(email)
            
            email_info = {
                'email': email,
                'domain': email_domain,
                'is_privacy': is_privacy,
                'privacy_service': privacy_service,
                'is_us': self.is_us_based(email),
                'whois_data': None
            }
            
            # Get WHOIS for email domain if it's not a privacy service
            if email_domain and email_domain != domain:
                email_whois = self.get_cached_whois(email_domain)
                if 'error' not in email_whois:
                    email_info['whois_data'] = email_whois
                    email_info['email_domain_us'] = self.is_us_based(
                        email_whois.get('registrant_country', '')
                    )
                    email_info['email_domain_registrar'] = email_whois.get('registrar')
            
            email_analysis.append(email_info)
        
        # Analyze name servers
        ns_analysis = []
        for ns in main_whois.get('name_servers', []):
            if ns:
                try:
                    # Get IP of name server
                    ns_ips = dns.resolver.resolve(ns, 'A')
                    for ip in ns_ips:
                        ip_str = str(ip)
                        geo_info = self.get_ip_geolocation(ip_str)
                        
                        ns_info = {
                            'nameserver': ns,
                            'ip': ip_str,
                            'is_us': self.is_us_based(geo_info.get('country', '')),
                            'geolocation': geo_info
                        }
                        ns_analysis.append(ns_info)
                        break  # Just take first IP
                except:
                    ns_analysis.append({
                        'nameserver': ns,
                        'ip': 'Unknown',
                        'is_us': False,
                        'geolocation': {'country': 'Unknown', 'region': 'Unknown'}
                    })
        
        # Check if domain/registrar is US-based
        is_domain_us = self.is_us_based(main_whois.get('registrant_country', ''))
        is_registrar_us = self.is_us_based(main_whois.get('registrar', ''))
        
        # Privacy analysis
        main_privacy, main_privacy_service = self.is_privacy_protected(main_whois.get('raw', ''))
        
        analysis_result = {
            'domain': domain,
            'analysis_time': round(time.time() - start_time, 2),
            'main_whois': main_whois,
            'dns_data': dns_data,
            'is_domain_us': is_domain_us,
            'is_registrar_us': is_registrar_us,
            'has_privacy': main_privacy,
            'privacy_service': main_privacy_service,
            'email_analysis': email_analysis,
            'nameserver_analysis': ns_analysis,
            'us_summary': {
                'domain_us': is_domain_us,
                'registrar_us': is_registrar_us,
                'privacy_emails': len([e for e in email_analysis if e['is_privacy']]),
                'us_emails': len([e for e in email_analysis if e['is_us']]),
                'us_nameservers': len([ns for ns in ns_analysis if ns['is_us']])
            }
        }
        
        return analysis_result

# Initialize the intelligence engine
intel = DomainIntelligence()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze/<domain>')
def analyze_domain(domain):
    """API endpoint for domain analysis"""
    try:
        result = intel.analyze_domain_comprehensive(domain)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/bulk_analyze', methods=['POST'])
def bulk_analyze():
    """Analyze multiple domains"""
    domains = request.json.get('domains', [])
    if not domains:
        return jsonify({'error': 'No domains provided'}), 400
    
    results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {
            executor.submit(intel.analyze_domain_comprehensive, domain): domain 
            for domain in domains[:10]  # Limit to 10 domains
        }
        
        for future in future_to_domain:
            domain = future_to_domain[future]
            try:
                results[domain] = future.result(timeout=30)
            except Exception as e:
                results[domain] = {'error': str(e)}
    
    return jsonify(results)

@app.route('/export/<format>/<domain>')
def export_data(format, domain):
    """Export analysis data"""
    result = intel.analyze_domain_comprehensive(domain)
    
    if format == 'json':
        filename = f"{domain}_analysis.json"
        with open(filename, 'w') as f:
            json.dump(result, f, indent=2)
        return send_file(filename, as_attachment=True)
    
    elif format == 'txt':
        filename = f"{domain}_analysis.txt"
        with open(filename, 'w') as f:
            f.write(f"DOMAIN INTELLIGENCE REPORT\n")
            f.write(f"{'='*50}\n")
            f.write(f"Domain: {domain}\n")
            f.write(f"Analysis Time: {result.get('analysis_time', 0)} seconds\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"US CLASSIFICATION SUMMARY\n")
            f.write(f"{'-'*30}\n")
            us_summary = result.get('us_summary', {})
            f.write(f"Domain US-based: {us_summary.get('domain_us', False)}\n")
            f.write(f"Registrar US-based: {us_summary.get('registrar_us', False)}\n")
            f.write(f"Privacy emails: {us_summary.get('privacy_emails', 0)}\n")
            f.write(f"US emails: {us_summary.get('us_emails', 0)}\n")
            f.write(f"US nameservers: {us_summary.get('us_nameservers', 0)}\n\n")
            
            f.write(f"EMAIL ANALYSIS\n")
            f.write(f"{'-'*20}\n")
            for email in result.get('email_analysis', []):
                f.write(f"Email: {email['email']}\n")
                f.write(f"  Privacy: {email['is_privacy']}\n")
                f.write(f"  US-based: {email['is_us']}\n")
                if email.get('privacy_service'):
                    f.write(f"  Service: {email['privacy_service']}\n")
                f.write(f"\n")
            
            f.write(f"NAMESERVER ANALYSIS\n")
            f.write(f"{'-'*25}\n")
            for ns in result.get('nameserver_analysis', []):
                f.write(f"NS: {ns['nameserver']}\n")
                f.write(f"  IP: {ns['ip']}\n")
                f.write(f"  US-based: {ns['is_us']}\n")
                f.write(f"  Country: {ns['geolocation'].get('country', 'Unknown')}\n")
                f.write(f"\n")
        
        return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)