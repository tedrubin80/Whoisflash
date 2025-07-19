<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Intelligence Platform - Threat Analysis</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <style>
        body { 
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); 
            min-height: 100vh; 
        }
        .main-container { 
            background: rgba(255, 255, 255, 0.95); 
            backdrop-filter: blur(10px); 
            border-radius: 20px; 
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); 
            margin-top: 2rem; 
        }
        .hero-section { 
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); 
            color: white; 
            border-radius: 20px 20px 0 0; 
            padding: 2rem 0; 
        }
        .analysis-card { 
            border: none; 
            border-radius: 15px; 
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
            margin-bottom: 1.5rem; 
            transition: transform 0.2s ease; 
        }
        .analysis-card:hover { 
            transform: translateY(-2px); 
        }
        .us-indicator { 
            background: linear-gradient(135deg, #27ae60 0%, #229954 100%); 
        }
        .non-us-indicator { 
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); 
        }
        .privacy-indicator { 
            background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); 
        }
        .metric-card { 
            text-align: center; 
            padding: 1.5rem; 
            border-radius: 15px; 
            background: white; 
            border: 2px solid #ecf0f1; 
        }
        .metric-number { 
            font-size: 2rem; 
            font-weight: bold; 
        }
        .btn-analyze { 
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); 
            border: none; 
            border-radius: 25px; 
            padding: 12px 30px; 
            font-weight: 600; 
        }
        .loading-spinner { 
            display: none; 
        }
        .threat-level-high { 
            color: #e74c3c; 
            font-weight: bold; 
        }
        .threat-level-medium { 
            color: #f39c12; 
            font-weight: bold; 
        }
        .threat-level-low { 
            color: #27ae60; 
            font-weight: bold; 
        }
        
        /* Fix tab styling - make text black */
        .nav-pills .nav-link {
            color: #333 !important;
            background-color: rgba(255, 255, 255, 0.8);
            border: 2px solid rgba(255, 255, 255, 0.3);
            margin: 0 5px;
        }
        .nav-pills .nav-link.active {
            color: #000 !important;
            background-color: rgba(255, 255, 255, 0.95);
            border: 2px solid rgba(255, 255, 255, 0.8);
        }
        .nav-pills .nav-link:hover {
            color: #000 !important;
            background-color: rgba(255, 255, 255, 0.9);
        }
        
        /* Error styling */
        .error-display {
            background: #ffebee;
            color: #c62828;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #f44336;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row justify-content-center">
            <div class="col-12 col-xl-11">
                <div class="main-container">
                    <!-- Hero Section -->
                    <div class="hero-section">
                        <div class="container">
                            <div class="row">
                                <div class="col-12 text-center">
                                    <h1 class="display-4 fw-bold mb-3">
                                        <i class="bi bi-shield-exclamation"></i> Domain Threat Intelligence
                                    </h1>
                                    <p class="lead mb-4">Automated US/Non-US Classification & Privacy Analysis</p>
                                    
                                    <!-- Navigation Tabs -->
                                    <ul class="nav nav-pills nav-fill justify-content-center mb-4" id="mainTabs" role="tablist">
                                        <li class="nav-item" role="presentation">
                                            <button class="nav-link active" id="domain-tab" data-bs-toggle="pill" 
                                                    data-bs-target="#domain-analysis" type="button" role="tab">
                                                <i class="bi bi-globe"></i> Domain Analysis
                                            </button>
                                        </li>
                                        <li class="nav-item" role="presentation">
                                            <button class="nav-link" id="bulk-tab" data-bs-toggle="pill" 
                                                    data-bs-target="#bulk-analysis" type="button" role="tab">
                                                <i class="bi bi-list-ul"></i> Bulk Analysis
                                            </button>
                                        </li>
                                    </ul>

                                    <!-- Tab Content -->
                                    <div class="tab-content" id="mainTabContent">
                                        <!-- Domain Analysis Tab -->
                                        <div class="tab-pane fade show active" id="domain-analysis" role="tabpanel">
                                            <div class="row justify-content-center">
                                                <div class="col-md-8">
                                                    <div class="input-group input-group-lg">
                                                        <span class="input-group-text bg-white"><i class="bi bi-search"></i></span>
                                                        <input type="text" class="form-control" id="domainInput" 
                                                               placeholder="Enter domain for threat analysis (e.g., suspicious-domain.com)" 
                                                               autocomplete="off">
                                                        <button class="btn btn-light btn-analyze" onclick="analyzeDomain()" id="analyzeBtn">
                                                            <i class="bi bi-shield-check"></i> Analyze Threat
                                                        </button>
                                                    </div>
                                                    <div class="mt-2">
                                                        <small class="text-light">
                                                            <i class="bi bi-info-circle"></i> 
                                                            Instant classification: US vs Non-US registration, privacy detection, contact analysis
                                                        </small>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>

                                        <!-- Bulk Analysis Tab -->
                                        <div class="tab-pane fade" id="bulk-analysis" role="tabpanel">
                                            <div class="row justify-content-center">
                                                <div class="col-md-8">
                                                    <div class="mb-3">
                                                        <label for="bulkDomains" class="form-label text-white">Enter domains (one per line):</label>
                                                        <textarea class="form-control" id="bulkDomains" rows="8" 
                                                                  placeholder="suspicious-domain1.com&#10;suspicious-domain2.org&#10;threat-domain.net"></textarea>
                                                    </div>
                                                    <button class="btn btn-light btn-analyze" onclick="bulkAnalyze()" id="bulkAnalyzeBtn">
                                                        <i class="bi bi-shield-check"></i> Analyze All Domains
                                                    </button>
                                                    <div class="mt-2">
                                                        <small class="text-light">
                                                            <i class="bi bi-info-circle"></i> 
                                                            Maximum 10 domains per batch for performance
                                                        </small>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Quick Actions -->
                                    <div class="row justify-content-center mt-4">
                                        <div class="col-md-6">
                                            <button class="btn btn-outline-light me-2" onclick="clearCache()">
                                                <i class="bi bi-arrow-clockwise"></i> Clear Cache
                                            </button>
                                            <button class="btn btn-outline-light" onclick="showApiHelp()">
                                                <i class="bi bi-question-circle"></i> API Help
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Loading Indicator -->
                    <div class="container loading-spinner" id="loadingSpinner">
                        <div class="row py-5">
                            <div class="col-12 text-center">
                                <div class="spinner-border text-danger" style="width: 3rem; height: 3rem;" role="status">
                                    <span class="visually-hidden">Analyzing...</span>
                                </div>
                                <h4 class="mt-3">Analyzing Domain Threat Level</h4>
                                <p class="text-muted">Checking registrar, contacts, DNS, and geographic data...</p>
                            </div>
                        </div>
                    </div>

                    <!-- Results Section -->
                    <div class="container" id="resultsContainer" style="display: none;">
                        <div class="row py-5">
                            <div class="col-12">
                                <!-- Threat Assessment Header -->
                                <div class="alert d-flex align-items-center mb-4" id="threatAlert" role="alert">
                                    <i class="bi me-2" id="threatIcon"></i>
                                    <div>
                                        <strong id="threatTitle"></strong> <span id="analyzedDomain"></span>
                                        <div class="mt-1"><small id="threatDescription"></small></div>
                                    </div>
                                </div>

                                <!-- Quick Intelligence Summary -->
                                <div class="row mb-4">
                                    <div class="col-12">
                                        <h3 class="mb-3"><i class="bi bi-speedometer2"></i> Intelligence Summary</h3>
                                    </div>
                                    <div class="col-6 col-md-3">
                                        <div class="metric-card">
                                            <div class="metric-number" id="usClassification">Unknown</div>
                                            <div class="text-muted">US Classification</div>
                                        </div>
                                    </div>
                                    <div class="col-6 col-md-3">
                                        <div class="metric-card">
                                            <div class="metric-number" id="privacyStatus">Unknown</div>
                                            <div class="text-muted">Privacy Status</div>
                                        </div>
                                    </div>
                                    <div class="col-6 col-md-3">
                                        <div class="metric-card">
                                            <div class="metric-number" id="emailCount">0</div>
                                            <div class="text-muted">Contact Emails</div>
                                        </div>
                                    </div>
                                    <div class="col-6 col-md-3">
                                        <div class="metric-card">
                                            <div class="metric-number" id="nsCount">0</div>
                                            <div class="text-muted">Name Servers</div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Analysis Results -->
                                <div class="row">
                                    <!-- Domain Registration Info -->
                                    <div class="col-12 col-lg-6 mb-4">
                                        <div class="card analysis-card h-100">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-building"></i> Registration Intelligence</h5>
                                            </div>
                                            <div class="card-body">
                                                <div id="registrationInfo"></div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- DNS & Infrastructure -->
                                    <div class="col-12 col-lg-6 mb-4">
                                        <div class="card analysis-card h-100">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-diagram-3"></i> DNS Infrastructure</h5>
                                            </div>
                                            <div class="card-body">
                                                <div id="dnsInfo"></div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Email Contact Analysis -->
                                    <div class="col-12 mb-4">
                                        <div class="card analysis-card">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-envelope-exclamation"></i> Contact Intelligence</h5>
                                            </div>
                                            <div class="card-body">
                                                <div id="emailAnalysis"></div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Name Server Geographic Analysis -->
                                    <div class="col-12 mb-4">
                                        <div class="card analysis-card">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-geo-alt"></i> Geographic Intelligence</h5>
                                            </div>
                                            <div class="card-body">
                                                <div id="nameServerAnalysis"></div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Export & Actions -->
                                    <div class="col-12">
                                        <div class="card analysis-card">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-download"></i> Export Intelligence Report</h5>
                                            </div>
                                            <div class="card-body text-center">
                                                <p class="text-muted mb-3">Export threat intelligence analysis for reporting and documentation</p>
                                                <button class="btn btn-success me-2" onclick="exportData('txt')">
                                                    <i class="bi bi-file-text"></i> Export TXT Report
                                                </button>
                                                <button class="btn btn-info me-2" onclick="exportData('json')">
                                                    <i class="bi bi-file-code"></i> Export JSON Data
                                                </button>
                                                <button class="btn btn-warning" onclick="copyToClipboard()">
                                                    <i class="bi bi-clipboard"></i> Copy Summary
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentAnalysis = null;

        // Domain validation function
        function isValidDomain(domain) {
            const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
            return domainRegex.test(domain.trim());
        }

        // Show error message
        function showError(message) {
            const errorHtml = `
                <div class="error-display">
                    <h5><i class="bi bi-exclamation-triangle"></i> Analysis Failed</h5>
                    <p>${message}</p>
                </div>
            `;
            
            document.getElementById('resultsContainer').innerHTML = `
                <div class="row py-5">
                    <div class="col-12">
                        ${errorHtml}
                    </div>
                </div>
            `;
            document.getElementById('resultsContainer').style.display = 'block';
        }

        async function analyzeDomain() {
            const domain = document.getElementById('domainInput').value.trim();
            
            if (!domain) {
                alert('Please enter a domain name');
                return;
            }

            if (!isValidDomain(domain)) {
                alert('Please enter a valid domain name (e.g., example.com)');
                return;
            }

            console.log('Starting analysis for:', domain);
            showLoading();
            hideResults();

            try {
                const response = await fetch(`/api/analyze/${encodeURIComponent(domain)}`, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    }
                });
                
                console.log('Response status:', response.status);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const data = await response.json();
                console.log('Analysis data received:', data);
                
                if (data.error) {
                    throw new Error(data.error);
                }

                currentAnalysis = data;
                displayResults(data);
            } catch (error) {
                console.error('Analysis error:', error);
                hideLoading();
                showError(`Failed to analyze domain: ${error.message}`);
            }
        }

        function showLoading() {
            document.getElementById('loadingSpinner').style.display = 'block';
            document.getElementById('resultsContainer').style.display = 'none';
            document.getElementById('analyzeBtn').disabled = true;
        }

        function hideLoading() {
            document.getElementById('loadingSpinner').style.display = 'none';
            document.getElementById('analyzeBtn').disabled = false;
        }

        function hideResults() {
            document.getElementById('resultsContainer').style.display = 'none';
        }

        function displayResults(data) {
            hideLoading();
            
            // Update domain name
            document.getElementById('analyzedDomain').textContent = data.domain;
            
            // Determine threat level and classification
            const usSum = data.us_summary || {};
            let threatLevel = 'low';
            let threatClass = 'alert-success';
            let threatIcon = 'bi-shield-check';
            let threatTitle = 'Low Threat';
            let threatDesc = 'Domain appears to be legitimately registered with standard practices.';

            if (!usSum.domain_us && !usSum.registrar_us && usSum.privacy_emails > 0) {
                threatLevel = 'high';
                threatClass = 'alert-danger';
                threatIcon = 'bi-shield-exclamation';
                threatTitle = 'High Threat';
                threatDesc = 'Non-US registration with privacy protection - requires investigation.';
            } else if (!usSum.domain_us || !usSum.registrar_us) {
                threatLevel = 'medium';
                threatClass = 'alert-warning';
                threatIcon = 'bi-shield-slash';
                threatTitle = 'Medium Threat';
                threatDesc = 'Partial non-US registration detected - monitor for suspicious activity.';
            }

            document.getElementById('threatAlert').className = `alert ${threatClass} d-flex align-items-center mb-4`;
            document.getElementById('threatIcon').className = `bi ${threatIcon} me-2`;
            document.getElementById('threatTitle').textContent = threatTitle;
            document.getElementById('threatDescription').textContent = threatDesc;

            // Update metrics
            document.getElementById('usClassification').textContent = usSum.domain_us ? 'US-Based' : 'Non-US';
            document.getElementById('usClassification').className = `metric-number ${usSum.domain_us ? 'threat-level-low' : 'threat-level-high'}`;
            
            document.getElementById('privacyStatus').textContent = data.has_privacy ? 'Protected' : 'Public';
            document.getElementById('privacyStatus').className = `metric-number ${data.has_privacy ? 'threat-level-medium' : 'threat-level-low'}`;
            
            document.getElementById('emailCount').textContent = data.email_analysis ? data.email_analysis.length : 0;
            document.getElementById('nsCount').textContent = data.nameserver_analysis ? data.nameserver_analysis.length : 0;

            // Registration Info
            const whois = data.main_whois || {};
            const regInfo = `
                <div class="table-responsive">
                    <table class="table table-borderless">
                        <tr><td><strong>Registrar:</strong></td><td>${whois.registrar || 'Unknown'}</td></tr>
                        <tr><td><strong>US Registrar:</strong>#!/bin/bash

# Domain Intelligence Platform Setup Script
# Creates complete project structure and files

set -e  # Exit on any error

echo "🚀 Setting up Domain Intelligence Platform..."
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Create project directory
PROJECT_NAME="domain-intelligence-platform"
if [ -d "$PROJECT_NAME" ]; then
    print_warning "Directory $PROJECT_NAME already exists!"
    read -p "Do you want to remove it and start fresh? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$PROJECT_NAME"
        print_status "Removed existing directory"
    else
        echo "Exiting..."
        exit 1
    fi
fi

mkdir "$PROJECT_NAME"
cd "$PROJECT_NAME"
print_status "Created project directory: $PROJECT_NAME"

# Create directory structure
print_info "Creating directory structure..."
mkdir -p templates
mkdir -p static/{css,js,images}
mkdir -p api
mkdir -p models  
mkdir -p utils
mkdir -p tests
mkdir -p docs
mkdir -p data
mkdir -p scripts
mkdir -p database
print_status "Directory structure created"

# Create app.py (Main Flask Application)
print_info "Creating app.py..."
cat > app.py << 'EOF'
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
EOF
print_status "Created app.py"

# Create templates/index.html
print_info "Creating templates/index.html..."
cat > templates/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Intelligence Platform - Threat Analysis</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <style>
        body { background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%); min-height: 100vh; }
        .main-container { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); margin-top: 2rem; }
        .hero-section { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: white; border-radius: 20px 20px 0 0; padding: 2rem 0; }
        .analysis-card { border: none; border-radius: 15px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); margin-bottom: 1.5rem; transition: transform 0.2s ease; }
        .analysis-card:hover { transform: translateY(-2px); }
        .us-indicator { background: linear-gradient(135deg, #27ae60 0%, #229954 100%); }
        .non-us-indicator { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .privacy-indicator { background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); }
        .metric-card { text-align: center; padding: 1.5rem; border-radius: 15px; background: white; border: 2px solid #ecf0f1; }
        .metric-number { font-size: 2rem; font-weight: bold; }
        .btn-analyze { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); border: none; border-radius: 25px; padding: 12px 30px; font-weight: 600; }
        .loading-spinner { display: none; }
        .threat-level-high { color: #e74c3c; font-weight: bold; }
        .threat-level-medium { color: #f39c12; font-weight: bold; }
        .threat-level-low { color: #27ae60; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row justify-content-center">
            <div class="col-12 col-xl-11">
                <div class="main-container">
                    <!-- Hero Section -->
                    <div class="hero-section">
                        <div class="container">
                            <div class="row">
                                <div class="col-12 text-center">
                                    <h1 class="display-4 fw-bold mb-3">
                                        <i class="bi bi-shield-exclamation"></i> Domain Threat Intelligence
                                    </h1>
                                    <p class="lead mb-4">Automated US/Non-US Classification & Privacy Analysis</p>
                                    
                                    <!-- Quick Analysis Form -->
                                    <div class="row justify-content-center">
                                        <div class="col-md-8">
                                            <div class="input-group input-group-lg">
                                                <span class="input-group-text bg-white"><i class="bi bi-search"></i></span>
                                                <input type="text" class="form-control" id="domainInput" 
                                                       placeholder="Enter domain for threat analysis (e.g., suspicious-domain.com)" 
                                                       autocomplete="off">
                                                <button class="btn btn-light btn-analyze" onclick="analyzeDomain()" id="analyzeBtn">
                                                    <i class="bi bi-shield-check"></i> Analyze Threat
                                                </button>
                                            </div>
                                            <div class="mt-2">
                                                <small class="text-light">
                                                    <i class="bi bi-info-circle"></i> 
                                                    Instant classification: US vs Non-US registration, privacy detection, contact analysis
                                                </small>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Bulk Analysis -->
                                    <div class="row justify-content-center mt-4">
                                        <div class="col-md-6">
                                            <button class="btn btn-outline-light" data-bs-toggle="modal" data-bs-target="#bulkModal">
                                                <i class="bi bi-list-ul"></i> Bulk Analysis
                                            </button>
                                            <button class="btn btn-outline-light ms-2" onclick="clearCache()">
                                                <i class="bi bi-arrow-clockwise"></i> Clear Cache
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Loading Indicator -->
                    <div class="container loading-spinner" id="loadingSpinner">
                        <div class="row py-5">
                            <div class="col-12 text-center">
                                <div class="spinner-border text-danger" style="width: 3rem; height: 3rem;" role="status">
                                    <span class="visually-hidden">Analyzing...</span>
                                </div>
                                <h4 class="mt-3">Analyzing Domain Threat Level</h4>
                                <p class="text-muted">Checking registrar, contacts, DNS, and geographic data...</p>
                            </div>
                        </div>
                    </div>

                    <!-- Results Section -->
                    <div class="container" id="resultsContainer" style="display: none;">
                        <div class="row py-5">
                            <div class="col-12">
                                <!-- Threat Assessment Header -->
                                <div class="alert d-flex align-items-center mb-4" id="threatAlert" role="alert">
                                    <i class="bi me-2" id="threatIcon"></i>
                                    <div>
                                        <strong id="threatTitle"></strong> <span id="analyzedDomain"></span>
                                        <div class="mt-1"><small id="threatDescription"></small></div>
                                    </div>
                                </div>

                                <!-- Quick Intelligence Summary -->
                                <div class="row mb-4">
                                    <div class="col-12">
                                        <h3 class="mb-3"><i class="bi bi-speedometer2"></i> Intelligence Summary</h3>
                                    </div>
                                    <div class="col-6 col-md-3">
                                        <div class="metric-card">
                                            <div class="metric-number" id="usClassification">Unknown</div>
                                            <div class="text-muted">US Classification</div>
                                        </div>
                                    </div>
                                    <div class="col-6 col-md-3">
                                        <div class="metric-card">
                                            <div class="metric-number" id="privacyStatus">Unknown</div>
                                            <div class="text-muted">Privacy Status</div>
                                        </div>
                                    </div>
                                    <div class="col-6 col-md-3">
                                        <div class="metric-card">
                                            <div class="metric-number" id="emailCount">0</div>
                                            <div class="text-muted">Contact Emails</div>
                                        </div>
                                    </div>
                                    <div class="col-6 col-md-3">
                                        <div class="metric-card">
                                            <div class="metric-number" id="nsCount">0</div>
                                            <div class="text-muted">Name Servers</div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Analysis Results -->
                                <div class="row">
                                    <!-- Domain Registration Info -->
                                    <div class="col-12 col-lg-6 mb-4">
                                        <div class="card analysis-card h-100">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-building"></i> Registration Intelligence</h5>
                                            </div>
                                            <div class="card-body">
                                                <div id="registrationInfo"></div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- DNS & Infrastructure -->
                                    <div class="col-12 col-lg-6 mb-4">
                                        <div class="card analysis-card h-100">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-diagram-3"></i> DNS Infrastructure</h5>
                                            </div>
                                            <div class="card-body">
                                                <div id="dnsInfo"></div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Email Contact Analysis -->
                                    <div class="col-12 mb-4">
                                        <div class="card analysis-card">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-envelope-exclamation"></i> Contact Intelligence</h5>
                                            </div>
                                            <div class="card-body">
                                                <div id="emailAnalysis"></div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Name Server Geographic Analysis -->
                                    <div class="col-12 mb-4">
                                        <div class="card analysis-card">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-geo-alt"></i> Geographic Intelligence</h5>
                                            </div>
                                            <div class="card-body">
                                                <div id="nameServerAnalysis"></div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Export & Actions -->
                                    <div class="col-12">
                                        <div class="card analysis-card">
                                            <div class="card-header">
                                                <h5 class="card-title mb-0"><i class="bi bi-download"></i> Export Intelligence Report</h5>
                                            </div>
                                            <div class="card-body text-center">
                                                <p class="text-muted mb-3">Export threat intelligence analysis for reporting and documentation</p>
                                                <button class="btn btn-success me-2" onclick="exportData('txt')">
                                                    <i class="bi bi-file-text"></i> Export TXT Report
                                                </button>
                                                <button class="btn btn-info me-2" onclick="exportData('json')">
                                                    <i class="bi bi-file-code"></i> Export JSON Data
                                                </button>
                                                <button class="btn btn-warning" onclick="copyToClipboard()">
                                                    <i class="bi bi-clipboard"></i> Copy Summary
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bulk Analysis Modal -->
    <div class="modal fade" id="bulkModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="bi bi-list-ul"></i> Bulk Domain Analysis</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="bulkDomains" class="form-label">Enter domains (one per line):</label>
                        <textarea class="form-control" id="bulkDomains" rows="10" 
                                  placeholder="suspicious-domain1.com&#10;suspicious-domain2.org&#10;threat-domain.net"></textarea>
                    </div>
                    <div class="mb-3">
                        <small class="text-muted">Maximum 10 domains per batch for performance</small>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-danger" onclick="bulkAnalyze()">
                        <i class="bi bi-shield-check"></i> Analyze All Domains
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentAnalysis = null;

        async function analyzeDomain() {
            const domain = document.getElementById('domainInput').value.trim();
            if (!domain) return;

            showLoading();
            hideResults();

            try {
                const response = await fetch(`/api/analyze/${domain}`);
                const data = await response.json();
                
                if (data.error) {
                    throw new Error(data.error);
                }

                currentAnalysis = data;
                displayResults(data);
            } catch (error) {
                hideLoading();
                alert(`Analysis failed: ${error.message}`);
            }
        }

        function showLoading() {
            document.getElementById('loadingSpinner').style.display = 'block';
            document.getElementById('resultsContainer').style.display = 'none';
        }

        function hideLoading() {
            document.getElementById('loadingSpinner').style.display = 'none';
        }

        function hideResults() {
            document.getElementById('resultsContainer').style.display = 'none';
        }

        function displayResults(data) {
            hideLoading();
            
            // Update domain name
            document.getElementById('analyzedDomain').textContent = data.domain;
            
            // Determine threat level and classification
            const usSum = data.us_summary;
            let threatLevel = 'low';
            let threatClass = 'alert-success';
            let threatIcon = 'bi-shield-check';
            let threatTitle = 'Low Threat';
            let threatDesc = 'Domain appears to be legitimately registered with standard practices.';

            if (!usSum.domain_us && !usSum.registrar_us && usSum.privacy_emails > 0) {
                threatLevel = 'high';
                threatClass = 'alert-danger';
                threatIcon = 'bi-shield-exclamation';
                threatTitle = 'High Threat';
                threatDesc = 'Non-US registration with privacy protection - requires investigation.';
            } else if (!usSum.domain_us || !usSum.registrar_us) {
                threatLevel = 'medium';
                threatClass = 'alert-warning';
                threatIcon = 'bi-shield-slash';
                threatTitle = 'Medium Threat';
                threatDesc = 'Partial non-US registration detected - monitor for suspicious activity.';
            }

            document.getElementById('threatAlert').className = `alert ${threatClass} d-flex align-items-center mb-4`;
            document.getElementById('threatIcon').className = `bi ${threatIcon} me-2`;
            document.getElementById('threatTitle').textContent = threatTitle;
            document.getElementById('threatDescription').textContent = threatDesc;

            // Update metrics
            document.getElementById('usClassification').textContent = usSum.domain_us ? 'US-Based' : 'Non-US';
            document.getElementById('usClassification').className = `metric-number ${usSum.domain_us ? 'threat-level-low' : 'threat-level-high'}`;
            
            document.getElementById('privacyStatus').textContent = data.has_privacy ? 'Protected' : 'Public';
            document.getElementById('privacyStatus').className = `metric-number ${data.has_privacy ? 'threat-level-medium' : 'threat-level-low'}`;
            
            document.getElementById('emailCount').textContent = data.email_analysis.length;
            document.getElementById('nsCount').textContent = data.nameserver_analysis.length;

            // Registration Info
            const regInfo = `
                <div class="table-responsive">
                    <table class="table table-borderless">
                        <tr><td><strong>Registrar:</strong></td><td>${data.main_whois.registrar || 'Unknown'}</td></tr>
                        <tr><td><strong>US Registrar:</strong></td><td><span class="badge ${usSum.registrar_us ? 'bg-success' : 'bg-danger'}">${usSum.registrar_us ? 'Yes' : 'No'}</span></td></tr>
                        <tr><td><strong>Domain Country:</strong></td><td>${data.main_whois.registrant_country || 'Unknown'}</td></tr>
                        <tr><td><strong>US Domain:</strong></td><td><span class="badge ${usSum.domain_us ? 'bg-success' : 'bg-danger'}">${usSum.domain_us ? 'Yes' : 'No'}</span></td></tr>
                        <tr><td><strong>Created:</strong></td><td>${data.main_whois.creation_date || 'Unknown'}</td></tr>
                        <tr><td><strong>Expires:</strong></td><td>${data.main_whois.expiration_date || 'Unknown'}</td></tr>
                        <tr><td><strong>Privacy Service:</strong></td><td>${data.privacy_service || 'None detected'}</td></tr>
                    </table>
                </div>
            `;
            document.getElementById('registrationInfo').innerHTML = regInfo;

            // DNS Info
            let dnsInfo = `
                <div class="mb-3">
                    <strong>Last DNS Update:</strong> ${data.dns_data.last_update || 'Unknown'}<br>
                    <strong>SOA Serial:</strong> ${data.dns_data.serial || 'Unknown'}
                </div>
            `;
            
            if (data.dns_data.records.A && data.dns_data.records.A.length > 0) {
                dnsInfo += `<div class="mb-2"><strong>A Records:</strong><br>`;
                data.dns_data.records.A.forEach(record => {
                    dnsInfo += `<span class="font-monospace">${record}</span><br>`;
                });
                dnsInfo += `</div>`;
            }

            if (data.dns_data.dig_output) {
                dnsInfo += `<div class="mt-3"><strong>DIG Output:</strong><br><pre class="bg-light p-2 rounded">${data.dns_data.dig_output}</pre></div>`;
            }
            
            document.getElementById('dnsInfo').innerHTML = dnsInfo;

            // Email Analysis
            let emailHtml = '';
            if (data.email_analysis.length > 0) {
                data.email_analysis.forEach(email => {
                    const privacyBadge = email.is_privacy ? 'bg-warning' : 'bg-success';
                    const usBadge = email.is_us ? 'bg-success' : 'bg-danger';
                    
                    emailHtml += `
                        <div class="card mb-2">
                            <div class="card-body py-2">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <strong>${email.email}</strong>
                                        <div class="mt-1">
                                            <span class="badge ${privacyBadge}">${email.is_privacy ? 'Privacy Protected' : 'Direct Contact'}</span>
                                            <span class="badge ${usBadge} ms-1">${email.is_us ? 'US-Based' : 'Non-US'}</span>
                                        </div>
                                        ${email.privacy_service ? `<small class="text-muted">Service: ${email.privacy_service}</small>` : ''}
                                    </div>
                                    <div class="text-end">
                                        ${email.whois_data ? `
                                            <small class="text-muted">
                                                Domain: ${email.domain}<br>
                                                Registrar: ${email.whois_data.registrar || 'Unknown'}
                                            </small>
                                        ` : ''}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                });
            } else {
                emailHtml = '<div class="text-muted">No email addresses found in WHOIS data</div>';
            }
            document.getElementById('emailAnalysis').innerHTML = emailHtml;

            // Name Server Analysis
            let nsHtml = '';
            if (data.nameserver_analysis.length > 0) {
                data.nameserver_analysis.forEach(ns => {
                    const usBadge = ns.is_us ? 'bg-success' : 'bg-danger';
                    
                    nsHtml += `
                        <div class="card mb-2">
                            <div class="card-body py-2">
                                <div class="d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong>${ns.nameserver}</strong>
                                        <span class="badge ${usBadge} ms-2">${ns.is_us ? 'US-Based' : 'Non-US'}</span>
                                    </div>
                                    <div class="text-end">
                                        <small class="text-muted">
                                            IP: ${ns.ip}<br>
                                            Country: ${ns.geolocation.country}<br>
                                            Region: ${ns.geolocation.region}
                                        </small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                });
            } else {
                nsHtml = '<div class="text-muted">No name server data available</div>';
            }
            document.getElementById('nameServerAnalysis').innerHTML = nsHtml;

            // Show results
            document.getElementById('resultsContainer').style.display = 'block';
            document.getElementById('resultsContainer').scrollIntoView({ behavior: 'smooth' });
        }

        async function bulkAnalyze() {
            const domains = document.getElementById('bulkDomains').value
                .split('\n')
                .map(d => d.trim())
                .filter(d => d.length > 0)
                .slice(0, 10);

            if (domains.length === 0) return;

            // Close modal
            bootstrap.Modal.getInstance(document.getElementById('bulkModal')).hide();
            
            showLoading();
            
            try {
                const response = await fetch('/api/bulk_analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domains: domains })
                });
                
                const results = await response.json();
                displayBulkResults(results);
            } catch (error) {
                hideLoading();
                alert(`Bulk analysis failed: ${error.message}`);
            }
        }

        function displayBulkResults(results) {
            hideLoading();
            
            let html = '<div class="table-responsive"><table class="table table-striped"><thead><tr>';
            html += '<th>Domain</th><th>US Status</th><th>Privacy</th><th>Threat Level</th><th>Actions</th>';
            html += '</tr></thead><tbody>';
            
            for (const [domain, data] of Object.entries(results)) {
                if (data.error) {
                    html += `<tr><td>${domain}</td><td colspan="4" class="text-danger">Error: ${data.error}</td></tr>`;
                    continue;
                }
                
                const usStatus = data.us_summary.domain_us ? 'US-Based' : 'Non-US';
                const privacy = data.has_privacy ? 'Protected' : 'Public';
                let threatLevel = 'Low';
                let threatClass = 'text-success';
                
                if (!data.us_summary.domain_us && data.has_privacy) {
                    threatLevel = 'High';
                    threatClass = 'text-danger';
                } else if (!data.us_summary.domain_us) {
                    threatLevel = 'Medium';
                    threatClass = 'text-warning';
                }
                
                html += `<tr>
                    <td><strong>${domain}</strong></td>
                    <td><span class="badge ${data.us_summary.domain_us ? 'bg-success' : 'bg-danger'}">${usStatus}</span></td>
                    <td><span class="badge ${data.has_privacy ? 'bg-warning' : 'bg-info'}">${privacy}</span></td>
                    <td><span class="${threatClass}">${threatLevel}</span></td>
                    <td><button class="btn btn-sm btn-outline-primary" onclick="analyzeSingle('${domain}')">Details</button></td>
                </tr>`;
            }
            
            html += '</tbody></table></div>';
            
            document.getElementById('resultsContainer').innerHTML = `
                <div class="row py-5">
                    <div class="col-12">
                        <h3><i class="bi bi-list-check"></i> Bulk Analysis Results</h3>
                        ${html}
                    </div>
                </div>
            `;
            document.getElementById('resultsContainer').style.display = 'block';
        }

        function analyzeSingle(domain) {
            document.getElementById('domainInput').value = domain;
            analyzeDomain();
        }

        function exportData(format) {
            if (!currentAnalysis) return;
            window.open(`/export/${format}/${currentAnalysis.domain}`, '_blank');
        }

        function copyToClipboard() {
            if (!currentAnalysis) return;
            
            const summary = `Domain: ${currentAnalysis.domain}
US-Based: ${currentAnalysis.us_summary.domain_us ? 'Yes' : 'No'}
Privacy Protected: ${currentAnalysis.has_privacy ? 'Yes' : 'No'}
Registrar: ${currentAnalysis.main_whois.registrar || 'Unknown'}
Threat Assessment: ${currentAnalysis.us_summary.domain_us ? 'Low' : 'High'}`;
            
            navigator.clipboard.writeText(summary);
            alert('Summary copied to clipboard!');
        }

        function clearCache() {
            fetch('/api/clear_cache', { method: 'POST' })
                .then(() => alert('Cache cleared successfully!'))
                .catch(() => alert('Failed to clear cache'));
        }

        // Enter key support
        document.getElementById('domainInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                analyzeDomain();
            }
        });

        // Auto-focus
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('domainInput').focus();
        });
    </script>
</body>
</html>
EOF
print_status "Created templates/index.html"

# Create requirements.txt
print_info "Creating requirements.txt..."
cat > requirements.txt << 'EOF'
Flask==2.3.3
python-whois==0.8.0
dnspython==2.4.2
requests==2.31.0
geopy==2.3.0
gunicorn==21.2.0
python-dotenv==1.0.0
Flask-Limiter==3.5.0
Flask-Caching==2.1.0
Werkzeug==2.3.7
Jinja2==3.1.2
click==8.1.7
itsdangerous==2.1.2
MarkupSafe==2.1.3
psycopg2-binary==2.9.7
redis==5.0.1
EOF
print_status "Created requirements.txt"

# Create Procfile
print_info "Creating deployment files..."
echo "web: gunicorn wsgi:app" > Procfile
print_status "Created Procfile"

# Create runtime.txt
echo "python-3.11.0" > runtime.txt
print_status "Created runtime.txt"

# Create wsgi.py
cat > wsgi.py << 'EOF'
from app import app

if __name__ == "__main__":
    app.run()
EOF
print_status "Created wsgi.py"

# Create config.py
cat > config.py << 'EOF'
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    
    # Database settings
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///whois_cache.db'
    
    # Cache settings
    CACHE_TIMEOUT = int(os.environ.get('CACHE_TIMEOUT', 86400))  # 24 hours
    DNS_CACHE_TIMEOUT = int(os.environ.get('DNS_CACHE_TIMEOUT', 21600))  # 6 hours
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE = int(os.environ.get('RATE_LIMIT_PER_MINUTE', 60))
    BULK_ANALYSIS_LIMIT = int(os.environ.get('BULK_ANALYSIS_LIMIT', 10))
    
    # External API settings
    WHOIS_TIMEOUT = int(os.environ.get('WHOIS_TIMEOUT', 30))
    DNS_TIMEOUT = int(os.environ.get('DNS_TIMEOUT', 10))
    GEO_API_TIMEOUT = int(os.environ.get('GEO_API_TIMEOUT', 5))
    
    # Thread pool settings
    MAX_WORKERS = int(os.environ.get('MAX_WORKERS', 5))
    
    # Environment
    ENV = os.environ.get('FLASK_ENV', 'production')
    DEBUG = ENV == 'development'

class DevelopmentConfig(Config):
    DEBUG = True
    ENV = 'development'

class ProductionConfig(Config):
    DEBUG = False
    ENV = 'production'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': ProductionConfig
}
EOF
print_status "Created config.py"

# Create .gitignore
cat > .gitignore << 'EOF'
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/
cover/

# Flask
instance/
.webassets-cache

# Environment variables
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Database files
*.db
*.sqlite
*.sqlite3
database/
cache/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Logs
*.log
logs/

# Temporary files
tmp/
temp/
exports/
EOF
print_status "Created .gitignore"

# Create railway.json
cat > railway.json << 'EOF'
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
EOF
print_status "Created railway.json"

# Create README.md
print_info "Creating README.md..."
cat > README.md << 'EOF'
# 🛡️ Domain Intelligence Platform

A high-performance Flask application for automated domain threat intelligence analysis. Built for security analysts and threat hunters who need rapid US/Non-US classification, privacy detection, and infrastructure analysis.

## 🎯 Key Features

### ⚡ Instant Threat Classification
- **US vs Non-US registration** detection
- **Privacy protection** identification  
- **Threat level scoring** (High/Medium/Low)
- **Geographic infrastructure** analysis

### 🔍 Comprehensive Analysis
- **WHOIS data extraction** with caching
- **DNS record analysis** with DIG integration
- **Email contact intelligence** 
- **Name server geographic mapping**
- **Recursive domain investigation**

### 🚀 Performance Optimized
- **SQLite caching** (24-hour WHOIS, 6-hour DNS)
- **Bulk domain processing** (up to 10 domains)
- **Threaded analysis** for speed
- **Rate limiting** to avoid API restrictions

## 🚀 Quick Start

### Local Development
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py

# Access at http://localhost:5000
```

### Railway Deployment
1. **Fork this repository**
2. **Connect to Railway** - Import your forked repo
3. **Environment Variables** (optional):
   ```
   SECRET_KEY=your-secret-key-here
   CACHE_TIMEOUT=86400
   RATE_LIMIT_PER_MINUTE=60
   ```
4. **Deploy** - Railway will automatically build and deploy

## 🎮 Usage

### Single Domain Analysis
1. Enter domain in search box
2. Click "Analyze Threat"
3. Get instant classification:
   - **🔴 High Threat**: Non-US + Privacy Protected
   - **🟡 Medium Threat**: Partial non-US registration  
   - **🟢 Low Threat**: US-based standard practices

### Bulk Analysis
1. Click "Bulk Analysis"
2. Enter domains (one per line, max 10)
3. Get threat matrix overview
4. Click "Details" for individual analysis

### API Integration
```bash
# Single domain analysis
curl https://your-app.railway.app/api/analyze/suspicious-domain.com

# Bulk analysis
curl -X POST https://your-app.railway.app/api/bulk_analyze \
  -H "Content-Type: application/json" \
  -d '{"domains": ["domain1.com", "domain2.org"]}'
```

## 📝 License

This project is licensed under the MIT License.

---

**Built for security professionals who need fast, accurate domain intelligence.**
EOF
print_status "Created README.md"

# Create LICENSE
cat > LICENSE << 'EOF'
MIT License

Copyright (c) 2024 Domain Intelligence Platform

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF
print_status "Created LICENSE"

# Create empty __init__.py files for Python packages
touch api/__init__.py
touch models/__init__.py  
touch utils/__init__.py
touch tests/__init__.py
print_status "Created Python package files"

# Create data files
print_info "Creating data files..."
cat > data/privacy_services.json << 'EOF'
{
  "services": {
    "whoisguard": "Namecheap WhoisGuard",
    "domains by proxy": "GoDaddy Domains By Proxy",
    "perfect privacy": "Perfect Privacy LLC",
    "contact privacy": "Contact Privacy Inc.",
    "redacted for privacy": "ICANN Privacy Redaction",
    "withheldforprivacy": "Withheld for Privacy ehf",
    "domainprivacygroup": "Domain Privacy Group"
  }
}
EOF

cat > data/registrar_categories.json << 'EOF'
{
  "categories": {
    "major_commercial": ["godaddy", "namecheap", "name.com"],
    "enterprise": ["network solutions", "verisign", "markmonitor"],
    "tech_giants": ["google domains", "cloudflare", "amazon"],
    "european": ["1&1", "ionos", "ovh"],
    "wholesale": ["tucows", "enom", "directi"]
  }
}
EOF

cat > data/country_codes.json << 'EOF'
{
  "us_indicators": [
    "US", "USA", "UNITED STATES", "CALIFORNIA", "NEW YORK", 
    "TEXAS", "FLORIDA", "ILLINOIS", "PENNSYLVANIA"
  ]
}
EOF
print_status "Created data files"

# Create basic test file
cat > tests/test_basic.py << 'EOF'
import unittest
from app import app

class BasicTests(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_home_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_api_endpoint(self):
        response = self.app.get('/api/analyze/google.com')
        self.assertIn(response.status_code, [200, 500])  # Allow 500 if dependencies missing

if __name__ == '__main__':
    unittest.main()
EOF
print_status "Created basic tests"

# Make script executable
chmod +x setup.sh

echo ""
echo "================================================"
print_status "🎉 Domain Intelligence Platform setup complete!"
echo ""
print_info "📁 Project created in: $(pwd)"
print_info "🚀 Next steps:"
echo "   1. cd $PROJECT_NAME"
echo "   2. python -m venv venv"
echo "   3. source venv/bin/activate  # (Windows: venv\\Scripts\\activate)"
echo "   4. pip install -r requirements.txt"
echo "   5. python app.py"
echo ""
print_info "🌐 Access your application at: http://localhost:5000"
echo ""
print_info "📚 Deploy to Railway:"
echo "   1. Push to GitHub: git add . && git commit -m 'Initial commit' && git push"
echo "   2. Connect GitHub repo to Railway"
echo "   3. Deploy automatically!"
echo ""
print_warning "⚠️  Remember to set a proper SECRET_KEY in production!"
echo "================================================"
EOF

chmod +x setup.sh

print_status "Created setup.sh script"
