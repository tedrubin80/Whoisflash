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

### 📊 Export & Integration
- **TXT/JSON reports** for documentation
- **RESTful API** for SIEM integration
- **Bulk analysis** for investigation lists
- **Copy-to-clipboard** quick summaries

## 🚀 Quick Start

### Local Development
```bash
# Clone the repository
git clone https://github.com/yourusername/domain-intelligence-platform.git
cd domain-intelligence-platform

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
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/your-template-id)

1. **Fork this repository**
2. **Connect to Railway** - Import your forked repo
3. **Environment Variables** (optional):
   ```
   SECRET_KEY=your-secret-key-here
   CACHE_TIMEOUT=86400
   RATE_LIMIT_PER_MINUTE=60
   ```
4. **Deploy** - Railway will automatically build and deploy

### Manual Railway Setup
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Deploy from local directory
railway up
```

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

## 📁 Project Structure

```
domain-intelligence-platform/
├── app.py                  # Main Flask application
├── requirements.txt        # Dependencies
├── Procfile               # Railway deployment
├── wsgi.py                # WSGI entry point
├── config.py              # Configuration
├── templates/             # HTML templates
├── static/                # CSS/JS/Images
├── api/                   # Analysis modules
├── models/                # Data models
├── utils/                 # Utility functions
├── tests/                 # Test suite
└── docs/                  # Documentation
```

## 🔧 Configuration

### Environment Variables
```bash
# Security
SECRET_KEY=your-secret-key

# Cache settings
CACHE_TIMEOUT=86400        # WHOIS cache (24 hours)
DNS_CACHE_TIMEOUT=21600    # DNS cache (6 hours)

# Rate limiting
RATE_LIMIT_PER_MINUTE=60   # API rate limit
BULK_ANALYSIS_LIMIT=10     # Max bulk domains

# Timeouts
WHOIS_TIMEOUT=30           # WHOIS lookup timeout
DNS_TIMEOUT=10             # DNS query timeout
GEO_API_TIMEOUT=5          # Geolocation API timeout

# Performance
MAX_WORKERS=5              # Thread pool size
```

### Database Configuration
- **Development**: SQLite (automatic)
- **Production**: PostgreSQL (Railway managed)
- **Caching**: Redis (optional, falls back to in-memory)

## 🛡️ Security Features

### Rate Limiting
- **60 requests/minute** per IP by default
- **Bulk analysis** limited to 10 domains
- **Cache-based** duplicate prevention

### Data Protection
- **No persistent storage** of analyzed domains
- **Temporary cache only** for performance
- **No logging** of sensitive data
- **HTTPS enforced** in production

## 📊 API Documentation

### GET /api/analyze/{domain}
Analyze a single domain for threat intelligence.

**Response:**
```json
{
  "domain": "example.com",
  "analysis_time": 2.34,
  "is_domain_us": true,
  "is_registrar_us": true,
  "has_privacy": false,
  "us_summary": {
    "domain_us": true,
    "registrar_us": true,
    "privacy_emails": 0,
    "us_emails": 2,
    "us_nameservers": 4
  },
  "email_analysis": [...],
  "nameserver_analysis": [...]
}
```

### POST /api/bulk_analyze
Analyze multiple domains simultaneously.

**Request:**
```json
{
  "domains": ["domain1.com", "domain2.org", "domain3.net"]
}
```

### GET /export/{format}/{domain}
Export analysis results (`txt` or `json` format).

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/

# Run specific test category
python -m pytest tests/test_whois.py
python -m pytest tests/test_api.py

# Coverage report
python -m pytest --cov=. tests/
```

## 🚀 Deployment Options

### Railway (Recommended)
- **Automatic deployments** from GitHub
- **Managed PostgreSQL** database
- **Built-in monitoring** and logs
- **Custom domains** and SSL

### Heroku
- Standard `Procfile` included
- Add PostgreSQL addon
- Configure environment variables

### DigitalOcean App Platform
- Use `requirements.txt` for dependencies
- Configure build/run commands
- Add managed database

### Docker
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "wsgi:app"]
```

## 🤝 Contributing

1. **Fork** the repository
2. **Create** feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** changes: `git commit -m 'Add amazing feature'`
4. **Push** to branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **GitHub Issues**: Bug reports and feature requests
- **Documentation**: See `/docs` folder
- **API Help**: Check `/docs/API.md`

## 🔗 Links

- **Live Demo**: https://your-app.railway.app
- **GitHub**: https://github.com/yourusername/domain-intelligence-platform
- **Documentation**: https://your-app.railway.app/docs

---

**Built for security professionals who need fast, accurate domain intelligence.**