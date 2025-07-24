# PhishGuard - Phishing Detection System

## Overview

PhishGuard is a comprehensive web-based phishing detection system built with Flask that provides real-time analysis of URLs, emails, and HTML files. The application combines machine learning models with rule-based detection and blacklist/whitelist checking to identify potential phishing attempts. It features user authentication, scan history tracking, educational resources, and a browser extension for enhanced protection.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Architecture
- **Framework**: Flask with SQLAlchemy ORM
- **Database**: SQLite (configurable via DATABASE_URL environment variable for other databases)
- **Authentication**: Flask-Login for session management
- **Security**: Werkzeug password hashing, CSRF protection via secret keys
- **Deployment**: WSGI with ProxyFix middleware for production deployment

### Frontend Architecture
- **Template Engine**: Jinja2 with Flask
- **CSS Framework**: Bootstrap 5 with dark theme
- **Icons**: Font Awesome 6.4.0
- **JavaScript**: Vanilla JS with progressive enhancement
- **Responsive Design**: Mobile-first approach with Bootstrap grid system

### Browser Extension
- **Manifest**: Chrome Extension Manifest V3
- **Components**: Background service worker, content scripts, popup interface
- **Real-time Protection**: Automatic page scanning and warning notifications

## Key Components

### Database Models
1. **User Model**: Handles user authentication with username, email, password hash, and timestamps
2. **ScanHistory Model**: Stores scan results with type (url/email/html), content, result classification, confidence scores, and detection methods
3. **PhishingReport Model**: User-submitted reports for suspicious content with status tracking

### Detection Engine
1. **Feature Extraction**: Analyzes URLs, emails, and HTML content for suspicious patterns
2. **Rule-based Detection**: Applies heuristic rules for common phishing indicators
3. **Machine Learning**: RandomForest classifier for advanced pattern recognition
4. **Blacklist/Whitelist**: Domain reputation checking against known safe/malicious sites

### Core Modules
- **Routes**: Flask endpoints for all user interactions and API endpoints
- **Models**: SQLAlchemy database models with relationships and validation
- **Utils**: Detection logic, feature extraction, ML model handling, and security utilities
- **Templates**: Responsive HTML templates with consistent UI/UX
- **Static Assets**: CSS, JavaScript, and image resources

## Data Flow

1. **User Registration/Login**: Users create accounts or authenticate via Flask-Login
2. **Content Submission**: Users submit URLs, email content, or HTML files for analysis
3. **Feature Extraction**: System extracts relevant features from submitted content
4. **Multi-layered Analysis**: 
   - Whitelist check (immediate safe classification)
   - Blacklist check (immediate phishing classification)
   - Rule-based analysis (heuristic pattern matching)
   - ML model prediction (advanced classification)
5. **Result Generation**: Combined confidence score and classification returned to user
6. **History Storage**: Scan results stored in database for user history and analytics
7. **Educational Feedback**: Results include educational information about detected threats

## External Dependencies

### Python Packages
- Flask and Flask-SQLAlchemy for web framework and ORM
- Flask-Login for authentication management
- Werkzeug for security utilities and password hashing
- scikit-learn for machine learning models
- BeautifulSoup for HTML parsing
- tldextract for domain analysis
- whois for domain information lookup

### Frontend Dependencies
- Bootstrap 5 CSS framework from CDN
- Font Awesome icons from CDN
- Custom CSS and JavaScript for enhanced functionality

### Browser Extension Dependencies
- Chrome Extension APIs for tab management and notifications
- Web accessible resources for cross-origin requests

## Deployment Strategy

### Development Environment
- SQLite database for local development
- Flask development server with debug mode
- Environment variables for configuration
- Hot reloading for rapid development

### Production Considerations
- Database URL configuration for PostgreSQL or other production databases
- WSGI deployment with ProxyFix for reverse proxy compatibility
- Session secret management via environment variables
- Connection pooling and database optimization settings
- Static file serving optimization

### Security Features
- Password hashing with Werkzeug
- Session management with Flask-Login
- CSRF protection via Flask secret keys
- Input validation and sanitization
- Secure file upload handling
- Rate limiting considerations for API endpoints

### Browser Extension Deployment
- Chrome Web Store deployment process
- Manifest V3 compliance for modern browsers
- Permission management for security
- Content Security Policy implementation

The system is designed to be scalable, maintainable, and secure while providing an intuitive user experience for phishing detection and education.