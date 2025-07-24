import json
import os
from flask import render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import app, db
from models import User, ScanHistory, PhishingReport
from utils.detection import analyze_url, analyze_email, analyze_html_file
from utils.ml_model import load_model, predict_phishing

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User()
        user.username = username
        user.email = email
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent scans
    recent_scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).limit(5).all()
    
    # Get scan statistics
    total_scans = ScanHistory.query.filter_by(user_id=current_user.id).count()
    phishing_detected = ScanHistory.query.filter_by(user_id=current_user.id, result='phishing').count()
    safe_scans = ScanHistory.query.filter_by(user_id=current_user.id, result='safe').count()
    
    stats = {
        'total_scans': total_scans,
        'phishing_detected': phishing_detected,
        'safe_scans': safe_scans,
        'suspicious_scans': total_scans - phishing_detected - safe_scans
    }
    
    return render_template('dashboard.html', recent_scans=recent_scans, stats=stats)

@app.route('/scan-url', methods=['GET', 'POST'])
@login_required
def scan_url():
    if request.method == 'POST':
        url = request.form['url'].strip()
        
        if not url:
            flash('Please enter a URL to scan', 'error')
            return render_template('scan_url.html')
        
        # Analyze the URL
        result = analyze_url(url)
        
        # Save scan history
        scan = ScanHistory()
        scan.user_id = current_user.id
        scan.scan_type = 'url'
        scan.content = url
        scan.result = result['result']
        scan.confidence_score = result['confidence']
        scan.detection_method = result['method']
        scan.details = json.dumps(result['details'])
        db.session.add(scan)
        db.session.commit()
        
        return render_template('scan_url.html', result=result, url=url)
    
    return render_template('scan_url.html')

@app.route('/scan-email', methods=['GET', 'POST'])
@login_required
def scan_email():
    if request.method == 'POST':
        email_content = request.form['email_content'].strip()
        
        if not email_content:
            flash('Please enter email content to scan', 'error')
            return render_template('scan_email.html')
        
        # Analyze the email
        result = analyze_email(email_content)
        
        # Save scan history
        scan = ScanHistory()
        scan.user_id = current_user.id
        scan.scan_type = 'email'
        scan.content = email_content[:1000]  # Truncate for storage
        scan.result = result['result']
        scan.confidence_score = result['confidence']
        scan.detection_method = result['method']
        scan.details = json.dumps(result['details'])
        db.session.add(scan)
        db.session.commit()
        
        return render_template('scan_email.html', result=result)
    
    return render_template('scan_email.html')

@app.route('/scan-html', methods=['GET', 'POST'])
@login_required
def scan_html():
    if request.method == 'POST':
        if 'html_file' not in request.files:
            flash('No file selected', 'error')
            return render_template('scan_html.html')
        
        file = request.files['html_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return render_template('scan_html.html')
        
        if file and file.filename and file.filename.lower().endswith(('.html', '.htm')):
            filename = secure_filename(file.filename)
            
            # Read file content
            html_content = file.read().decode('utf-8', errors='ignore')
            
            # Analyze the HTML
            result = analyze_html_file(html_content, filename)
            
            # Save scan history
            scan = ScanHistory()
            scan.user_id = current_user.id
            scan.scan_type = 'html'
            scan.content = f"File: {filename}"
            scan.result = result['result']
            scan.confidence_score = result['confidence']
            scan.detection_method = result['method']
            scan.details = json.dumps(result['details'])
            db.session.add(scan)
            db.session.commit()
            
            return render_template('scan_html.html', result=result, filename=filename)
        else:
            flash('Please upload a valid HTML file', 'error')
    
    return render_template('scan_html.html')

@app.route('/scan-history')
@login_required
def scan_history():
    page = request.args.get('page', 1, type=int)
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template('scan_history.html', scans=scans)

@app.route('/education')
def education():
    return render_template('education.html')

@app.route('/profile')
@login_required
def profile():
    user_reports = PhishingReport.query.filter_by(user_id=current_user.id).order_by(PhishingReport.created_at.desc()).all()
    return render_template('profile.html', reports=user_reports)

@app.route('/report-phishing', methods=['POST'])
@login_required
def report_phishing():
    url = request.form['url'].strip()
    description = request.form.get('description', '').strip()
    
    if not url:
        flash('URL is required', 'error')
        return redirect(url_for('profile'))
    
    # Create new report
    report = PhishingReport()
    report.user_id = current_user.id
    report.url = url
    report.description = description
    db.session.add(report)
    db.session.commit()
    
    flash('Thank you for reporting! We will investigate this URL.', 'success')
    return redirect(url_for('profile'))

@app.route('/api/scan-url', methods=['POST'])
@login_required
def api_scan_url():
    """API endpoint for browser extension"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Analyze the URL
    result = analyze_url(url)
    
    # Save scan history
    scan = ScanHistory()
    scan.user_id = current_user.id
    scan.scan_type = 'url'
    scan.content = url
    scan.result = result['result']
    scan.confidence_score = result['confidence']
    scan.detection_method = result['method']
    scan.details = json.dumps(result['details'])
    db.session.add(scan)
    db.session.commit()
    
    return jsonify(result)

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
