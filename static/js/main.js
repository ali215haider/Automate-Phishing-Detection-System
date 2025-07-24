// Main JavaScript file for PhishGuard

// Global application object
const PhishGuard = {
    init: function() {
        this.bindEvents();
        this.initTooltips();
        this.initCounters();
        this.checkBrowserSupport();
    },

    bindEvents: function() {
        // Form validation
        document.addEventListener('DOMContentLoaded', function() {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', PhishGuard.handleFormSubmit);
            });
        });

        // Auto-dismiss alerts
        this.autoDismissAlerts();
        
        // Smooth scrolling for anchor links
        this.initSmoothScrolling();
        
        // Copy to clipboard functionality
        this.initCopyToClipboard();
        
        // Real-time form validation
        this.initFormValidation();
    },

    handleFormSubmit: function(event) {
        const form = event.target;
        const submitBtn = form.querySelector('button[type="submit"]');
        
        if (submitBtn && !submitBtn.disabled) {
            // Add loading state
            const originalHTML = submitBtn.innerHTML;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
            submitBtn.disabled = true;
            
            // Re-enable button after 30 seconds (fallback)
            setTimeout(() => {
                if (submitBtn.disabled) {
                    submitBtn.innerHTML = originalHTML;
                    submitBtn.disabled = false;
                }
            }, 30000);
        }
    },

    initTooltips: function() {
        // Initialize Bootstrap tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function(tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    },

    initCounters: function() {
        // Animate counters on the dashboard
        const counters = document.querySelectorAll('.counter');
        counters.forEach(counter => {
            const target = parseInt(counter.getAttribute('data-target') || counter.textContent);
            let current = 0;
            const increment = target / 50;
            
            const updateCounter = () => {
                if (current < target) {
                    current += increment;
                    counter.textContent = Math.ceil(current);
                    requestAnimationFrame(updateCounter);
                } else {
                    counter.textContent = target;
                }
            };
            
            // Start animation when element is in viewport
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        updateCounter();
                        observer.unobserve(entry.target);
                    }
                });
            });
            
            observer.observe(counter);
        });
    },

    autoDismissAlerts: function() {
        // Auto-dismiss success and info alerts after 5 seconds
        const alerts = document.querySelectorAll('.alert-success, .alert-info');
        alerts.forEach(alert => {
            if (!alert.querySelector('.btn-close')) return;
            
            setTimeout(() => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        });
    },

    initSmoothScrolling: function() {
        // Smooth scrolling for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    },

    initCopyToClipboard: function() {
        // Add copy functionality to code elements
        document.querySelectorAll('code').forEach(codeBlock => {
            if (codeBlock.textContent.length > 20) {
                codeBlock.style.cursor = 'pointer';
                codeBlock.title = 'Click to copy';
                
                codeBlock.addEventListener('click', function() {
                    navigator.clipboard.writeText(this.textContent).then(() => {
                        PhishGuard.showToast('Copied to clipboard!', 'success');
                    }).catch(() => {
                        PhishGuard.showToast('Failed to copy', 'error');
                    });
                });
            }
        });
    },

    initFormValidation: function() {
        // Real-time validation for common form fields
        const urlInputs = document.querySelectorAll('input[type="url"]');
        urlInputs.forEach(input => {
            input.addEventListener('input', function() {
                this.setCustomValidity('');
                if (this.value && !PhishGuard.isValidURL(this.value)) {
                    this.setCustomValidity('Please enter a valid URL');
                }
            });
        });

        const emailInputs = document.querySelectorAll('input[type="email"]');
        emailInputs.forEach(input => {
            input.addEventListener('input', function() {
                this.setCustomValidity('');
                if (this.value && !PhishGuard.isValidEmail(this.value)) {
                    this.setCustomValidity('Please enter a valid email address');
                }
            });
        });
    },

    isValidURL: function(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    },

    isValidEmail: function(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    showToast: function(message, type = 'info') {
        // Create and show a toast notification
        const toastContainer = document.getElementById('toast-container') || this.createToastContainer();
        
        const toastHTML = `
            <div class="toast align-items-center text-white bg-${type === 'error' ? 'danger' : type} border-0" role="alert">
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'} me-2"></i>
                        ${message}
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            </div>
        `;
        
        toastContainer.insertAdjacentHTML('beforeend', toastHTML);
        const toastElement = toastContainer.lastElementChild;
        const toast = new bootstrap.Toast(toastElement);
        toast.show();
        
        // Remove element after it's hidden
        toastElement.addEventListener('hidden.bs.toast', () => {
            toastElement.remove();
        });
    },

    createToastContainer: function() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        container.style.zIndex = '1055';
        document.body.appendChild(container);
        return container;
    },

    checkBrowserSupport: function() {
        // Check for required browser features
        const requiredFeatures = [
            'fetch',
            'IntersectionObserver',
            'URL',
            'Promise'
        ];
        
        const unsupported = requiredFeatures.filter(feature => !(feature in window));
        
        if (unsupported.length > 0) {
            console.warn('Some features may not work properly. Unsupported:', unsupported);
            this.showToast('Your browser may not support all features. Please consider updating.', 'warning');
        }
    },

    // URL Analysis utilities
    analyzeURL: function(url) {
        const analysis = {
            protocol: '',
            domain: '',
            subdomain: '',
            path: '',
            query: '',
            length: url.length,
            suspicious: false
        };

        try {
            const urlObj = new URL(url);
            analysis.protocol = urlObj.protocol;
            analysis.domain = urlObj.hostname;
            analysis.path = urlObj.pathname;
            analysis.query = urlObj.search;
            
            // Extract subdomain
            const parts = urlObj.hostname.split('.');
            if (parts.length > 2) {
                analysis.subdomain = parts.slice(0, -2).join('.');
            }
            
            // Basic suspicious indicators
            analysis.suspicious = this.checkSuspiciousIndicators(url, urlObj);
            
        } catch (e) {
            analysis.error = 'Invalid URL';
        }
        
        return analysis;
    },

    checkSuspiciousIndicators: function(url, urlObj) {
        const indicators = [];
        
        // Check for IP address
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (ipPattern.test(urlObj.hostname)) {
            indicators.push('Uses IP address');
        }
        
        // Check URL length
        if (url.length > 100) {
            indicators.push('Very long URL');
        }
        
        // Check for excessive subdomains
        const subdomainCount = urlObj.hostname.split('.').length - 2;
        if (subdomainCount > 3) {
            indicators.push('Many subdomains');
        }
        
        // Check for suspicious characters
        if (url.includes('@')) {
            indicators.push('Contains @ symbol');
        }
        
        // Check protocol
        if (urlObj.protocol !== 'https:') {
            indicators.push('Not using HTTPS');
        }
        
        return indicators;
    },

    // File upload utilities
    validateFile: function(file, allowedTypes, maxSize) {
        const errors = [];
        
        if (!allowedTypes.includes(file.type)) {
            errors.push(`File type not allowed. Allowed: ${allowedTypes.join(', ')}`);
        }
        
        if (file.size > maxSize) {
            errors.push(`File too large. Max size: ${(maxSize / 1024 / 1024).toFixed(1)}MB`);
        }
        
        return errors;
    },

    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Local storage utilities
    saveToLocalStorage: function(key, data) {
        try {
            localStorage.setItem(key, JSON.stringify(data));
            return true;
        } catch (e) {
            console.error('Failed to save to localStorage:', e);
            return false;
        }
    },

    getFromLocalStorage: function(key) {
        try {
            const data = localStorage.getItem(key);
            return data ? JSON.parse(data) : null;
        } catch (e) {
            console.error('Failed to read from localStorage:', e);
            return null;
        }
    },

    // Performance monitoring
    measurePerformance: function(name, fn) {
        const start = performance.now();
        const result = fn();
        const end = performance.now();
        console.log(`${name} took ${(end - start).toFixed(2)} milliseconds`);
        return result;
    }
};

// Utility functions for scan results
const ScanUtils = {
    formatConfidence: function(confidence) {
        return Math.round(confidence * 100) + '%';
    },

    getConfidenceClass: function(confidence) {
        if (confidence > 0.7) return 'bg-danger';
        if (confidence > 0.4) return 'bg-warning';
        return 'bg-success';
    },

    getResultIcon: function(result) {
        const icons = {
            'safe': 'fas fa-check-circle text-success',
            'phishing': 'fas fa-exclamation-triangle text-danger',
            'suspicious': 'fas fa-question-circle text-warning'
        };
        return icons[result] || 'fas fa-question-circle text-muted';
    },

    getResultBadge: function(result) {
        const badges = {
            'safe': 'badge bg-success',
            'phishing': 'badge bg-danger',
            'suspicious': 'badge bg-warning'
        };
        return badges[result] || 'badge bg-secondary';
    }
};

// Extension communication utilities
const ExtensionUtils = {
    isExtensionAvailable: function() {
        return window.chrome && window.chrome.runtime;
    },

    sendMessageToExtension: function(message, callback) {
        if (this.isExtensionAvailable()) {
            chrome.runtime.sendMessage(message, callback);
        } else {
            console.warn('Extension not available');
            if (callback) callback({error: 'Extension not available'});
        }
    },

    checkExtensionStatus: function() {
        if (this.isExtensionAvailable()) {
            this.sendMessageToExtension({action: 'ping'}, (response) => {
                if (response && response.status === 'ok') {
                    PhishGuard.showToast('Extension connected successfully', 'success');
                }
            });
        }
    }
};

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    PhishGuard.init();
    ExtensionUtils.checkExtensionStatus();
});

// Export utilities for use in other scripts
window.PhishGuard = PhishGuard;
window.ScanUtils = ScanUtils;
window.ExtensionUtils = ExtensionUtils;
