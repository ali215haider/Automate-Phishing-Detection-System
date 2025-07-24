// PhishGuard Content Script

class PhishGuardContent {
    constructor() {
        this.serverUrl = 'http://localhost:5000'; // Change to production URL
        this.isScanning = false;
        this.scanTimeout = null;
        
        this.init();
    }

    init() {
        // Don't run on localhost or file:// URLs
        if (window.location.hostname === 'localhost' || 
            window.location.protocol === 'file:' ||
            window.location.protocol === 'chrome-extension:') {
            return;
        }

        this.setupMessageListener();
        this.checkPageOnLoad();
        this.observeNavigationChanges();
        this.injectWarningStyles();
    }

    setupMessageListener() {
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            if (message.action === 'scan-page') {
                this.scanCurrentPage().then(sendResponse);
                return true; // Keep message channel open for async response
            }
            
            if (message.action === 'get-page-info') {
                sendResponse({
                    url: window.location.href,
                    title: document.title,
                    domain: window.location.hostname
                });
            }
        });
    }

    async checkPageOnLoad() {
        // Wait for page to load
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.delayedScan();
            });
        } else {
            this.delayedScan();
        }
    }

    delayedScan() {
        // Delay scanning to avoid interfering with page load
        this.scanTimeout = setTimeout(() => {
            this.scanCurrentPage();
        }, 2000);
    }

    observeNavigationChanges() {
        // Watch for navigation changes (SPAs)
        let lastUrl = window.location.href;
        
        const observer = new MutationObserver(() => {
            if (lastUrl !== window.location.href) {
                lastUrl = window.location.href;
                if (this.scanTimeout) {
                    clearTimeout(this.scanTimeout);
                }
                this.delayedScan();
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    async scanCurrentPage() {
        if (this.isScanning) {
            return;
        }

        this.isScanning = true;
        
        try {
            const result = await this.performScan(window.location.href);
            
            if (result && result.result === 'phishing') {
                this.showPhishingWarning(result);
            } else if (result && result.result === 'suspicious') {
                this.showSuspiciousWarning(result);
            }
            
            // Send result to background script
            chrome.runtime.sendMessage({
                action: 'scan-result',
                url: window.location.href,
                result: result
            });
            
            return result;
        } catch (error) {
            console.error('PhishGuard scan error:', error);
        } finally {
            this.isScanning = false;
        }
    }

    async performScan(url) {
        try {
            const response = await fetch(`${this.serverUrl}/api/scan-url`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
                credentials: 'include'
            });

            if (response.ok) {
                return await response.json();
            }
        } catch (error) {
            console.error('Error connecting to PhishGuard server:', error);
        }
        
        return null;
    }

    showPhishingWarning(result) {
        // Remove any existing warnings
        this.removeExistingWarnings();
        
        const warning = this.createWarningBanner('danger', 
            'Phishing Website Detected!', 
            'This website has been identified as potentially dangerous. Your personal information may be at risk.',
            result);
        
        document.body.insertBefore(warning, document.body.firstChild);
        
        // Show browser notification
        this.showNotification('Phishing Detected', 'The current website has been flagged as potentially dangerous.');
    }

    showSuspiciousWarning(result) {
        // Remove any existing warnings
        this.removeExistingWarnings();
        
        const warning = this.createWarningBanner('warning',
            'Suspicious Website Detected',
            'This website has some suspicious characteristics. Please be cautious with any personal information.',
            result);
        
        document.body.insertBefore(warning, document.body.firstChild);
    }

    createWarningBanner(type, title, message, result) {
        const banner = document.createElement('div');
        banner.id = 'phishguard-warning';
        banner.className = `phishguard-banner phishguard-${type}`;
        
        banner.innerHTML = `
            <div class="phishguard-content">
                <div class="phishguard-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 2L1 21h22L12 2zm0 3.99L19.53 19H4.47L12 5.99zM11 16h2v2h-2v-2zm0-6h2v4h-2v-4z"/>
                    </svg>
                </div>
                <div class="phishguard-text">
                    <div class="phishguard-title">${title}</div>
                    <div class="phishguard-message">${message}</div>
                    <div class="phishguard-confidence">Confidence: ${Math.round((result.confidence || 0) * 100)}%</div>
                </div>
                <div class="phishguard-actions">
                    <button class="phishguard-btn phishguard-btn-primary" onclick="this.parentElement.parentElement.parentElement.style.display='none'">
                        Dismiss
                    </button>
                    <button class="phishguard-btn phishguard-btn-secondary" onclick="window.history.back()">
                        Go Back
                    </button>
                </div>
            </div>
        `;
        
        return banner;
    }

    removeExistingWarnings() {
        const existing = document.getElementById('phishguard-warning');
        if (existing) {
            existing.remove();
        }
    }

    injectWarningStyles() {
        if (document.getElementById('phishguard-styles')) {
            return;
        }
        
        const styles = document.createElement('style');
        styles.id = 'phishguard-styles';
        styles.textContent = `
            .phishguard-banner {
                position: fixed !important;
                top: 0 !important;
                left: 0 !important;
                right: 0 !important;
                z-index: 2147483647 !important;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
                font-size: 14px !important;
                line-height: 1.4 !important;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2) !important;
                animation: phishguard-slide-down 0.3s ease-out !important;
            }
            
            .phishguard-danger {
                background: linear-gradient(135deg, #dc2626, #b91c1c) !important;
                color: white !important;
                border-bottom: 3px solid #991b1b !important;
            }
            
            .phishguard-warning {
                background: linear-gradient(135deg, #d97706, #b45309) !important;
                color: white !important;
                border-bottom: 3px solid #92400e !important;
            }
            
            .phishguard-content {
                display: flex !important;
                align-items: center !important;
                padding: 16px 20px !important;
                max-width: 1200px !important;
                margin: 0 auto !important;
                gap: 16px !important;
            }
            
            .phishguard-icon {
                flex-shrink: 0 !important;
                opacity: 0.9 !important;
            }
            
            .phishguard-text {
                flex: 1 !important;
                min-width: 0 !important;
            }
            
            .phishguard-title {
                font-weight: 600 !important;
                font-size: 16px !important;
                margin-bottom: 4px !important;
            }
            
            .phishguard-message {
                opacity: 0.9 !important;
                margin-bottom: 4px !important;
            }
            
            .phishguard-confidence {
                font-size: 12px !important;
                opacity: 0.8 !important;
            }
            
            .phishguard-actions {
                display: flex !important;
                gap: 8px !important;
                flex-shrink: 0 !important;
            }
            
            .phishguard-btn {
                padding: 8px 16px !important;
                border: none !important;
                border-radius: 6px !important;
                font-size: 14px !important;
                font-weight: 500 !important;
                cursor: pointer !important;
                transition: all 0.2s !important;
            }
            
            .phishguard-btn-primary {
                background: rgba(255, 255, 255, 0.2) !important;
                color: white !important;
                border: 1px solid rgba(255, 255, 255, 0.3) !important;
            }
            
            .phishguard-btn-primary:hover {
                background: rgba(255, 255, 255, 0.3) !important;
            }
            
            .phishguard-btn-secondary {
                background: rgba(0, 0, 0, 0.2) !important;
                color: white !important;
                border: 1px solid rgba(0, 0, 0, 0.3) !important;
            }
            
            .phishguard-btn-secondary:hover {
                background: rgba(0, 0, 0, 0.3) !important;
            }
            
            @keyframes phishguard-slide-down {
                from {
                    transform: translateY(-100%) !important;
                }
                to {
                    transform: translateY(0) !important;
                }
            }
            
            @media (max-width: 768px) {
                .phishguard-content {
                    flex-direction: column !important;
                    text-align: center !important;
                    padding: 12px 16px !important;
                }
                
                .phishguard-actions {
                    width: 100% !important;
                    justify-content: center !important;
                }
            }
        `;
        
        document.head.appendChild(styles);
    }

    async showNotification(title, message) {
        try {
            // Send message to background script to show notification
            chrome.runtime.sendMessage({
                action: 'show-notification',
                title: title,
                message: message
            });
        } catch (error) {
            console.error('Error showing notification:', error);
        }
    }
}

// Initialize content script
const phishGuardContent = new PhishGuardContent();
