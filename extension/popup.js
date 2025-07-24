// PhishGuard Extension Popup

class PhishGuardPopup {
    constructor() {
        this.serverUrl = 'http://localhost:5000'; // Change to production URL
        this.currentTab = null;
        this.scanResult = null;
        
        this.init();
    }

    async init() {
        await this.getCurrentTab();
        this.bindEvents();
        await this.loadScanResult();
    }

    async getCurrentTab() {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            this.currentTab = tab;
            document.getElementById('current-url').textContent = tab.url;
        } catch (error) {
            console.error('Error getting current tab:', error);
            this.showError('Unable to access current page');
        }
    }

    bindEvents() {
        document.getElementById('rescan-btn').addEventListener('click', () => {
            this.rescanCurrentPage();
        });

        document.getElementById('report-btn').addEventListener('click', () => {
            this.reportPhishing();
        });

        document.getElementById('dashboard-btn').addEventListener('click', () => {
            this.openDashboard();
        });

        document.getElementById('settings-btn').addEventListener('click', () => {
            this.openSettings();
        });
    }

    async loadScanResult() {
        if (!this.currentTab || !this.currentTab.url) {
            this.showError('No valid URL to scan');
            return;
        }

        // Skip scanning for non-http(s) URLs
        if (!this.currentTab.url.startsWith('http')) {
            this.showLocalPage();
            return;
        }

        try {
            // First, check if we have cached results
            const cached = await this.getCachedResult(this.currentTab.url);
            if (cached && this.isCacheValid(cached)) {
                this.displayResult(cached.result);
                this.hideLoading();
                return;
            }

            // Perform new scan
            await this.scanUrl(this.currentTab.url);
        } catch (error) {
            console.error('Error loading scan result:', error);
            this.showError('Unable to scan current page');
        }
    }

    async scanUrl(url) {
        try {
            const response = await fetch(`${this.serverUrl}/api/scan-url`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
                credentials: 'include'
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const result = await response.json();
            this.scanResult = result;
            
            // Cache the result
            await this.cacheResult(url, result);
            
            this.displayResult(result);
        } catch (error) {
            console.error('Error scanning URL:', error);
            this.showError('Unable to connect to PhishGuard server');
        } finally {
            this.hideLoading();
        }
    }

    displayResult(result) {
        const statusIcon = document.getElementById('status-icon');
        const statusTitle = document.getElementById('status-title');
        const statusSubtitle = document.getElementById('status-subtitle');
        const scoreFill = document.getElementById('score-fill');

        // Update status based on result
        if (result.result === 'safe') {
            statusIcon.className = 'status-icon status-safe';
            statusIcon.innerHTML = '<i class="fas fa-check"></i>';
            statusTitle.textContent = 'Safe Website';
            statusSubtitle.textContent = 'No threats detected';
            scoreFill.style.background = '#4ade80';
        } else if (result.result === 'phishing') {
            statusIcon.className = 'status-icon status-danger';
            statusIcon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
            statusTitle.textContent = 'Phishing Detected';
            statusSubtitle.textContent = 'This site may be dangerous';
            scoreFill.style.background = '#ef4444';
        } else {
            statusIcon.className = 'status-icon status-warning';
            statusIcon.innerHTML = '<i class="fas fa-question"></i>';
            statusTitle.textContent = 'Suspicious Content';
            statusSubtitle.textContent = 'Exercise caution';
            scoreFill.style.background = '#fbbf24';
        }

        // Update confidence score
        const confidence = result.confidence || 0;
        scoreFill.style.width = `${Math.max(confidence * 100, 10)}%`;

        // Show notifications for dangerous sites
        if (result.result === 'phishing') {
            this.showNotification('Phishing website detected!', 'This website has been identified as potentially dangerous.');
        }

        document.getElementById('content').classList.remove('hidden');
    }

    showLocalPage() {
        const statusIcon = document.getElementById('status-icon');
        const statusTitle = document.getElementById('status-title');
        const statusSubtitle = document.getElementById('status-subtitle');
        const scoreFill = document.getElementById('score-fill');

        statusIcon.className = 'status-icon status-safe';
        statusIcon.innerHTML = '<i class="fas fa-home"></i>';
        statusTitle.textContent = 'Local Page';
        statusSubtitle.textContent = 'Browser page or extension';
        scoreFill.style.width = '100%';
        scoreFill.style.background = '#4ade80';

        document.getElementById('content').classList.remove('hidden');
        this.hideLoading();
    }

    async rescanCurrentPage() {
        if (!this.currentTab || !this.currentTab.url.startsWith('http')) {
            return;
        }

        // Clear cache for this URL
        await this.clearCachedResult(this.currentTab.url);
        
        // Show loading and rescan
        this.showLoading();
        document.getElementById('content').classList.add('hidden');
        
        await this.scanUrl(this.currentTab.url);
    }

    reportPhishing() {
        if (!this.currentTab || !this.currentTab.url.startsWith('http')) {
            return;
        }

        // Open report form in new tab
        const reportUrl = `${this.serverUrl}/profile?report_url=${encodeURIComponent(this.currentTab.url)}`;
        chrome.tabs.create({ url: reportUrl });
    }

    openDashboard() {
        chrome.tabs.create({ url: `${this.serverUrl}/dashboard` });
    }

    openSettings() {
        chrome.runtime.openOptionsPage();
    }

    showLoading() {
        document.getElementById('loading').classList.remove('hidden');
        document.getElementById('error').classList.add('hidden');
        document.getElementById('content').classList.add('hidden');
    }

    hideLoading() {
        document.getElementById('loading').classList.add('hidden');
    }

    showError(message) {
        document.getElementById('error-message').textContent = message;
        document.getElementById('error').classList.remove('hidden');
        document.getElementById('loading').classList.add('hidden');
        document.getElementById('content').classList.add('hidden');
    }

    async showNotification(title, message) {
        try {
            await chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: title,
                message: message,
                priority: 2
            });
        } catch (error) {
            console.error('Error showing notification:', error);
        }
    }

    async getCachedResult(url) {
        try {
            const result = await chrome.storage.local.get(`scan_${this.hashUrl(url)}`);
            return result[`scan_${this.hashUrl(url)}`] || null;
        } catch (error) {
            console.error('Error getting cached result:', error);
            return null;
        }
    }

    async cacheResult(url, result) {
        try {
            const cacheData = {
                result: result,
                timestamp: Date.now(),
                url: url
            };
            await chrome.storage.local.set({ [`scan_${this.hashUrl(url)}`]: cacheData });
        } catch (error) {
            console.error('Error caching result:', error);
        }
    }

    async clearCachedResult(url) {
        try {
            await chrome.storage.local.remove(`scan_${this.hashUrl(url)}`);
        } catch (error) {
            console.error('Error clearing cached result:', error);
        }
    }

    isCacheValid(cached) {
        const maxAge = 30 * 60 * 1000; // 30 minutes
        return cached && cached.timestamp && (Date.now() - cached.timestamp) < maxAge;
    }

    hashUrl(url) {
        // Simple hash function for URL (in production, use a proper hash function)
        let hash = 0;
        if (url.length === 0) return hash;
        for (let i = 0; i < url.length; i++) {
            const char = url.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash).toString();
    }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PhishGuardPopup();
});
