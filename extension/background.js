// PhishGuard Background Service Worker

class PhishGuardBackground {
    constructor() {
        this.serverUrl = 'http://localhost:5000'; // Change to production URL
        this.scanCache = new Map();
        this.notificationQueue = [];
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.startPeriodicTasks();
        console.log('PhishGuard background service started');
    }

    setupEventListeners() {
        // Extension installation/startup
        chrome.runtime.onInstalled.addListener((details) => {
            this.handleInstall(details);
        });

        chrome.runtime.onStartup.addListener(() => {
            this.handleStartup();
        });

        // Message handling from content scripts and popup
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
            this.handleMessage(message, sender, sendResponse);
            return true; // Keep message channel open for async responses
        });

        // Tab updates for real-time scanning
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
            this.handleTabUpdate(tabId, changeInfo, tab);
        });

        // Navigation events
        chrome.webNavigation.onCompleted.addListener((details) => {
            this.handleNavigationCompleted(details);
        });

        // Alarm events for periodic tasks
        chrome.alarms.onAlarm.addListener((alarm) => {
            this.handleAlarm(alarm);
        });

        // Notification clicks
        chrome.notifications.onClicked.addListener((notificationId) => {
            this.handleNotificationClick(notificationId);
        });
    }

    async handleInstall(details) {
        if (details.reason === 'install') {
            // First-time installation
            await this.setDefaultSettings();
            await this.showWelcomeNotification();
            
            // Open welcome page
            chrome.tabs.create({
                url: `${this.serverUrl}/education`
            });
        } else if (details.reason === 'update') {
            // Extension update
            console.log('PhishGuard updated to version', chrome.runtime.getManifest().version);
        }
    }

    async handleStartup() {
        // Clean up old cache entries
        await this.cleanupCache();
        
        // Restore periodic alarms
        chrome.alarms.create('cleanup', { periodInMinutes: 60 });
        chrome.alarms.create('updateBlacklist', { periodInMinutes: 720 }); // 12 hours
    }

    async handleMessage(message, sender, sendResponse) {
        try {
            switch (message.action) {
                case 'scan-url':
                    const result = await this.scanUrl(message.url);
                    sendResponse(result);
                    break;

                case 'scan-result':
                    await this.processScanResult(message.url, message.result, sender.tab);
                    sendResponse({ status: 'ok' });
                    break;

                case 'show-notification':
                    await this.showNotification(message.title, message.message);
                    sendResponse({ status: 'ok' });
                    break;

                case 'get-settings':
                    const settings = await this.getSettings();
                    sendResponse(settings);
                    break;

                case 'update-settings':
                    await this.updateSettings(message.settings);
                    sendResponse({ status: 'ok' });
                    break;

                case 'get-cache-stats':
                    const stats = await this.getCacheStats();
                    sendResponse(stats);
                    break;

                case 'clear-cache':
                    await this.clearCache();
                    sendResponse({ status: 'ok' });
                    break;

                case 'ping':
                    sendResponse({ status: 'ok', version: chrome.runtime.getManifest().version });
                    break;

                default:
                    sendResponse({ error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ error: error.message });
        }
    }

    async handleTabUpdate(tabId, changeInfo, tab) {
        // Only process completed loads of http(s) URLs
        if (changeInfo.status === 'complete' && 
            tab.url && 
            (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
            
            const settings = await this.getSettings();
            if (settings.realTimeScanning) {
                // Delayed scan to avoid interfering with page load
                setTimeout(() => {
                    this.backgroundScan(tab.url, tabId);
                }, 3000);
            }
        }
    }

    async handleNavigationCompleted(details) {
        // Handle single-page application navigation
        if (details.frameId === 0) { // Main frame only
            const settings = await this.getSettings();
            if (settings.realTimeScanning) {
                setTimeout(() => {
                    this.backgroundScan(details.url, details.tabId);
                }, 2000);
            }
        }
    }

    async handleAlarm(alarm) {
        switch (alarm.name) {
            case 'cleanup':
                await this.cleanupCache();
                break;
            case 'updateBlacklist':
                await this.updateBlacklistCache();
                break;
        }
    }

    async handleNotificationClick(notificationId) {
        if (notificationId.startsWith('phishing_')) {
            // Extract URL from notification ID
            const url = notificationId.replace('phishing_', '');
            
            // Open PhishGuard dashboard
            chrome.tabs.create({
                url: `${this.serverUrl}/dashboard`
            });
        }
        
        // Clear the notification
        chrome.notifications.clear(notificationId);
    }

    async scanUrl(url) {
        // Check cache first
        const cached = await this.getCachedScan(url);
        if (cached && this.isCacheValid(cached)) {
            return cached.result;
        }

        try {
            // Perform server-side scan
            const response = await fetch(`${this.serverUrl}/api/scan-url`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url }),
                credentials: 'include'
            });

            if (response.ok) {
                const result = await response.json();
                
                // Cache the result
                await this.cacheScanResult(url, result);
                
                return result;
            } else {
                throw new Error(`Server responded with ${response.status}`);
            }
        } catch (error) {
            console.error('Error scanning URL:', error);
            
            // Fallback to local basic checks
            return this.performBasicScan(url);
        }
    }

    async backgroundScan(url, tabId) {
        try {
            const result = await this.scanUrl(url);
            
            if (result.result === 'phishing') {
                await this.handlePhishingDetected(url, tabId, result);
            } else if (result.result === 'suspicious') {
                await this.handleSuspiciousDetected(url, tabId, result);
            }
        } catch (error) {
            console.error('Background scan error:', error);
        }
    }

    async handlePhishingDetected(url, tabId, result) {
        const settings = await this.getSettings();
        
        if (settings.showNotifications) {
            const notificationId = `phishing_${url}`;
            await chrome.notifications.create(notificationId, {
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: 'Phishing Website Detected!',
                message: `This website has been identified as potentially dangerous. Confidence: ${Math.round(result.confidence * 100)}%`,
                priority: 2,
                requireInteraction: true
            });
        }

        // Update extension badge
        chrome.action.setBadgeText({
            text: '⚠',
            tabId: tabId
        });
        chrome.action.setBadgeBackgroundColor({
            color: '#dc2626',
            tabId: tabId
        });

        // Send message to content script if available
        try {
            chrome.tabs.sendMessage(tabId, {
                action: 'phishing-detected',
                result: result
            });
        } catch (error) {
            // Content script might not be injected yet
        }
    }

    async handleSuspiciousDetected(url, tabId, result) {
        const settings = await this.getSettings();
        
        if (settings.showSuspiciousNotifications) {
            await chrome.notifications.create(`suspicious_${url}`, {
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: 'Suspicious Website',
                message: `This website has some suspicious characteristics. Exercise caution.`,
                priority: 1
            });
        }

        // Update extension badge
        chrome.action.setBadgeText({
            text: '?',
            tabId: tabId
        });
        chrome.action.setBadgeBackgroundColor({
            color: '#d97706',
            tabId: tabId
        });
    }

    performBasicScan(url) {
        // Basic local scan when server is unavailable
        const result = {
            result: 'safe',
            confidence: 0.1,
            method: 'local',
            details: {
                features: {},
                rules_triggered: [],
                offline_mode: true
            }
        };

        try {
            const urlObj = new URL(url);
            const suspiciousPatterns = [
                // IP addresses
                /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
                // Suspicious TLDs
                /\.(tk|ml|ga|cf|pw)$/,
                // URL shorteners
                /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly)/,
                // Suspicious keywords
                /(secure|account|update|verify|login|banking)/i
            ];

            let suspiciousCount = 0;
            
            // Check domain against patterns
            for (const pattern of suspiciousPatterns) {
                if (pattern.test(urlObj.hostname) || pattern.test(url)) {
                    suspiciousCount++;
                    result.details.rules_triggered.push(`Pattern matched: ${pattern.source}`);
                }
            }

            // Check URL length
            if (url.length > 100) {
                suspiciousCount++;
                result.details.rules_triggered.push('Long URL detected');
            }

            // Check for no HTTPS
            if (urlObj.protocol !== 'https:') {
                suspiciousCount++;
                result.details.rules_triggered.push('No HTTPS encryption');
            }

            if (suspiciousCount >= 2) {
                result.result = 'suspicious';
                result.confidence = Math.min(suspiciousCount * 0.2, 0.8);
            } else if (suspiciousCount >= 3) {
                result.result = 'phishing';
                result.confidence = Math.min(suspiciousCount * 0.3, 0.9);
            }

        } catch (error) {
            result.details.error = 'Invalid URL';
        }

        return result;
    }

    async processScanResult(url, result, tab) {
        // Store scan result for analytics
        const scanData = {
            url: url,
            result: result,
            timestamp: Date.now(),
            tabId: tab?.id,
            userAgent: navigator.userAgent
        };

        // Store in local storage for extension analytics
        const existing = await chrome.storage.local.get('scanHistory') || { scanHistory: [] };
        existing.scanHistory = existing.scanHistory || [];
        existing.scanHistory.push(scanData);

        // Keep only last 100 scans
        if (existing.scanHistory.length > 100) {
            existing.scanHistory = existing.scanHistory.slice(-100);
        }

        await chrome.storage.local.set({ scanHistory: existing.scanHistory });
    }

    async getCachedScan(url) {
        try {
            const key = `scan_${this.hashUrl(url)}`;
            const result = await chrome.storage.local.get(key);
            return result[key] || null;
        } catch (error) {
            console.error('Error getting cached scan:', error);
            return null;
        }
    }

    async cacheScanResult(url, result) {
        try {
            const key = `scan_${this.hashUrl(url)}`;
            const cacheData = {
                result: result,
                timestamp: Date.now(),
                url: url
            };
            await chrome.storage.local.set({ [key]: cacheData });
        } catch (error) {
            console.error('Error caching scan result:', error);
        }
    }

    isCacheValid(cached) {
        const maxAge = 30 * 60 * 1000; // 30 minutes
        return cached && cached.timestamp && (Date.now() - cached.timestamp) < maxAge;
    }

    async setDefaultSettings() {
        const defaultSettings = {
            realTimeScanning: true,
            showNotifications: true,
            showSuspiciousNotifications: false,
            autoBlock: false,
            serverUrl: this.serverUrl,
            cacheTimeout: 1800000, // 30 minutes
            version: chrome.runtime.getManifest().version
        };

        await chrome.storage.sync.set({ settings: defaultSettings });
    }

    async getSettings() {
        try {
            const result = await chrome.storage.sync.get('settings');
            return result.settings || await this.setDefaultSettings();
        } catch (error) {
            console.error('Error getting settings:', error);
            return await this.setDefaultSettings();
        }
    }

    async updateSettings(newSettings) {
        const currentSettings = await this.getSettings();
        const updatedSettings = { ...currentSettings, ...newSettings };
        await chrome.storage.sync.set({ settings: updatedSettings });
    }

    async showWelcomeNotification() {
        await chrome.notifications.create('welcome', {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: 'PhishGuard Installed Successfully!',
            message: 'Your browser is now protected against phishing attacks. Click to learn more.',
            priority: 1
        });
    }

    async showNotification(title, message, priority = 1) {
        const settings = await this.getSettings();
        if (!settings.showNotifications) {
            return;
        }

        const notificationId = `notification_${Date.now()}`;
        await chrome.notifications.create(notificationId, {
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: title,
            message: message,
            priority: priority
        });

        // Auto-clear after 10 seconds
        setTimeout(() => {
            chrome.notifications.clear(notificationId);
        }, 10000);
    }

    async cleanupCache() {
        try {
            const allData = await chrome.storage.local.get();
            const keysToRemove = [];
            const now = Date.now();
            const maxAge = 24 * 60 * 60 * 1000; // 24 hours

            for (const [key, value] of Object.entries(allData)) {
                if (key.startsWith('scan_') && value.timestamp) {
                    if (now - value.timestamp > maxAge) {
                        keysToRemove.push(key);
                    }
                }
            }

            if (keysToRemove.length > 0) {
                await chrome.storage.local.remove(keysToRemove);
                console.log(`Cleaned up ${keysToRemove.length} expired cache entries`);
            }
        } catch (error) {
            console.error('Error cleaning up cache:', error);
        }
    }

    async getCacheStats() {
        try {
            const allData = await chrome.storage.local.get();
            let scanCacheCount = 0;
            let totalSize = 0;

            for (const [key, value] of Object.entries(allData)) {
                if (key.startsWith('scan_')) {
                    scanCacheCount++;
                    totalSize += JSON.stringify(value).length;
                }
            }

            return {
                scanCacheCount: scanCacheCount,
                estimatedSize: totalSize,
                lastCleanup: Date.now()
            };
        } catch (error) {
            console.error('Error getting cache stats:', error);
            return { scanCacheCount: 0, estimatedSize: 0, lastCleanup: 0 };
        }
    }

    async clearCache() {
        try {
            const allData = await chrome.storage.local.get();
            const keysToRemove = Object.keys(allData).filter(key => key.startsWith('scan_'));
            
            if (keysToRemove.length > 0) {
                await chrome.storage.local.remove(keysToRemove);
                console.log(`Cleared ${keysToRemove.length} cache entries`);
            }
        } catch (error) {
            console.error('Error clearing cache:', error);
        }
    }

    async updateBlacklistCache() {
        // This would fetch updated blacklist from server
        // For now, just log that it would happen
        console.log('Updating blacklist cache (placeholder)');
    }

    startPeriodicTasks() {
        // Set up periodic alarms
        chrome.alarms.create('cleanup', { 
            delayInMinutes: 60, 
            periodInMinutes: 60 
        });
        
        chrome.alarms.create('updateBlacklist', { 
            delayInMinutes: 30, 
            periodInMinutes: 720 
        });
    }

    hashUrl(url) {
        // Simple hash function for URL caching
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

// Initialize background service
const phishGuardBackground = new PhishGuardBackground();
