/**
 * Draxyl Security Library v2.0
 * Comprehensive security utilities for frontend protection
 */

// ==================== XSS PROTECTION ====================
const Security = {
    /**
     * Sanitize HTML to prevent XSS attacks
     */
    sanitizeHTML: function(str) {
        if (!str) return '';
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    },

    /**
     * Escape HTML entities
     */
    escapeHTML: function(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    },

    /**
     * Validate email format
     */
    validateEmail: function(email) {
        const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return pattern.test(email);
    },

    /**
     * Validate password strength
     */
    validatePassword: function(password) {
        if (password.length < 8) {
            return { valid: false, message: 'Password must be at least 8 characters long' };
        }
        if (!/[A-Z]/.test(password)) {
            return { valid: false, message: 'Password must contain at least one uppercase letter' };
        }
        if (!/[a-z]/.test(password)) {
            return { valid: false, message: 'Password must contain at least one lowercase letter' };
        }
        if (!/\d/.test(password)) {
            return { valid: false, message: 'Password must contain at least one number' };
        }
        return { valid: true, message: 'Password is strong' };
    },

    /**
     * Sanitize user input before sending to backend
     */
    sanitizeInput: function(input) {
        if (!input) return '';
        return String(input).trim().substring(0, 10000); // Max length 10k chars
    },

    // ==================== TOKEN MANAGEMENT ====================
    /**
     * Store JWT token securely
     */
    setToken: function(token) {
        try {
            localStorage.setItem('draxyl_token', token);
            return true;
        } catch (e) {
            console.error('Failed to store token:', e);
            return false;
        }
    },

    /**
     * Retrieve JWT token
     */
    getToken: function() {
        try {
            return localStorage.getItem('draxyl_token');
        } catch (e) {
            console.error('Failed to retrieve token:', e);
            return null;
        }
    },

    /**
     * Remove JWT token (logout)
     */
    clearToken: function() {
        try {
            localStorage.removeItem('draxyl_token');
            return true;
        } catch (e) {
            console.error('Failed to clear token:', e);
            return false;
        }
    },

    /**
     * Check if token exists
     */
    hasToken: function() {
        return !!this.getToken();
    },

    /**
     * Decode JWT token (client-side only for display, not validation)
     */
    decodeToken: function(token) {
        try {
            if (!token) return null;
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            }).join(''));
            return JSON.parse(jsonPayload);
        } catch (e) {
            console.error('Failed to decode token:', e);
            return null;
        }
    },

    /**
     * Check if token is expired (client-side check only)
     */
    isTokenExpired: function(token) {
        const decoded = this.decodeToken(token);
        if (!decoded || !decoded.exp) return true;
        return Date.now() >= decoded.exp * 1000;
    },

    // ==================== SECURE STORAGE ====================
    /**
     * Encrypt data for localStorage (simple XOR encryption)
     */
    encrypt: function(data, key = 'draxyl-secure-key-2026') {
        try {
            const jsonStr = JSON.stringify(data);
            let encrypted = '';
            for (let i = 0; i < jsonStr.length; i++) {
                encrypted += String.fromCharCode(jsonStr.charCodeAt(i) ^ key.charCodeAt(i % key.length));
            }
            return btoa(encrypted);
        } catch (e) {
            console.error('Encryption failed:', e);
            return null;
        }
    },

    /**
     * Decrypt data from localStorage
     */
    decrypt: function(encrypted, key = 'draxyl-secure-key-2026') {
        try {
            const decoded = atob(encrypted);
            let decrypted = '';
            for (let i = 0; i < decoded.length; i++) {
                decrypted += String.fromCharCode(decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length));
            }
            return JSON.parse(decrypted);
        } catch (e) {
            console.error('Decryption failed:', e);
            return null;
        }
    },

    /**
     * Store user data securely
     */
    setSecureData: function(key, data) {
        const encrypted = this.encrypt(data);
        if (encrypted) {
            localStorage.setItem(`draxyl_${key}`, encrypted);
            return true;
        }
        return false;
    },

    /**
     * Retrieve secure user data
     */
    getSecureData: function(key) {
        const encrypted = localStorage.getItem(`draxyl_${key}`);
        if (encrypted) {
            return this.decrypt(encrypted);
        }
        return null;
    },

    // ==================== API REQUEST HELPERS ====================
    /**
     * Make secure API request with token
     */
    secureRequest: async function(url, options = {}) {
        const token = this.getToken();
        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        };

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            // Handle token expiration
            if (response.status === 401) {
                const data = await response.json();
                if (data.message && data.message.includes('expired')) {
                    this.clearToken();
                    alert('Your session has expired. Please log in again.');
                    window.location.href = 'login.html';
                }
            }

            return response;
        } catch (error) {
            console.error('Secure request failed:', error);
            throw error;
        }
    },

    /**
     * Validate and sanitize form data
     */
    sanitizeFormData: function(formData) {
        const sanitized = {};
        for (const [key, value] of Object.entries(formData)) {
            if (key === 'password') {
                // Don't sanitize passwords
                sanitized[key] = value;
            } else if (typeof value === 'string') {
                sanitized[key] = this.sanitizeInput(value);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    },

    // ==================== CSRF PROTECTION ====================
    /**
     * Generate CSRF token
     */
    generateCSRFToken: function() {
        return Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * Store CSRF token
     */
    setCSRFToken: function() {
        const token = this.generateCSRFToken();
        sessionStorage.setItem('csrf_token', token);
        return token;
    },

    /**
     * Get CSRF token
     */
    getCSRFToken: function() {
        let token = sessionStorage.getItem('csrf_token');
        if (!token) {
            token = this.setCSRFToken();
        }
        return token;
    },

    // ==================== INPUT VALIDATION ====================
    /**
     * Validate message content
     */
    validateMessage: function(message) {
        if (!message || message.trim().length === 0) {
            return { valid: false, message: 'Message cannot be empty' };
        }
        if (message.length > 5000) {
            return { valid: false, message: 'Message too long (max 5000 characters)' };
        }
        return { valid: true };
    },

    /**
     * Validate workspace/channel name
     */
    validateName: function(name, maxLength = 100) {
        if (!name || name.trim().length === 0) {
            return { valid: false, message: 'Name cannot be empty' };
        }
        if (name.length > maxLength) {
            return { valid: false, message: `Name too long (max ${maxLength} characters)` };
        }
        // Check for special characters that could cause issues
        if (!/^[a-zA-Z0-9\s\-_]+$/.test(name)) {
            return { valid: false, message: 'Name can only contain letters, numbers, spaces, hyphens, and underscores' };
        }
        return { valid: true };
    },

    // ==================== SECURITY WARNINGS ====================
    /**
     * Show security warning modal
     */
    showSecurityWarning: function(message) {
        alert('⚠️ SECURITY WARNING\n\n' + message);
    },

    /**
     * Log security event (for monitoring)
     */
    logSecurityEvent: function(event, details) {
        console.warn(`[SECURITY EVENT] ${event}:`, details);
        // In production, this should send to a security monitoring service
    }
};

// ==================== AUTO-LOGOUT ON TOKEN EXPIRATION ====================
// Check token expiration every 5 minutes
setInterval(() => {
    const token = Security.getToken();
    if (token && Security.isTokenExpired(token)) {
        Security.clearToken();
        alert('Your session has expired. Please log in again.');
        window.location.href = 'login.html';
    }
}, 5 * 60 * 1000);

// ==================== PREVENT CLICKJACKING ====================
if (window.top !== window.self) {
    Security.logSecurityEvent('CLICKJACKING_ATTEMPT', {
        location: window.location.href
    });
    window.top.location = window.self.location;
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Security;
}
