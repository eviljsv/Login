class SecurityHeaders {
    static setSecurityHeaders(res) {
        // Headers de segurança
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        res.setHeader('Content-Security-Policy', 
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
        );
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
        
        // Remove headers sensíveis
        res.removeHeader('X-Powered-By');
        res.removeHeader('Server');
    }

    static generateCSRFToken() {
        const crypto = require('crypto');
        return crypto.randomBytes(32).toString('hex');
    }

    static validateCSRFToken(token, sessionToken) {
        if (!token || !sessionToken) return false;
        return crypto.timingSafeEqual(
            Buffer.from(token),
            Buffer.from(sessionToken)
        );
    }
}

module.exports = SecurityHeaders;
