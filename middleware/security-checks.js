const AdvancedFirewall = require('../security/firewall');
const AdvancedRateLimiter = require('../security/rate-limiter');
const InputSanitizer = require('../security/input-sanitizer');
const SecurityHeaders = require('../security/headers-config');

const firewall = new AdvancedFirewall();
const rateLimiter = new AdvancedRateLimiter();

function securityMiddleware(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    
    // 1. Verifica IP bloqueado
    if (firewall.isIPBlocked(ip)) {
        return res.status(403).json({ 
            error: 'Access denied',
            code: 'IP_BLOCKED'
        });
    }

    // 2. Analisa requisição no firewall
    if (!firewall.analyzeRequest(req)) {
        return res.status(403).json({ 
            error: 'Suspicious activity detected',
            code: 'REQUEST_BLOCKED'
        });
    }

    // 3. Rate limiting
    const rateLimitResult = rateLimiter.checkRateLimit(ip, req.path);
    if (!rateLimitResult.allowed) {
        res.setHeader('X-RateLimit-Limit', '100');
        res.setHeader('X-RateLimit-Remaining', '0');
        res.setHeader('X-RateLimit-Reset', rateLimitResult.resetTime);
        
        return res.status(429).json({
            error: 'Too many requests',
            retryAfter: Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000)
        });
    }

    // 4. Sanitiza inputs
    if (req.body) {
        req.body = InputSanitizer.sanitizeObject(req.body);
    }
    if (req.query) {
        req.query = InputSanitizer.sanitizeObject(req.query);
    }

    // 5. Configura headers de segurança
    SecurityHeaders.setSecurityHeaders(res);

    // 6. Log de segurança
    console.log(`🔒 Security: ${ip} - ${req.method} ${req.url} - ${new Date().toISOString()}`);

    next();
}

module.exports = securityMiddleware;
