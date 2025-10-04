class AdvancedFirewall {
    constructor() {
        this.blockedIPs = new Set();
        this.suspiciousActivities = new Map();
        this.threatPatterns = [
            /(\b)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|EXEC)(\b)/gi,
            /(\b)(script|alert|onerror|onload)=/gi,
            /(\.\.\/|\.\.\\|\\\.\.)/gi, // Path traversal
            /(<|>|&lt;|&gt;)/gi, // HTML injection
            /(eval\(|system\(|exec\()/gi, // Command injection
            /(base64_decode|gzinflate)/gi, // PHP attacks
            /(union.*select|insert.*into)/gi, // SQL injection
        ];
    }

    // Analisa requisições em tempo real
    analyzeRequest(req) {
        const ip = req.ip || req.connection.remoteAddress;
        const userAgent = req.headers['user-agent'] || '';
        const url = req.url;
        
        // Verifica padrões maliciosos
        if (this.isMaliciousRequest(req)) {
            this.blockIP(ip, 'Malicious pattern detected');
            return false;
        }

        // Verifica User-Agent suspeito
        if (this.isSuspiciousUserAgent(userAgent)) {
            this.recordSuspiciousActivity(ip, 'Suspicious User-Agent');
            return false;
        }

        // Verifica taxa de requisições
        if (this.isRateLimitExceeded(ip)) {
            this.blockIP(ip, 'Rate limit exceeded');
            return false;
        }

        return true;
    }

    isMaliciousRequest(req) {
        const checkFields = [
            req.url,
            req.headers['user-agent'],
            JSON.stringify(req.body),
            JSON.stringify(req.query),
            JSON.stringify(req.params)
        ];

        for (const field of checkFields) {
            for (const pattern of this.threatPatterns) {
                if (pattern.test(field)) {
                    return true;
                }
            }
        }
        return false;
    }

    isSuspiciousUserAgent(userAgent) {
        const suspiciousAgents = [
            'nmap', 'sqlmap', 'metasploit', 'nikto', 
            'wget', 'curl', 'python-requests', 'go-http-client',
            '', 'null', 'undefined'
        ];
        
        return suspiciousAgents.some(agent => 
            userAgent.toLowerCase().includes(agent.toLowerCase())
        );
    }

    isRateLimitExceeded(ip) {
        const now = Date.now();
        const activities = this.suspiciousActivities.get(ip) || [];
        
        // Limite: 100 requisições por minuto
        const recentActivities = activities.filter(time => now - time < 60000);
        this.suspiciousActivities.set(ip, recentActivities);
        
        if (recentActivities.length > 100) {
            return true;
        }
        
        recentActivities.push(now);
        return false;
    }

    blockIP(ip, reason) {
        this.blockedIPs.add(ip);
        console.log(`🚨 IP ${ip} blocked: ${reason}`);
        
        // Bloqueio temporário (1 hora)
        setTimeout(() => {
            this.blockedIPs.delete(ip);
        }, 60 * 60 * 1000);
    }

    isIPBlocked(ip) {
        return this.blockedIPs.has(ip);
    }
}

module.exports = AdvancedFirewall;
