class AdvancedRateLimiter {
    constructor() {
        this.requests = new Map();
        this.config = {
            windowMs: 15 * 60 * 1000, // 15 minutos
            maxRequests: 100, // máximo de requisições por IP
            blockDuration: 30 * 60 * 1000, // 30 minutos de bloqueio
        };
    }

    checkRateLimit(ip, endpoint) {
        const now = Date.now();
        const key = `${ip}-${endpoint}`;
        
        if (!this.requests.has(key)) {
            this.requests.set(key, []);
        }
        
        const userRequests = this.requests.get(key);
        
        // Remove requisições antigas
        const windowStart = now - this.config.windowMs;
        const recentRequests = userRequests.filter(time => time > windowStart);
        this.requests.set(key, recentRequests);
        
        // Verifica se excedeu o limite
        if (recentRequests.length >= this.config.maxRequests) {
            return {
                allowed: false,
                remaining: 0,
                resetTime: windowStart + this.config.windowMs
            };
        }
        
        // Adiciona nova requisição
        recentRequests.push(now);
        
        return {
            allowed: true,
            remaining: this.config.maxRequests - recentRequests.length,
            resetTime: windowStart + this.config.windowMs
        };
    }

    // Limpeza periódica
    cleanup() {
        const now = Date.now();
        for (const [key, requests] of this.requests.entries()) {
            const validRequests = requests.filter(time => 
                now - time < this.config.windowMs + this.config.blockDuration
            );
            if (validRequests.length === 0) {
                this.requests.delete(key);
            } else {
                this.requests.set(key, validRequests);
            }
        }
    }
}

module.exports = AdvancedRateLimiter;
