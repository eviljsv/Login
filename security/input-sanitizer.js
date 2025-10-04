class InputSanitizer {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        
        // Remove caracteres perigosos
        let sanitized = input
            .replace(/[<>]/g, '') // Remove < e >
            .replace(/javascript:/gi, '')
            .replace(/on\w+=/gi, '')
            .replace(/expression\(/gi, '')
            .replace(/url\(/gi, '')
            .replace(/\\/g, '')
            .replace(/'/g, '&#39;')
            .replace(/"/g, '&#34;')
            .trim();
        
        return sanitized;
    }

    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email) && email.length <= 254;
    }

    static validatePassword(password) {
        // Mínimo 8 caracteres, pelo menos 1 letra maiúscula, 1 minúscula, 1 número e 1 caractere especial
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        return passwordRegex.test(password);
    }

    static preventSQLInjection(input) {
        const sqlKeywords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 
            'EXEC', 'OR', 'AND', 'WHERE', 'FROM', 'TABLE'
        ];
        
        const upperInput = input.toUpperCase();
        return !sqlKeywords.some(keyword => upperInput.includes(keyword));
    }

    static sanitizeObject(obj) {
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string') {
                sanitized[key] = this.sanitizeInput(value);
            } else if (Array.isArray(value)) {
                sanitized[key] = value.map(item => 
                    typeof item === 'string' ? this.sanitizeInput(item) : item
                );
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }
}

module.exports = InputSanitizer;
