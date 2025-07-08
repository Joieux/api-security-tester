/**
 * API Security Tester - Caido Plugin Backend
 * Token discovery and security analysis
 */

// Token patterns for discovery
const TOKEN_PATTERNS = {
    'JWT': /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    'API Key': /(?:api[_-]?key|apikey)[_-]?[:=]\s*['"']?([A-Za-z0-9_-]{20,})['"']?/gi,
    'Bearer': /bearer\s+([A-Za-z0-9_-]{20,})/gi,
    'GitHub': /gh[pousr]_[A-Za-z0-9_]{36}/g,
    'Slack': /xox[baprs]-[A-Za-z0-9_-]{10,}/g,
    'AWS Access': /AKIA[0-9A-Z]{16}/g,
    'Generic Secret': /(?:secret|token)[_-]?[:=]\s*['"']?([A-Za-z0-9_-]{20,})['"']?/gi
};

// Plugin findings storage
let findings = [];

/**
 * Find tokens in text
 */
function findTokensInText(text, source, url) {
    const newFindings = [];
    
    for (const [tokenType, pattern] of Object.entries(TOKEN_PATTERNS)) {
        const matches = text.matchAll(pattern);
        
        for (const match of matches) {
            const token = match[1] || match[0];
            if (token && token.length >= 15) {
                const finding = {
                    type: tokenType,
                    token: token,
                    truncatedToken: token.length > 20 ? token.substring(0, 20) + '...' : token,
                    source: source,
                    url: url,
                    timestamp: Date.now()
                };
                
                newFindings.push(finding);
                findings.push(finding);
                
                // Log to console
                console.log(`[API Security] ${tokenType}: ${finding.truncatedToken} - ${source}`);
            }
        }
    }
    
    return newFindings;
}

/**
 * Check for CORS vulnerabilities
 */
function checkCORS(response, url) {
    if (!response.headers) return [];
    
    const corsHeader = response.headers['access-control-allow-origin'] || 
                      response.headers['Access-Control-Allow-Origin'];
    
    if (corsHeader === '*') {
        console.log(`[API Security] CORS Vulnerability: Wildcard CORS at ${url}`);
        return [{
            type: 'CORS Vulnerability',
            severity: 'High',
            description: 'Wildcard CORS origin (*) detected',
            url: url,
            timestamp: Date.now()
        }];
    }
    
    return [];
}

/**
 * Main plugin function
 */
export function init(sdk) {
    console.log('API Security Tester plugin initialized');
    
    // Listen for HTTP requests
    sdk.events.on('request', (event) => {
        try {
            const request = event.request;
            const url = request.url || 'unknown';
            
            // Analyze request body
            if (request.body) {
                const bodyText = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
                findTokensInText(bodyText, 'Request Body', url);
            }
            
            // Analyze request headers
            if (request.headers) {
                for (const [name, value] of Object.entries(request.headers)) {
                    if (typeof value === 'string') {
                        findTokensInText(value, `Request Header: ${name}`, url);
                    }
                }
            }
        } catch (error) {
            console.error('Error analyzing request:', error);
        }
    });
    
    // Listen for HTTP responses
    sdk.events.on('response', (event) => {
        try {
            const response = event.response;
            const url = response.url || event.request?.url || 'unknown';
            
            // Analyze response body
            if (response.body) {
                const bodyText = typeof response.body === 'string' ? response.body : JSON.stringify(response.body);
                findTokensInText(bodyText, 'Response Body', url);
            }
            
            // Analyze response headers
            if (response.headers) {
                for (const [name, value] of Object.entries(response.headers)) {
                    if (typeof value === 'string') {
                        findTokensInText(value, `Response Header: ${name}`, url);
                    }
                }
            }
            
            // Check for CORS issues
            checkCORS(response, url);
            
        } catch (error) {
            console.error('Error analyzing response:', error);
        }
    });
    
    // Register commands
    sdk.commands.register({
        id: 'clear-findings',
        name: 'Clear Findings',
        run: () => {
            findings = [];
            console.log('API Security: Findings cleared');
        }
    });
    
    sdk.commands.register({
        id: 'show-findings',
        name: 'Show Findings',
        run: () => {
            console.log(`API Security: Total findings: ${findings.length}`);
            findings.forEach((finding, index) => {
                console.log(`${index + 1}. ${finding.type}: ${finding.truncatedToken || finding.description}`);
            });
        }
    });
}