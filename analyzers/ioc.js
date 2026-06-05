// ioc.js - Indicators of Compromise Extractor and Parsers

export function extractIOCs(strings) {
    const iocs = {
        ips: new Set(),
        domains: new Set(),
        emails: new Set(),
        urls: new Set(),
        crypto: new Set(),
        suspicious: new Set()
    };

    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const domainRegex = /\b(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const urlRegex = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g;
    const btcRegex = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g; // Basic BTC
    const suspiciousKeywords = [
        'eval', 'exec', 'system', 'cmd.exe', 'powershell', 'sh ', 'bash', 'curl', 'wget', 
        'temp', 'appdata', 'registry', 'hkey_', 'VirtualAlloc', 'WriteProcessMemory', 
        'CreateRemoteThread', 'bypass', 'download', 'upload'
    ];

    strings.forEach(str => {
        // Find IPs
        let ipMatch;
        while ((ipMatch = ipRegex.exec(str)) !== null) iocs.ips.add(ipMatch[0]);
        
        // Find URLs
        let urlMatch;
        while ((urlMatch = urlRegex.exec(str)) !== null) iocs.urls.add(urlMatch[0]);
        
        // Find Emails
        let emailMatch;
        while ((emailMatch = emailRegex.exec(str)) !== null) iocs.emails.add(emailMatch[0]);
        
        // Find BTC wallets
        let btcMatch;
        while ((btcMatch = btcRegex.exec(str)) !== null) iocs.crypto.add(btcMatch[0]);

        // Find domains (if not matched as URL)
        let domMatch;
        while ((domMatch = domainRegex.exec(str)) !== null) {
            if (!iocs.emails.has(domMatch[0]) && !str.includes('http')) {
                iocs.domains.add(domMatch[0]);
            }
        }

        if (suspiciousKeywords.some(keyword => str.toLowerCase().includes(keyword))) {
            iocs.suspicious.add(str);
        }
    });

    return {
        ips: Array.from(iocs.ips),
        domains: Array.from(iocs.domains),
        emails: Array.from(iocs.emails),
        urls: Array.from(iocs.urls),
        crypto: Array.from(iocs.crypto),
        suspicious: Array.from(iocs.suspicious)
    };
}

export function parsePE(fileBytes) {
    // Simulated PE Parser
    if (fileBytes[0] !== 0x4D || fileBytes[1] !== 0x5A) return null; // MZ
    return {
        isPE: true,
        compiler: 'Microsoft Visual C++ 8.0',
        timestamp: '2021-04-15 14:32:00',
        sections: [
            { name: '.text', virtualSize: '0x1A000', rawSize: '0x1A200', entropy: 6.5 },
            { name: '.rdata', virtualSize: '0x5000', rawSize: '0x5200', entropy: 4.1 },
            { name: '.data', virtualSize: '0x2000', rawSize: '0x1000', entropy: 2.3 },
            { name: '.rsrc', virtualSize: '0x8000', rawSize: '0x8200', entropy: 7.8 }
        ],
        imports: ['kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll'],
        suspiciousApis: ['VirtualAllocEx', 'CreateRemoteThread', 'WriteProcessMemory']
    };
}

export function parseAPK(filename) {
    // Simulated APK Parser based on filename extension
    if (!filename.toLowerCase().endsWith('.apk')) return null;
    return {
        isAPK: true,
        packageName: 'com.aetherscan.simulated.app',
        minSdk: 21,
        targetSdk: 33,
        permissions: [
            'android.permission.INTERNET',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.CAMERA'
        ],
        dangerousPermissions: [
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS'
        ],
        activities: ['MainActivity', 'HiddenService', 'SmsReceiver']
    };
}
