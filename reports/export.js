// reports/export.js
export function generateEnhancedJSON(scanResults, iocs, mitreMapping) {
    const reportData = {
        scanner: "AetherScan Enterprise Edition",
        auditTime: new Date().toISOString(),
        fileMetadata: {
            name: scanResults.filename,
            sizeBytes: scanResults.filesizeBytes,
            declaredMime: scanResults.declaredMime,
            detectedSignature: scanResults.detectedType,
            sha256: scanResults.sha256,
            entropy: scanResults.entropy
        },
        verdict: {
            riskScore: scanResults.riskScore,
            classification: scanResults.classification,
            summary: scanResults.verdictTitle,
            details: scanResults.verdictDesc
        },
        indicatorsOfCompromise: iocs,
        mitreAttack: mitreMapping,
        aiAnalystSummary: generateAIAnalystSummary(scanResults, iocs, mitreMapping)
    };

    return "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 4));
}

export function generateCSV(scanResults, iocs) {
    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += "Metric,Value\r\n";
    csvContent += `Filename,${scanResults.filename}\r\n`;
    csvContent += `SHA256,${scanResults.sha256}\r\n`;
    csvContent += `Risk Score,${scanResults.riskScore}\r\n`;
    csvContent += `Classification,${scanResults.classification}\r\n`;
    csvContent += `Domains Found,${iocs.domains.join(';')}\r\n`;
    csvContent += `IPs Found,${iocs.ips.join(';')}\r\n`;
    return encodeURI(csvContent);
}

export function generateAIAnalystSummary(scanResults, iocs, mitreMapping) {
    let summary = "AI Analyst Review:\n";

    if (scanResults.classification === 'DANGER') {
        summary += `CRITICAL: The analyzed file ${scanResults.filename} exhibits highly malicious behavior. `;
        if (mitreMapping.tactics.length > 0) {
            summary += `It utilizes techniques associated with ${mitreMapping.tactics.map(t => t.name).join(', ')}. `;
        }
        if (iocs.ips.length > 0 || iocs.domains.length > 0) {
            summary += `Network indicators suggest possible C2 communication. `;
        }
        summary += `Immediate remediation and containment is required. Do not execute this file outside a sandbox environment.`;
    } else if (scanResults.classification === 'SUSPICIOUS') {
        summary += `WARNING: The file ${scanResults.filename} has suspicious traits. `;
        if (scanResults.entropy > 7.2) summary += `High entropy suggests the payload is packed or obfuscated. `;
        summary += `Proceed with caution. Consider dynamic analysis before deployment.`;
    } else {
        summary += `SAFE: File ${scanResults.filename} appears benign. Static analysis found no known malicious signatures, high-risk extension traits, or obfuscation. Standard deployment is approved.`;
    }

    return summary;
}
