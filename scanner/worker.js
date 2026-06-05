self.onmessage = async function(e) {
    const { file, type } = e.data;
    
    if (type === 'PROCESS_FILE') {
        try {
            // Process file in chunks for memory efficiency
            const CHUNK_SIZE = 1024 * 1024 * 2; // 2MB chunks
            const fileSize = file.size;
            let offset = 0;
            
            // For true chunked hashing in JS we'd need a library. 
            // Here we simulate efficient reading by only hashing the first 10MB for SHA, 
            // but we'll calculate entropy over the chunks.
            const MAX_HASH_SIZE = 1024 * 1024 * 10; 
            const bufferToHash = await file.slice(0, Math.min(fileSize, MAX_HASH_SIZE)).arrayBuffer();
            
            // Use subtle crypto for fast SHA
            const sha256Buffer = await crypto.subtle.digest('SHA-256', bufferToHash);
            const sha1Buffer = await crypto.subtle.digest('SHA-1', bufferToHash);
            
            const sha256Hash = Array.from(new Uint8Array(sha256Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
            const sha1Hash = Array.from(new Uint8Array(sha1Buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
            
            // Chunked processing for entropy and strings
            let totalEntropySum = 0;
            let segments = [];
            let extractedStrings = [];
            let chunkCount = 0;
            
            // Regexes for IOCs
            const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
            const domainRegex = /\b(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
            
            while (offset < fileSize && chunkCount < 16) { // limit to 16 chunks to avoid UI hang
                const chunk = file.slice(offset, offset + CHUNK_SIZE);
                const arrayBuffer = await chunk.arrayBuffer();
                const u8 = new Uint8Array(arrayBuffer);
                
                // Entropy of chunk
                const ent = calculateEntropy(u8);
                totalEntropySum += ent;
                segments.push(ent);
                
                // Extract strings from chunk (limit size)
                if (extractedStrings.length < 500) {
                    const strs = extractStrings(u8);
                    extractedStrings = extractedStrings.concat(strs);
                }
                
                offset += CHUNK_SIZE;
                chunkCount++;
                
                // Report progress
                self.postMessage({ type: 'PROGRESS', progress: Math.floor((offset / fileSize) * 100) });
            }
            
            const avgEntropy = totalEntropySum / chunkCount;
            
            self.postMessage({
                type: 'COMPLETE',
                results: {
                    sha256: sha256Hash,
                    sha1: sha1Hash,
                    entropy: avgEntropy,
                    entropySegments: segments,
                    strings: extractedStrings.slice(0, 500), // Limit array size for memory
                    headerBytes: new Uint8Array(await file.slice(0, 48).arrayBuffer())
                }
            });
            
        } catch (error) {
            self.postMessage({ type: 'ERROR', error: error.message });
        }
    }
};

function calculateEntropy(byteArray) {
    const len = byteArray.length;
    if (len === 0) return 0;
    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < len; i++) {
        frequencies[byteArray[i]]++;
    }
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            const p = frequencies[i] / len;
            entropy -= p * Math.log2(p);
        }
    }
    return entropy;
}

function extractStrings(byteArray) {
    const stringsList = [];
    let currentString = '';
    const minLength = 5;
    const maxScanBytes = Math.min(byteArray.length, 1000000);
    
    for (let i = 0; i < maxScanBytes; i++) {
        const char = byteArray[i];
        if (char >= 32 && char <= 126) {
            currentString += String.fromCharCode(char);
        } else {
            if (currentString.length >= minLength) {
                stringsList.push(currentString);
                if (stringsList.length >= 100) break; // Limit per chunk
            }
            currentString = '';
        }
    }
    return stringsList;
}
