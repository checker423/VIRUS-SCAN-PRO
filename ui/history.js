// history.js - IndexedDB Scan History Manager

const DB_NAME = 'AetherScanHistoryDB';
const DB_VERSION = 1;
const STORE_NAME = 'scans';

let db;

export function initHistoryDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = (event) => reject('IndexedDB error: ' + event.target.error);

        request.onsuccess = (event) => {
            db = event.target.result;
            resolve(db);
        };

        request.onupgradeneeded = (event) => {
            db = event.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                const store = db.createObjectStore(STORE_NAME, { keyPath: 'sha256' });
                store.createIndex('timestamp', 'timestamp', { unique: false });
                store.createIndex('classification', 'classification', { unique: false });
            }
        };
    });
}

export function saveScanResult(result) {
    if (!db) return Promise.reject('DB not initialized');
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        
        // Ensure we don't save excessive data (limit strings array)
        const record = { ...result, timestamp: Date.now() };
        if (record.strings && record.strings.length > 50) {
            record.strings = record.strings.slice(0, 50);
        }

        const request = store.put(record);
        request.onsuccess = () => resolve();
        request.onerror = (e) => reject(e.target.error);
    });
}

export function getScanHistory(limit = 20) {
    if (!db) return Promise.reject('DB not initialized');
    return new Promise((resolve, reject) => {
        const transaction = db.transaction([STORE_NAME], 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const index = store.index('timestamp');
        
        const results = [];
        const request = index.openCursor(null, 'prev'); // descending

        request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor && results.length < limit) {
                results.push(cursor.value);
                cursor.continue();
            } else {
                resolve(results);
            }
        };
        request.onerror = (e) => reject(e.target.error);
    });
}
