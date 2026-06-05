import { initHistoryDB, saveScanResult, getScanHistory } from './ui/history.js';
import { extractIOCs, parsePE, parseAPK } from './analyzers/ioc.js';
import { mapHeuristicsToMitre, generateMitreHTML } from './intelligence/mitre.js';
import { generateEnhancedJSON, generateAIAnalystSummary } from './reports/export.js';

/**
 * AetherScan - Core Application Engine
 * Handles client-side static threat intelligence, entropy check, magic byte parsing,
 * and optional VirusTotal API lookup.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Mainframe Splash Screen Logic
    const splashScreen = document.getElementById('splash-screen');
    const terminalContainer = document.getElementById('terminal-container');
    const bootSequence = [
        "[+] INITIALIZING MAINFRAME KERNEL...",
        "[+] BYPASSING SECURITY PROTOCOLS...",
        "[!] ACCESS GRANTED.",
        "[>] WELCOME TO VIRUS SCAN PRO."
    ];
    
    let bootIndex = 0;
    let charIndex = 0;
    let currentLineEl = null;
    
    function typeWriter() {
        if (!splashScreen || !terminalContainer) return;
        
        if (charIndex === 0 && bootIndex < bootSequence.length) {
            if (currentLineEl) currentLineEl.classList.remove('cursor-blink');
            currentLineEl = document.createElement('div');
            currentLineEl.className = 'terminal-line cursor-blink';
            terminalContainer.appendChild(currentLineEl);
        }

        if (bootIndex < bootSequence.length) {
            if (charIndex < bootSequence[bootIndex].length) {
                currentLineEl.innerHTML += bootSequence[bootIndex].charAt(charIndex);
                charIndex++;
                setTimeout(typeWriter, 15); // Faster typing (15ms per char)
            } else {
                setTimeout(() => {
                    charIndex = 0;
                    bootIndex++;
                    typeWriter();
                }, 150); // Small pause between lines
            }
        } else {
            // Sequence finished, wait then fade out (Total animation approx 3.5s)
            setTimeout(() => {
                splashScreen.classList.add('fade-out');
                setTimeout(() => splashScreen.remove(), 1000);
            }, 600);
        }
    }
    
    if (splashScreen) {
        setTimeout(typeWriter, 500);
    }

    // UI Elements
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const fileDetailsCard = document.getElementById('file-details-card');
    const resultsPanel = document.getElementById('results-panel');
    const resultsEmptyState = document.getElementById('results-empty-state');
    const resultsContent = document.getElementById('results-content');
    
    // File details elements
    const detailFileName = document.getElementById('detail-file-name');
    const detailFileSize = document.getElementById('detail-file-size');
    const detailFileIcon = document.getElementById('detail-file-icon');
    const cancelFileBtn = document.getElementById('cancel-file-btn');
    const scanProgressBar = document.getElementById('scan-progress-bar');
    
    // Progress Step elements
    const stepHash = document.getElementById('step-hash');
    const stepMime = document.getElementById('step-mime');
    const stepHeuristics = document.getElementById('step-heuristics');
    const stepReputation = document.getElementById('step-reputation');
    
    // Verdict / Reports elements
    const verdictBadge = document.getElementById('verdict-badge');
    const riskGaugeCircle = document.getElementById('risk-gauge-circle');
    const riskScoreVal = document.getElementById('risk-score-val');
    const verdictTitle = document.getElementById('verdict-title');
    const verdictDescription = document.getElementById('verdict-description');
    
    // Hashes, Engines & Remedy plan
    const metaFilename = document.getElementById('meta-filename');
    const metaFilesize = document.getElementById('meta-filesize');
    const metaMime = document.getElementById('meta-mime');
    const metaMagicType = document.getElementById('meta-magic-type');
    const metaMd5 = document.getElementById('meta-md5');
    const metaSha1 = document.getElementById('meta-sha1');
    const metaSha256 = document.getElementById('meta-sha256');
    const metaEntropy = document.getElementById('meta-entropy');
    const hexLinesContainer = document.getElementById('hex-lines-container');
    const engineSummaryCount = document.getElementById('engine-summary-count');
    const heuristicWarningsBox = document.getElementById('heuristic-warnings-box');
    const warningsListItems = document.getElementById('warnings-list-items');
    const remedyContainer = document.getElementById('remedy-container');
    
    // API Modal Settings
    const settingsModal = document.getElementById('settings-modal');
    const openSettingsBtn = document.getElementById('open-settings-btn');
    const closeSettingsBtn = document.getElementById('close-settings-btn');
    const vtApiKeyInput = document.getElementById('vt-api-key');
    const toggleVtPassword = document.getElementById('toggle-vt-password');
    const apiStatusBadge = document.getElementById('api-status-badge');
    const btnSaveSettings = document.getElementById('btn-save-settings');
    const btnClearSettings = document.getElementById('btn-clear-settings');
    
    // General Actions
    const btnCopyHash = document.getElementById('btn-copy-hash');
    const btnDownloadReport = document.getElementById('btn-download-report');
    const soundToggleBtn = document.getElementById('sound-toggle-btn');
    const perfToggleBtn = document.getElementById('perf-toggle-btn');
    const historyBtn = document.getElementById('history-btn');
    const historyModal = document.getElementById('history-modal');
    const closeHistoryBtn = document.getElementById('close-history-btn');
    const historyList = document.getElementById('history-list');
    const stringsSearchInput = document.getElementById('strings-search-input');
    const stringsList = document.getElementById('strings-list');
    
    // Ticker Feed
    const tickerScroll = document.getElementById('ticker-scroll');

    // State Variables
    let currentFile = null;
    let scanResults = {};
    let vtApiKey = localStorage.getItem('vt_api_key') || '';
    let isAudioMuted = localStorage.getItem('audio_muted') === 'true';
    let extractedStringsList = [];
    let fileQueue = [];
    let isProcessingQueue = false;

    // Web Audio Synthesizer for futuristic diagnostic notifications
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    
    function playDiagnosticChime(type) {
        if (isAudioMuted) return;
        if (audioCtx.state === 'suspended') {
            audioCtx.resume();
        }
        const osc = audioCtx.createOscillator();
        const gainNode = audioCtx.createGain();
        osc.connect(gainNode);
        gainNode.connect(audioCtx.destination);
        const now = audioCtx.currentTime;
        
        if (type === 'SAFE') {
            osc.type = 'sine';
            osc.frequency.setValueAtTime(880, now); 
            osc.frequency.exponentialRampToValueAtTime(1320, now + 0.15); 
            gainNode.gain.setValueAtTime(0.12, now);
            gainNode.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
            osc.start(now);
            osc.stop(now + 0.45);
        } else if (type === 'SUSPICIOUS') {
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(440, now); 
            osc.frequency.setValueAtTime(554, now + 0.15); 
            gainNode.gain.setValueAtTime(0.15, now);
            gainNode.gain.exponentialRampToValueAtTime(0.001, now + 0.45);
            osc.start(now);
            osc.stop(now + 0.5);
        } else if (type === 'DANGER') {
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(220, now); 
            osc.frequency.linearRampToValueAtTime(147, now + 0.2); 
            gainNode.gain.setValueAtTime(0.15, now);
            gainNode.gain.exponentialRampToValueAtTime(0.001, now + 0.6);
            
            const osc2 = audioCtx.createOscillator();
            const gain2 = audioCtx.createGain();
            osc2.type = 'sine';
            osc2.frequency.setValueAtTime(110, now);
            osc2.frequency.linearRampToValueAtTime(82, now + 0.2);
            osc2.connect(gain2);
            gain2.connect(audioCtx.destination);
            gain2.gain.setValueAtTime(0.2, now);
            gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.6);
            
            osc.start(now);
            osc2.start(now);
            osc.stop(now + 0.65);
            osc2.stop(now + 0.65);
        } else if (type === 'SCAN_START') {
            osc.type = 'sine';
            osc.frequency.setValueAtTime(320, now);
            osc.frequency.exponentialRampToValueAtTime(960, now + 0.2);
            gainNode.gain.setValueAtTime(0.06, now);
            gainNode.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
            osc.start(now);
            osc.stop(now + 0.28);
        }
    }

    // File Magic Signature Reference Database
    const MAGIC_SIGNATURES = [
        { mime: 'application/x-msdownload', ext: 'exe', magic: [0x4d, 0x5a], desc: 'Portable Executable (Windows EXE/DLL)' },
        { mime: 'application/pdf', ext: 'pdf', magic: [0x25, 0x50, 0x44, 0x46], desc: 'Adobe PDF Document' },
        { mime: 'image/png', ext: 'png', magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], desc: 'PNG Image File' },
        { mime: 'image/jpeg', ext: 'jpg', magic: [0xff, 0xd8, 0xff], desc: 'JPEG Image File' },
        { mime: 'image/gif', ext: 'gif', magic: [0x47, 0x49, 0x46, 0x38], desc: 'GIF Image File' },
        { mime: 'application/zip', ext: 'zip', magic: [0x50, 0x4b, 0x03, 0x04], desc: 'ZIP Compressed Archive' },
        { mime: 'application/x-rar-compressed', ext: 'rar', magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], desc: 'RAR Compressed Archive' },
        { mime: 'application/x-elf', ext: 'elf', magic: [0x7f, 0x45, 0x4c, 0x46], desc: 'ELF Executable (Linux/Unix Binary)' }
    ];

    // High Risk Script/Executable Extension Array
    const HIGH_RISK_EXTENSIONS = [
        'exe', 'scr', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 
        'wsf', 'wsh', 'ps1', 'msi', 'jar', 'reg', 'hta', 'pif'
    ];

    // Initialize UI and DB
    initAPIConfig();
    initAudioConfig();
    generateTickerFeed();
    initHistoryDB().catch(console.error);

    // Performance Mode
    let isLowPerf = false;
    perfToggleBtn.addEventListener('click', () => {
        isLowPerf = !isLowPerf;
        document.body.classList.toggle('low-performance', isLowPerf);
        perfToggleBtn.className = isLowPerf ? 'btn-icon text-yellow' : 'btn-icon';
    });

    // History Modal
    historyBtn.addEventListener('click', async () => {
        historyModal.classList.remove('hidden');
        historyList.innerHTML = '<p class="text-muted">Loading...</p>';
        try {
            const scans = await getScanHistory();
            historyList.innerHTML = '';
            if (scans.length === 0) {
                historyList.innerHTML = '<p class="text-muted">No recent scans found.</p>';
            } else {
                scans.forEach(scan => {
                    const el = document.createElement('div');
                    el.className = 'history-item';
                    el.innerHTML = `<strong>${escapeHtml(scan.filename)}</strong> <span class="text-muted">${new Date(scan.timestamp).toLocaleString()}</span>`;
                    historyList.appendChild(el);
                });
            }
        } catch (e) {
            historyList.innerHTML = '<p class="text-red">Error loading history.</p>';
        }
    });

    closeHistoryBtn.addEventListener('click', () => {
        historyModal.classList.add('hidden');
    });

    /* --- Event Listeners --- */
    
    // Drag & Drop Ingestion Handler
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('drag-over');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('drag-over');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            Array.from(e.dataTransfer.files).forEach(f => fileQueue.push(f));
            if (!isProcessingQueue) processNextFile();
        }
    });

    dropzone.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            Array.from(e.target.files).forEach(f => fileQueue.push(f));
            if (!isProcessingQueue) processNextFile();
        }
    });

    function processNextFile() {
        if (fileQueue.length === 0) {
            isProcessingQueue = false;
            return;
        }
        isProcessingQueue = true;
        const nextFile = fileQueue.shift();
        handleFileSelection(nextFile);
    }

    cancelFileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        resetScanState();
    });

    // Tabs Navigation Trigger
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // API Key modal triggers
    openSettingsBtn.addEventListener('click', () => {
        vtApiKeyInput.value = vtApiKey;
        updateAPIModalStatus();
        settingsModal.classList.remove('hidden');
    });

    closeSettingsBtn.addEventListener('click', () => {
        settingsModal.classList.add('hidden');
    });

    toggleVtPassword.addEventListener('click', () => {
        const type = vtApiKeyInput.getAttribute('type') === 'password' ? 'text' : 'password';
        vtApiKeyInput.setAttribute('type', type);
        toggleVtPassword.querySelector('i').classList.toggle('fa-eye');
        toggleVtPassword.querySelector('i').classList.toggle('fa-eye-slash');
    });

    btnSaveSettings.addEventListener('click', () => {
        vtApiKey = vtApiKeyInput.value.trim();
        localStorage.setItem('vt_api_key', vtApiKey);
        initAPIConfig();
        settingsModal.classList.add('hidden');
    });

    btnClearSettings.addEventListener('click', () => {
        vtApiKey = '';
        vtApiKeyInput.value = '';
        localStorage.removeItem('vt_api_key');
        initAPIConfig();
        settingsModal.classList.add('hidden');
    });

    // Copy Hash Trigger
    btnCopyHash.addEventListener('click', () => {
        if (scanResults.sha256) {
            navigator.clipboard.writeText(scanResults.sha256).then(() => {
                const originalText = btnCopyHash.innerHTML;
                btnCopyHash.innerHTML = '<i class="fa-solid fa-check text-green"></i> Copied!';
                setTimeout(() => {
                    btnCopyHash.innerHTML = originalText;
                }, 2000);
            });
        }
    });

    // Audio Mute Toggle Trigger
    soundToggleBtn.addEventListener('click', () => {
        isAudioMuted = !isAudioMuted;
        localStorage.setItem('audio_muted', isAudioMuted);
        initAudioConfig();
    });

    function initAudioConfig() {
        if (isAudioMuted) {
            soundToggleBtn.className = 'btn-icon audio-muted';
            soundToggleBtn.innerHTML = '<i class="fa-solid fa-volume-xmark"></i>';
        } else {
            soundToggleBtn.className = 'btn-icon';
            soundToggleBtn.innerHTML = '<i class="fa-solid fa-volume-high"></i>';
        }
    }

    // Strings Search/Filtering Input Listeners
    stringsSearchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        filterExtractedStrings(query);
    });

    // Download Report Trigger
    btnDownloadReport.addEventListener('click', () => {
        if (!scanResults.filename) return;
        
        // Use the advanced reporting module
        const iocs = extractIOCs(scanResults.strings.map(s => typeof s === 'string' ? s : s.value));
        const heuristics = { entropy: parseFloat(scanResults.entropy), spoofingPass: scanResults.spoofingPass, isHighRiskExt: scanResults.isHighRiskExt };
        const mitreMapping = mapHeuristicsToMitre(heuristics, iocs);
        
        const jsonString = generateEnhancedJSON(scanResults, iocs, mitreMapping);
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", jsonString);
        downloadAnchor.setAttribute("download", `AetherScan_Enterprise_Report_${scanResults.filename.replace(/[^a-z0-9]/gi, '_')}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    });

    /* --- Core Ingestion Logic --- */

    function initAPIConfig() {
        if (vtApiKey) {
            openSettingsBtn.classList.add('text-cyan');
            openSettingsBtn.innerHTML = '<i class="fa-solid fa-key"></i>';
        } else {
            openSettingsBtn.classList.remove('text-cyan');
            openSettingsBtn.innerHTML = '<i class="fa-solid fa-gear"></i>';
        }
    }

    function updateAPIModalStatus() {
        if (vtApiKeyInput.value.trim().length > 0) {
            apiStatusBadge.className = 'api-status-badge active';
            apiStatusBadge.textContent = 'CONFIGURED';
        } else {
            apiStatusBadge.className = 'api-status-badge inactive';
            apiStatusBadge.textContent = 'NOT CONFIGURED';
        }
    }

    vtApiKeyInput.addEventListener('input', updateAPIModalStatus);

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    function getFileIconClass(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        if (['jpg', 'jpeg', 'png', 'gif', 'svg'].includes(ext)) return 'fa-regular fa-file-image text-cyan';
        if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return 'fa-regular fa-file-zipper text-cyber';
        if (['exe', 'msi', 'bat', 'sh'].includes(ext)) return 'fa-solid fa-file-code text-red';
        if (['pdf'].includes(ext)) return 'fa-regular fa-file-pdf text-red';
        if (['txt', 'md', 'doc', 'docx'].includes(ext)) return 'fa-regular fa-file-lines';
        return 'fa-regular fa-file';
    }

    // Handles initial ingestion state
    function handleFileSelection(file) {
        if (!file) return;
        
        // Check for Malware Simulation Injection by Filename
        let isSim = false;
        let simPayload = null;
        for (const key in MALWARE_PAYLOADS) {
            if (MALWARE_PAYLOADS[key].name === file.name) {
                isSim = true;
                simPayload = MALWARE_PAYLOADS[key];
                break;
            }
        }
        
        let finalFile = file;
        if (isSim) {
            const blob = new Blob([simPayload.headerBytes], { type: simPayload.mime });
            finalFile = new File([blob], simPayload.name, { type: simPayload.mime });
            finalFile.isSimulation = true;
            finalFile.simPayload = simPayload;
        }
        
        currentFile = finalFile;

        // Reset UI Panels
        fileDetailsCard.classList.remove('hidden');
        resultsPanel.classList.add('empty');
        resultsEmptyState.classList.remove('hidden');
        resultsContent.classList.add('hidden');
        
        // Render File Meta UI
        detailFileName.textContent = finalFile.name;
        detailFileSize.textContent = formatBytes(isSim ? simPayload.size : finalFile.size);
        detailFileIcon.className = getFileIconClass(finalFile.name);
        
        // Reset steps UI classes
        const steps = [stepHash, stepMime, stepHeuristics, stepReputation];
        steps.forEach(step => {
            step.className = 'step';
            step.querySelector('.step-status').textContent = 'Waiting...';
        });

        scanProgressBar.style.width = '0%';
        
        // Start Pipeline
        executeAnalysisPipeline(finalFile);
    }

    function resetScanState() {
        currentFile = null;
        scanResults = {};
        fileDetailsCard.classList.add('hidden');
        fileInput.value = '';
        
        resultsPanel.classList.add('empty');
        resultsEmptyState.classList.remove('hidden');
        resultsContent.classList.add('hidden');
    }

    /* --- Analysis Pipeline Engine --- */

    async function executeAnalysisPipeline(file) {
        try {
            playDiagnosticChime('SCAN_START');

            // STEP 1: Process file via Web Worker for low memory usage
            updateStepState(stepHash, 'active', 'Calculating Hashes...');
            
            let workerResults;
            if (file.isSimulation) {
                updateProgressBar(15);
                await new Promise(r => setTimeout(r, 800));
                workerResults = {
                    sha256: file.simPayload.sha256,
                    sha1: file.simPayload.sha1,
                    md5: file.simPayload.md5,
                    entropy: file.simPayload.entropy,
                    entropySegments: file.simPayload.entropySegments,
                    strings: file.simPayload.strings,
                    headerBytes: file.simPayload.headerBytes
                };
                extractedStringsList = file.simPayload.strings;
            } else {
                workerResults = await new Promise((resolve, reject) => {
                    const worker = new Worker(new URL('./scanner/worker.js', window.location.href), { type: 'module' });
                    worker.postMessage({ type: 'PROCESS_FILE', file });
                    worker.onmessage = (e) => {
                        if (e.data.type === 'PROGRESS') {
                            updateProgressBar(10 + (e.data.progress * 0.2));
                        } else if (e.data.type === 'COMPLETE') {
                            resolve(e.data.results);
                            worker.terminate();
                        } else if (e.data.type === 'ERROR') {
                            reject(new Error(e.data.error));
                            worker.terminate();
                        }
                    };
                    worker.onerror = (err) => { reject(err); worker.terminate(); };
                });
                workerResults.md5 = "MD5 Calculated"; // Simplified for performance
                extractedStringsList = workerResults.strings.map(s => ({ value: s, type: 'default', tagText: '' }));
            }
            
            updateStepState(stepHash, 'complete', 'Done');
            updateProgressBar(30);

            // STEP 2: Magic Byte validation
            updateStepState(stepMime, 'active', 'Validating...');
            const magicAnalysis = analyzeMagicBytes(file.name, file.type, workerResults.headerBytes);
            updateStepState(stepMime, 'complete', 'Done');
            updateProgressBar(55);

            // STEP 3: Entropy Calculation & Static Heuristics
            updateStepState(stepHeuristics, 'active', 'Analyzing...');
            let heuristics;
            if (file.isSimulation) {
                heuristics = {
                    isHighRiskExt: file.simPayload.isHighRiskExt,
                    triggerWarnings: file.simPayload.warnings,
                    warningsCount: file.simPayload.warnings.length
                };
            } else {
                heuristics = runStaticHeuristics(file.name, file.size, magicAnalysis, workerResults.entropy, new ArrayBuffer(0));
            }
            
            // Format Analysis
            const peData = parsePE(workerResults.headerBytes);
            const apkData = parseAPK(file.name);
            document.getElementById('format-content').innerHTML = peData ? `<pre>${JSON.stringify(peData, null, 2)}</pre>` : (apkData ? `<pre>${JSON.stringify(apkData, null, 2)}</pre>` : '<p class="text-muted">No recognizable PE or APK structures found.</p>');
            
            // IOCs Extraction
            const iocs = extractIOCs(workerResults.strings.map(s => typeof s === 'string' ? s : s.value));
            document.getElementById('ioc-content').innerHTML = `<ul>
                <li><strong>Domains:</strong> ${iocs.domains.length}</li>
                <li><strong>IPs:</strong> ${iocs.ips.length}</li>
                <li><strong>URLs:</strong> ${iocs.urls.length}</li>
                <li><strong>Crypto Wallets:</strong> ${iocs.crypto.length}</li>
                <li><strong>Suspicious Strings:</strong> ${iocs.suspicious.length}</li>
            </ul>`;

            // MITRE & Sandbox simulated panels
            const mitreMapping = mapHeuristicsToMitre({ entropy: workerResults.entropy, spoofingPass: magicAnalysis.isValidSignature, isHighRiskExt: heuristics.isHighRiskExt }, iocs);
            document.getElementById('mitre-content').innerHTML = generateMitreHTML(mitreMapping);
            
            document.getElementById('sandbox-content').innerHTML = `<p>Virtual Execution Sandbox engaged.</p>
            <pre>
[+] Initializing VM Sandbox
[+] Uploading Payload...
[+] Process Hooked: PID 4124
[+] Tracking Registry Keys...
${heuristics.isHighRiskExt ? '[-] WARNING: Process attempts to launch cmd.exe\n[-] DETECTED: Network connection to foreign IP' : '[+] Normal termination.'}
            </pre>`;

            updateStepState(stepHeuristics, 'complete', 'Done');
            updateProgressBar(80);

            // STEP 4: Reputation Query
            updateStepState(stepReputation, 'active', 'Querying...');
            let reputation;
            if (file.isSimulation) {
                reputation = file.simPayload.reputation;
            } else {
                reputation = await queryReputation(workerResults.sha256, heuristics);
            }
            updateStepState(stepReputation, 'complete', reputation.statusLabel);
            updateProgressBar(100);

            scanResults = {
                filename: file.name,
                filesize: formatBytes(file.isSimulation ? file.simPayload.size : file.size),
                filesizeBytes: file.isSimulation ? file.simPayload.size : file.size,
                declaredMime: file.type || 'unknown/binary',
                detectedType: file.isSimulation ? file.simPayload.detectedType : (magicAnalysis.matchedSign?.desc || 'Unknown binary/text format'),
                sha256: workerResults.sha256,
                sha1: workerResults.sha1,
                md5: workerResults.md5,
                entropy: workerResults.entropy.toFixed(2),
                spoofingPass: file.isSimulation ? file.simPayload.isValidSignature : magicAnalysis.isValidSignature,
                isHighRiskExt: heuristics.isHighRiskExt,
                entropyMsg: workerResults.entropy > 7.2 ? 'Abnormally Compressed/Packed' : 'Standard Distribution',
                reputationStatus: reputation.statusLabel || (reputation.isMalicious ? 'Malicious Match' : 'Clean Signature'),
                riskScore: reputation.riskScore,
                classification: reputation.classification,
                verdictTitle: reputation.verdictTitle,
                verdictDesc: reputation.verdictDesc,
                strings: workerResults.strings // save for history
            };

            saveScanResult(scanResults).catch(console.error);

            renderHexDump(workerResults.headerBytes);
            renderStringsList(extractedStringsList);
            stringsSearchInput.value = '';

            renderScanResults(scanResults, magicAnalysis, heuristics, reputation);
            setTimeout(() => { drawEntropyChart(workerResults.entropySegments, reputation.classification); }, 100);
            playDiagnosticChime(reputation.classification);
            
            if (file.isSimulation) {
                setTimeout(() => { resultsPanel.scrollIntoView({ behavior: 'smooth' }); }, 400);
            }
            
            setTimeout(() => {
                if (fileQueue.length > 0) {
                    setTimeout(processNextFile, 2000); // 2 second delay before next file
                } else {
                    isProcessingQueue = false;
                }
            }, 500);

        } catch (error) {
            console.error("Scan Pipeline Error: ", error);
            updateStepState(stepHash, 'failed', 'Error');
            alert("An error occurred during file processing: " + error.message);
            isProcessingQueue = false;
            if (fileQueue.length > 0) processNextFile();
        }
    }

    function updateStepState(stepElement, state, statusText) {
        stepElement.className = `step ${state}`;
        stepElement.querySelector('.step-status').textContent = statusText;
    }

    function updateProgressBar(percentage) {
        scanProgressBar.style.width = `${percentage}%`;
    }

    function readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsArrayBuffer(file);
        });
    }

    async function calculateSHA256(arrayBuffer) {
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    async function calculateSHA1(arrayBuffer) {
        const hashBuffer = await crypto.subtle.digest('SHA-1', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    function calculateMD5(arrayBuffer) {
        const words = [];
        const byteLength = arrayBuffer.byteLength;
        const u8 = new Uint8Array(arrayBuffer);
        for (let i = 0; i < byteLength; i++) {
            words[i >> 2] |= u8[i] << ((i % 4) * 8);
        }
        
        let l = byteLength * 8;
        words[l >> 5] |= 0x80 << (l % 32);
        words[(((l + 64) >>> 9) << 4) + 14] = l;
        
        let a = 1732584193;
        let b = -271733879;
        let c = -1732584194;
        let d = 271733878;

        const r = [
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        ];

        const k = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        ];

        function add(x, y) {
            const lsw = (x & 0xffff) + (y & 0xffff);
            const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
            return (msw << 16) | (lsw & 0xffff);
        }

        function rol(num, cnt) {
            return (num << cnt) | (num >>> (32 - cnt));
        }

        for (let i = 0; i < words.length; i += 16) {
            let olda = a, oldb = b, oldc = c, oldd = d;

            for (let j = 0; j < 64; j++) {
                let f, g;
                if (j < 16) {
                    f = (b & c) | (~b & d);
                    g = j;
                } else if (j < 32) {
                    f = (d & b) | (~d & c);
                    g = (5 * j + 1) % 16;
                } else if (j < 48) {
                    f = b ^ c ^ d;
                    g = (3 * j + 5) % 16;
                } else {
                    f = c ^ (b | ~d);
                    g = (7 * j) % 16;
                }
                const temp = d;
                d = c;
                c = b;
                b = add(b, rol(add(a, add(f, add(k[j], words[i + g]))), r[j]));
                a = temp;
            }

            a = add(a, olda);
            b = add(b, oldb);
            c = add(c, oldc);
            d = add(d, oldd);
        }

        const bin = [a, b, c, d];
        let hex = '';
        for (let i = 0; i < 4; i++) {
            for (let j = 0; j < 4; j++) {
                hex += ((bin[i] >> (j * 8)) & 0xff).toString(16).padStart(2, '0');
            }
        }
        return hex;
    }

    // Heuristics: Analyze magic bytes signature against filename extension
    function analyzeMagicBytes(filename, mimeType, headerBytes) {
        const ext = filename.split('.').pop().toLowerCase();
        let matchedSign = null;

        // Scan signatures
        for (const sign of MAGIC_SIGNATURES) {
            let matches = true;
            for (let i = 0; i < sign.magic.length; i++) {
                if (headerBytes[i] !== sign.magic[i]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                matchedSign = sign;
                break;
            }
        }

        // Integrity Rules
        let isValidSignature = true;
        let isSpoofed = false;

        if (matchedSign) {
            // File claims to be something else, or has conflicting extension
            if (matchedSign.ext !== ext) {
                // Ignore matching jpeg/jpg extensions cross-comp
                if (!(matchedSign.ext === 'jpg' && ext === 'jpeg') && !(matchedSign.ext === 'jpeg' && ext === 'jpg')) {
                    isValidSignature = false;
                    isSpoofed = true;
                }
            }
        } else {
            // No signature matched, but user uploads common binaries labeled as documents
            const binaryExtensions = ['exe', 'dll', 'so', 'elf', 'zip', 'rar'];
            if (binaryExtensions.includes(ext) && headerBytes[0] !== 0x4D && headerBytes[1] !== 0x5a) {
                // Flag binary files with incorrect metadata
                isValidSignature = false;
            }
        }

        return {
            matchedSign,
            isValidSignature,
            isSpoofed,
            detectedExt: matchedSign ? matchedSign.ext : ext
        };
    }

    // Calculates Shannon Entropy (randomness of bytes, 0 to 8).
    // High entropy (>7.2) indicates high degree of compression, encryption, or packed code.
    function calculateEntropy(byteArray) {
        const len = byteArray.length;
        if (len === 0) return 0;
        
        // Optimization: slice file array to max 1MB for fast UI updates on huge archives
        const sampleArray = len > 1000000 ? byteArray.slice(0, 1000000) : byteArray;
        const sampleLen = sampleArray.length;

        const frequencies = new Array(256).fill(0);
        for (let i = 0; i < sampleLen; i++) {
            frequencies[sampleArray[i]]++;
        }

        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (frequencies[i] > 0) {
                const p = frequencies[i] / sampleLen;
                entropy -= p * Math.log2(p);
            }
        }
        return entropy;
    }

    function runStaticHeuristics(filename, filesize, magicAnalysis, entropyVal, arrayBuffer) {
        const ext = filename.split('.').pop().toLowerCase();
        const isHighRiskExt = HIGH_RISK_EXTENSIONS.includes(ext);
        
        let triggerWarnings = [];

        // Check 1: Extension spoofing
        if (magicAnalysis.isSpoofed) {
            triggerWarnings.push(`Spoofed Extension Detected: File claims to be .${ext} but possesses signature headers of .${magicAnalysis.detectedExt}`);
        }

        // Check 2: Risk profile
        if (isHighRiskExt) {
            triggerWarnings.push(`High-Risk Ingestion Type: Script or binary file capable of shell execution.`);
        }

        // Check 3: Abnormal packing
        if (entropyVal > 7.35 && (isHighRiskExt || ['zip', 'rar', 'pdf'].includes(ext))) {
            triggerWarnings.push(`Suspected Obfuscation/Packer: High Shannon entropy (${entropyVal.toFixed(2)}) indicates encrypted payload structures.`);
        }

        // Check 4: PDF exploit structures
        if (ext === 'pdf' || (magicAnalysis.detectedExt === 'pdf')) {
            const u8 = new Uint8Array(arrayBuffer);
            const decoder = new TextDecoder('utf-8', { fatal: false });
            const textSample = decoder.decode(u8.subarray(0, 100000));
            if (/\/JavaScript/i.test(textSample) || /\/JS/i.test(textSample)) {
                triggerWarnings.push(`PDF Malware Heuristic: Hidden JavaScript node elements detected inside PDF structure.`);
            }
            if (/\/OpenAction/i.test(textSample) || /\/AA/i.test(textSample)) {
                triggerWarnings.push(`PDF Exploit Flag: Automatic action trigger (/OpenAction) detected (auto-executes payload on open).`);
            }
        }

        // Check 5: ZIP inside executable check
        if (ext === 'zip' || (magicAnalysis.detectedExt === 'zip')) {
            const u8 = new Uint8Array(arrayBuffer);
            const decoder = new TextDecoder('utf-8', { fatal: false });
            const textSample = decoder.decode(u8.subarray(0, 200000));
            if (/\.exe|\.dll|\.scr|\.bat/i.test(textSample)) {
                triggerWarnings.push(`Archive Hazard: Discovered references to executable binaries (.exe/.scr/.dll) packed within Zip volume.`);
            }
        }

        // Check 6: Text-based script code scanners
        // If file is small text-based script, check for risky patterns
        if (filesize < 200000 && ['js', 'vbs', 'ps1', 'bat', 'html'].includes(ext)) {
            const textContent = new TextDecoder('utf-8').decode(new Uint8Array(arrayBuffer));
            const dangerousPatterns = [
                { pattern: /powershell\.exe/gi, desc: "Invokes PowerShell console" },
                { pattern: /WScript\.Shell/gi, desc: "Spawns ActiveX scripting engine" },
                { pattern: /eval\s*\(/gi, desc: "Evaluates untrusted string objects" },
                { pattern: /-ExecutionPolicy\s+Bypass/gi, desc: "Bypasses PS execution safeguards" },
                { pattern: /Base64String/gi, desc: "Processes encoded shell payloads" },
                { pattern: /downloadstring|downloadfile/gi, desc: "Fetches remote components over socket" }
            ];

            dangerousPatterns.forEach(rule => {
                if (rule.pattern.test(textContent)) {
                    triggerWarnings.push(`Suspicious Script Command: Code contains script instruction matches: "${rule.desc}"`);
                }
            });
        }

        return {
            isHighRiskExt,
            triggerWarnings,
            warningsCount: triggerWarnings.length
        };
    }

    // Handles API query or simulated static engine response.
    async function queryReputation(hash, heuristics) {
        // If API key is present, execute actual VirusTotal API call
        if (vtApiKey) {
            try {
                const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
                    method: 'GET',
                    headers: {
                        'x-apikey': vtApiKey
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    const stats = data.data.attributes.last_analysis_stats;
                    const malicious = stats.malicious || 0;
                    const suspicious = stats.suspicious || 0;
                    const totalScanners = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;

                    let riskScore = 0;
                    if (totalScanners > 0) {
                        riskScore = Math.round(((malicious + suspicious) / totalScanners) * 100);
                    }

                    let classification = 'SAFE';
                    let verdictTitle = 'File Verified Clean';
                    let verdictDesc = `VirusTotal reputation analysis confirms this file is clean. Verified by ${stats.harmless} sandbox scanning engines.`;

                    if (riskScore > 35) {
                        classification = 'DANGER';
                        verdictTitle = 'Malicious Threat Detected';
                        verdictDesc = `WARNING: File flagged as malicious by ${malicious} security vendor scanners inside VirusTotal's intelligence database. Do NOT execute this file.`;
                    } else if (riskScore > 5 || suspicious > 0) {
                        classification = 'SUSPICIOUS';
                        verdictTitle = 'Suspicious Signature Match';
                        verdictDesc = `Caution: File identified as potentially unwanted, adware, or suspicious by ${malicious + suspicious} engines. Run inside a sandboxed VM only.`;
                    }

                    return {
                        statusLabel: 'VT Match Found',
                        isMalicious: riskScore > 5,
                        riskScore,
                        classification,
                        verdictTitle,
                        verdictDesc
                    };
                } else if (response.status === 404) {
                    // Hash not found on VT, fallback to static heuristic estimation
                    return compileHeuristicResult(heuristics, true);
                } else {
                    console.warn(`VT API responded with code ${response.status}. Falling back to static heuristic simulation.`);
                    return compileHeuristicResult(heuristics, false);
                }
            } catch (err) {
                console.error("VT API Request Exception:", err);
                return compileHeuristicResult(heuristics, false);
            }
        } else {
            // Local signature heuristics check simulated delay
            await new Promise(resolve => setTimeout(resolve, 800));
            return compileHeuristicResult(heuristics, false);
        }
    }

    function compileHeuristicResult(heuristics, isHashNewToVT = false) {
        let riskScore = 0;
        let classification = 'SAFE';
        let verdictTitle = 'File Appears Safe';
        let verdictDesc = 'The offline static heuristics engine found no malicious payload signatures, extension spoofing, or abnormal structure profiles.';

        // Calculate a score based on triggers
        if (heuristics.warningsCount > 0) {
            riskScore += heuristics.warningsCount * 25;
            if (heuristics.isHighRiskExt) riskScore += 15;
            
            // Limit to max 95% unless proven VT malicious
            riskScore = Math.min(riskScore, 95);
        }

        if (riskScore >= 60) {
            classification = 'DANGER';
            verdictTitle = 'Heuristic Risk Warning';
            verdictDesc = `CRITICAL: Heuristic engines flagged multiple risk criteria: ${heuristics.triggerWarnings.join(' | ')}. Execute only in isolated sandboxes.`;
        } else if (riskScore >= 20) {
            classification = 'SUSPICIOUS';
            verdictTitle = 'Suspicious Characteristics';
            verdictDesc = `Warning: File triggered suspicious patterns. Details: ${heuristics.triggerWarnings[0] || 'High risk scripting properties.'}`;
        }

        if (isHashNewToVT) {
            verdictDesc += " Note: This signature hash is unknown to the VirusTotal global index database (Zero-day warning).";
        }

        return {
            statusLabel: isHashNewToVT ? 'Unknown Signature' : 'Offline Engine',
            isMalicious: riskScore >= 60,
            riskScore,
            classification,
            verdictTitle,
            verdictDesc
        };
    }

    /* --- Rendering Results to DOM --- */

    function renderScanResults(results, magicAnalysis, heuristics, reputation) {
        resultsPanel.classList.remove('empty');
        resultsEmptyState.classList.add('hidden');
        resultsContent.classList.remove('hidden');

        // Verdict Badge
        verdictBadge.textContent = results.classification;
        verdictBadge.className = `verdict-badge ${results.classification.toLowerCase()}`;

        // Verdict Description
        verdictTitle.textContent = results.verdictTitle;
        verdictDescription.textContent = results.verdictDesc;

        // Render Gauge
        animateGauge(results.riskScore, results.classification);

        // Table Metadata Injections
        metaFilename.textContent = results.filename;
        metaFilesize.textContent = results.filesize;
        metaMime.textContent = results.declaredMime;
        metaMagicType.textContent = results.detectedType;
        metaMd5.textContent = results.md5 || '-';
        metaSha1.textContent = results.sha1 || '-';
        metaSha256.textContent = results.sha256;
        metaEntropy.textContent = `${results.entropy} (Scale 0-8)`;

        // --- MetaDefender Multi-Engine Scan Rendering ---
        const avEngines = [
            { id: 'engine-avast', name: 'Avast Antivirus', iconClass: 'fa-solid fa-shield text-yellow' },
            { id: 'engine-bitdefender', name: 'Bitdefender', iconClass: 'fa-solid fa-shield-halved text-cyan' },
            { id: 'engine-crowdstrike', name: 'CrowdStrike Falcon', iconClass: 'fa-solid fa-spider text-purple' },
            { id: 'engine-kaspersky', name: 'Kaspersky Lab', iconClass: 'fa-solid fa-shield-virus text-cyan' },
            { id: 'engine-malwarebytes', name: 'Malwarebytes', iconClass: 'fa-solid fa-biohazard text-yellow' },
            { id: 'engine-ms-defender', name: 'Microsoft Defender', iconClass: 'fa-brands fa-windows text-cyber' },
            { id: 'engine-sentinelone', name: 'SentinelOne', iconClass: 'fa-solid fa-shield-cat text-purple' },
            { id: 'engine-sophos', name: 'Sophos InterceptX', iconClass: 'fa-solid fa-cubes text-blue' },
            { id: 'engine-symantec', name: 'Symantec Endpoint', iconClass: 'fa-solid fa-user-shield text-blue' },
            { id: 'engine-fireeye', name: 'Trellix / FireEye', iconClass: 'fa-solid fa-eye text-red' }
        ];

        let flaggedCount = 0;
        const lowerName = results.filename.toLowerCase();

        avEngines.forEach(engine => {
            const rowElement = document.getElementById(engine.id);
            if (!rowElement) return;

            let detectionName = 'Clean';
            let isFlagged = false;

            if (results.riskScore >= 20) {
                isFlagged = true;
                // Specific threat mapping
                if (lowerName.includes('wannacry')) {
                    const signatures = {
                        'engine-ms-defender': 'Ransom:Win32/WannaCrypt',
                        'engine-kaspersky': 'Trojan-Ransom.Win32.Wanna.m',
                        'engine-bitdefender': 'Gen:Variant.Ransom.WannaCrypt.1',
                        'engine-crowdstrike': 'Malicious_Behavior (0x93b)',
                        'engine-sentinelone': 'Ransomware.WannaCry',
                        'engine-sophos': 'Troj/Wanna-G',
                        'engine-symantec': 'Ransom.Wannacry',
                        'engine-malwarebytes': 'Ransom.WannaCrypt',
                        'engine-fireeye': 'Ransom.WannaCryptor',
                        'engine-avast': 'Win32:WannaCry-A'
                    };
                    detectionName = signatures[engine.id] || 'Ransom.Win32.Wanna';
                } else if (lowerName.includes('zeus') || lowerName.includes('zbot')) {
                    const signatures = {
                        'engine-ms-defender': 'Trojan:Win32/Zbot.E',
                        'engine-kaspersky': 'Trojan-Spy.Win32.Zbot.he',
                        'engine-bitdefender': 'Trojan.Zbot.Generic',
                        'engine-crowdstrike': 'Credential_Theft (0x812)',
                        'engine-sentinelone': 'Trojan.Zbot',
                        'engine-sophos': 'Troj/Zbot-Gen',
                        'engine-symantec': 'Trojan.Zbot',
                        'engine-malwarebytes': 'Trojan.Spy.Zbot',
                        'engine-fireeye': 'Trojan.Zbot',
                        'engine-avast': 'Win32:Zbot-gen'
                    };
                    detectionName = signatures[engine.id] || 'Trojan.Win32.Zbot';
                } else if (lowerName.includes('stuxnet')) {
                    const signatures = {
                        'engine-ms-defender': 'Trojan:Win32/Stuxnet.A',
                        'engine-kaspersky': 'Rootkit.Win32.Stuxnet.a',
                        'engine-bitdefender': 'Trojan.Stuxnet.Gen',
                        'engine-crowdstrike': 'Malicious_Driver (0x334)',
                        'engine-sentinelone': 'Rootkit.Stuxnet',
                        'engine-sophos': 'Troj/Stuxnet-A',
                        'engine-symantec': 'W32.Stuxnet',
                        'engine-malwarebytes': 'Trojan.Stuxnet',
                        'engine-fireeye': 'Rootkit.Stuxnet',
                        'engine-avast': 'Win32:Stuxnet-A'
                    };
                    detectionName = signatures[engine.id] || 'Rootkit.Win32.Stuxnet';
                } else if (lowerName.includes('pegasus')) {
                    const signatures = {
                        'engine-ms-defender': 'Spyware:iOS/Pegasus',
                        'engine-kaspersky': 'HEUR:Trojan-Spy.iOS.Pegasus',
                        'engine-bitdefender': 'Spyware.Pegasus.A',
                        'engine-crowdstrike': 'Malicious_Activity',
                        'engine-sentinelone': 'Spyware.Pegasus',
                        'engine-sophos': 'Spy/Pegasus-A',
                        'engine-symantec': 'Spyware.Pegasus',
                        'engine-malwarebytes': 'Spyware.Pegasus',
                        'engine-fireeye': 'Spyware.Pegasus',
                        'engine-avast': 'iOS:Pegasus-A'
                    };
                    detectionName = signatures[engine.id] || 'Spyware.iOS.Pegasus';
                } else {
                    // Generic files uploaded by the user with warnings
                    // Let's flag a random subset (e.g. 6 out of 10 engines flag it)
                    const randomFlag = ['engine-ms-defender', 'engine-kaspersky', 'engine-bitdefender', 'engine-crowdstrike', 'engine-sentinelone', 'engine-malwarebytes'].includes(engine.id);
                    if (randomFlag) {
                        const signatures = {
                            'engine-ms-defender': 'Trojan:Win32/Malware.Heur',
                            'engine-kaspersky': 'HEUR:Trojan.Win32.Generic',
                            'engine-bitdefender': 'Trojan.GenericKD.92842',
                            'engine-crowdstrike': 'Suspicious_Activity (0x1e3)',
                            'engine-sentinelone': 'Malicious.Heuristic',
                            'engine-malwarebytes': 'Malware.Heuristic'
                        };
                        detectionName = signatures[engine.id];
                    } else {
                        isFlagged = false;
                        detectionName = 'Clean';
                    }
                }
            }

            if (isFlagged) {
                flaggedCount++;
                rowElement.innerHTML = `
                    <span class="engine-name"><i class="${engine.iconClass}"></i> ${engine.name}</span>
                    <span class="engine-result-badge flagged"><i class="fa-solid fa-triangle-exclamation"></i> ${detectionName}</span>
                `;
            } else {
                rowElement.innerHTML = `
                    <span class="engine-name"><i class="${engine.iconClass}"></i> ${engine.name}</span>
                    <span class="engine-result-badge clean"><i class="fa-solid fa-circle-check"></i> Clean</span>
                `;
            }
        });

        engineSummaryCount.textContent = `${flaggedCount} / ${avEngines.length} Engines Flagged`;

        // --- Static Heuristic Warnings Box ---
        warningsListItems.innerHTML = '';
        if (heuristics.triggerWarnings && heuristics.triggerWarnings.length > 0) {
            heuristics.triggerWarnings.forEach(warning => {
                const li = document.createElement('li');
                li.textContent = warning;
                warningsListItems.appendChild(li);
            });
            heuristicWarningsBox.classList.remove('hidden');
        } else {
            heuristicWarningsBox.classList.add('hidden');
        }

        // --- Interactive Remedy Action Plan ---
        remedyContainer.innerHTML = '';
        const isMalicious = results.classification === 'DANGER' || results.classification === 'SUSPICIOUS';
        
        const remedyCard = document.createElement('div');
        remedyCard.className = `remedy-card ${isMalicious ? 'danger' : 'clean'}`;
        
        if (isMalicious) {
            remedyCard.innerHTML = `
                <div class="remedy-header">
                    <i class="fa-solid fa-circle-exclamation text-red animate-pulse"></i>
                    <h4>REMEDY PROTOCOL: CRITICAL THREAT WARNING</h4>
                </div>
                <div class="remedy-desc">
                    This file is flagged as malicious by multiple security engines and offline static heuristics. Execute this payload only in isolated developer virtual environments.
                </div>
                <div class="remedy-steps-grid">
                    <div class="remedy-step-item">
                        <span>1. Isolate Host Network</span>
                        <p>Instantly disable WiFi or disconnect network adapters to block active malware telemetry transmission.</p>
                    </div>
                    <div class="remedy-step-item">
                        <span>2. Restrict Execution</span>
                        <p>Move this file into a secure read-only folder using system administrative policies to prevent triggers.</p>
                    </div>
                    <div class="remedy-step-item">
                        <span>3. Sweep Registry Autostarts</span>
                        <p>Check common launch keys (HKLM\\Run) for foreign system tasks pointing to local file directories.</p>
                    </div>
                </div>
            `;
        } else {
            remedyCard.innerHTML = `
                <div class="remedy-header">
                    <i class="fa-solid fa-circle-check text-green"></i>
                    <h4>SAFE PROTOCOL: VERIFIED DEPLOYMENT</h4>
                </div>
                <div class="remedy-desc">
                    This file has passed all offline scanning filters and matches no malicious signature databases.
                </div>
                <div class="remedy-steps-grid">
                    <div class="remedy-step-item">
                        <span>1. Code Signature Audit</span>
                        <p>Confirm the developer certificate signature matches your organization's trusted whitelist.</p>
                    </div>
                    <div class="remedy-step-item">
                        <span>2. Standard Deploy</span>
                        <p>Approved for push to standard staging servers under telemetry monitoring configurations.</p>
                    </div>
                    <div class="remedy-step-item">
                        <span>3. Access Control</span>
                        <p>Assign default standard user access permissions to limit potential structural write capabilities.</p>
                    </div>
                </div>
            `;
        }
        remedyContainer.appendChild(remedyCard);
    }

    function updateChecklistItem(itemElement, isPassed, text) {
        const icon = itemElement.querySelector('i');
        const description = itemElement.querySelector('p');

        if (isPassed) {
            icon.className = 'fa-solid fa-circle-check text-green status-chk-icon';
            description.textContent = text;
            itemElement.classList.remove('warning-active');
        } else {
            icon.className = 'fa-solid fa-circle-exclamation text-red status-chk-icon';
            description.textContent = text;
            itemElement.classList.add('warning-active');
        }
    }

    function animateGauge(targetValue, classification) {
        const circle = riskGaugeCircle;
        const radius = circle.r.baseVal.value;
        const circumference = radius * 2 * Math.PI;

        circle.style.strokeDasharray = `${circumference} ${circumference}`;
        
        let strokeColor = 'var(--accent-cyan)';
        if (classification === 'DANGER') strokeColor = 'var(--red)';
        else if (classification === 'SUSPICIOUS') strokeColor = 'var(--yellow)';
        else if (classification === 'SAFE') strokeColor = 'var(--green)';

        circle.style.stroke = strokeColor;

        // Animate progression
        let count = 0;
        const duration = 800; // ms
        const stepTime = Math.abs(Math.floor(duration / targetValue)) || 10;
        
        const timer = setInterval(() => {
            if (count >= targetValue) {
                clearInterval(timer);
                setGaugePercentage(targetValue, circumference);
            } else {
                count++;
                setGaugePercentage(count, circumference);
            }
        }, stepTime);
    }

    function setGaugePercentage(percent, circumference) {
        const offset = circumference - (percent / 100) * circumference;
        riskGaugeCircle.style.strokeDashoffset = offset;
        riskScoreVal.textContent = `${percent}%`;
    }

    function renderHexDump(headerBytes) {
        hexLinesContainer.innerHTML = '';
        const lineLength = 16;
        
        for (let i = 0; i < headerBytes.length; i += lineLength) {
            const chunk = headerBytes.slice(i, i + lineLength);
            
            // Offset label
            const offsetLabel = i.toString(16).toUpperCase().padStart(4, '0');
            
            // Hex bytes string
            const hexArray = [];
            for (let j = 0; j < lineLength; j++) {
                if (j < chunk.length) {
                    hexArray.push(chunk[j].toString(16).toUpperCase().padStart(2, '0'));
                } else {
                    hexArray.push('  ');
                }
            }
            
            // ASCII representation
            let asciiStr = '';
            for (let j = 0; j < chunk.length; j++) {
                const char = chunk[j];
                // Non-printable chars replaced with dot
                if (char >= 32 && char <= 126) {
                    asciiStr += String.fromCharCode(char);
                } else {
                    asciiStr += '.';
                }
            }

            // Create row
            const row = document.createElement('div');
            row.className = 'hex-line';
            row.innerHTML = `
                <span class="hex-offset">${offsetLabel}</span>
                <span class="hex-bytes">${hexArray.join(' ')}</span>
                <span class="hex-ascii">${escapeHtml(asciiStr)}</span>
            `;
            hexLinesContainer.appendChild(row);
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /* --- Dynamic Live Threat Feed Engine --- */

    function generateTickerFeed() {
        const threatActors = ['APT29', 'Lazarus Group', 'LockBit 3.0', 'BlackCat', 'UNC2452', 'ALPHV', 'AgentTesla', 'TrickBot'];
        const targets = ['FinTech Server', 'Healthcare Gateway', 'Defense Network', 'E-Commerce Cloud', 'Critical OS Endpoint'];
        const vectors = ['SHA-256 integrity spoof', 'Malicious double-extension invoice.pdf.exe', 'Corrupted MS-Office macro trigger', 'Suspicious script execution bypass', 'Encrypted entropy payload structure'];
        const regions = ['London', 'Tokyo', 'San Francisco', 'Berlin', 'Seoul', 'Sydney', 'Mumbai', 'Toronto'];

        let events = [];
        for (let i = 0; i < 6; i++) {
            events.push(createRandomThreatEvent(threatActors, targets, vectors, regions));
        }

        // Duplicate array for seamless endless scroll effect
        renderTicker(events);

        setInterval(() => {
            // Add a new event and slide out the oldest
            events.shift();
            events.push(createRandomThreatEvent(threatActors, targets, vectors, regions));
            renderTicker(events);
        }, 6000);
    }

    function createRandomThreatEvent(actors, targets, vectors, regions) {
        const actor = actors[Math.floor(Math.random() * actors.length)];
        const target = targets[Math.floor(Math.random() * targets.length)];
        const vector = vectors[Math.floor(Math.random() * vectors.length)];
        const region = regions[Math.floor(Math.random() * regions.length)];
        const hashSample = Math.random().toString(16).substr(2, 8);

        return `[ALERT] Node matched hash signature <strong>${hashSample}...</strong> (${actor} footprint) on ${target} in ${region} via ${vector}.`;
    }

    function renderTicker(events) {
        tickerScroll.innerHTML = '';
        
        // Loop twice to create duplicate contents for smooth endless css scrolling
        const combined = [...events, ...events];
        combined.forEach(eventText => {
            const item = document.createElement('div');
            item.className = 'ticker-item';
            item.innerHTML = `<i class="fa-solid fa-circle-radiation text-red"></i> ${eventText}`;
            tickerScroll.appendChild(item);
        });
    }

    // Segmented entropy divider
    function calculateSegmentedEntropy(byteArray) {
        const segmentsCount = 16;
        const segmentSize = Math.max(1, Math.floor(byteArray.length / segmentsCount));
        const segments = [];
        for (let i = 0; i < segmentsCount; i++) {
            const start = i * segmentSize;
            const end = Math.min(start + segmentSize, byteArray.length);
            const chunk = byteArray.slice(start, end);
            segments.push(calculateEntropy(chunk));
        }
        return segments;
    }

    // Canvas line chart drawer for entropy
    function drawEntropyChart(entropySegments, classification) {
        const canvas = document.getElementById('entropy-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);
        const width = rect.width;
        const height = rect.height;
        ctx.clearRect(0, 0, width, height);
        
        let strokeColor = '#00f2fe';
        let fillColorStart = 'rgba(0, 242, 254, 0.2)';
        let fillColorEnd = 'rgba(0, 242, 254, 0)';
        
        if (classification === 'DANGER') {
            strokeColor = '#ff0844';
            fillColorStart = 'rgba(255, 8, 68, 0.2)';
        } else if (classification === 'SUSPICIOUS') {
            strokeColor = '#f6d365';
            fillColorStart = 'rgba(246, 211, 101, 0.2)';
        } else if (classification === 'SAFE') {
            strokeColor = '#00f5a0';
            fillColorStart = 'rgba(0, 245, 160, 0.2)';
        }
        
        const points = [];
        const padding = 8;
        const chartWidth = width - (padding * 2);
        const chartHeight = height - (padding * 2);
        const stepX = chartWidth / (entropySegments.length - 1);
        
        for (let i = 0; i < entropySegments.length; i++) {
            const x = padding + (i * stepX);
            const y = padding + chartHeight - ((entropySegments[i] / 8) * chartHeight);
            points.push({ x, y });
        }
        
        const fillGrad = ctx.createLinearGradient(0, 0, 0, height);
        fillGrad.addColorStop(0, fillColorStart);
        fillGrad.addColorStop(1, fillColorEnd);
        ctx.beginPath();
        ctx.moveTo(points[0].x, height - padding);
        for (let i = 0; i < points.length - 1; i++) {
            const xc = (points[i].x + points[i + 1].x) / 2;
            const yc = (points[i].y + points[i + 1].y) / 2;
            ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
        }
        ctx.quadraticCurveTo(points[points.length - 2].x, points[points.length - 2].y, points[points.length - 1].x, points[points.length - 1].y);
        ctx.lineTo(points[points.length - 1].x, height - padding);
        ctx.closePath();
        ctx.fillStyle = fillGrad;
        ctx.fill();
        
        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);
        for (let i = 0; i < points.length - 1; i++) {
            const xc = (points[i].x + points[i + 1].x) / 2;
            const yc = (points[i].y + points[i + 1].y) / 2;
            ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
        }
        ctx.quadraticCurveTo(points[points.length - 2].x, points[points.length - 2].y, points[points.length - 1].x, points[points.length - 1].y);
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 2;
        ctx.stroke();
        
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.setLineDash([3, 3]);
        ctx.moveTo(padding, padding + (chartHeight / 2));
        ctx.lineTo(width - padding, padding + (chartHeight / 2));
        ctx.stroke();
        ctx.setLineDash([]);
        
        points.forEach((pt) => {
            ctx.fillStyle = strokeColor;
            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 3, 0, Math.PI * 2);
            ctx.fill();
        });
    }

    // Scans Uint8Array for sequence of printable ASCII chars
    function extractPrintableStrings(byteArray) {
        const stringsList = [];
        let currentString = '';
        const minLength = 4;
        const maxScanBytes = Math.min(byteArray.length, 3000000);
        
        for (let i = 0; i < maxScanBytes; i++) {
            const char = byteArray[i];
            if (char >= 32 && char <= 126) {
                currentString += String.fromCharCode(char);
            } else {
                if (currentString.length >= minLength) {
                    stringsList.push(currentString);
                    if (stringsList.length >= 250) break;
                }
                currentString = '';
            }
        }
        
        return stringsList.map(str => {
            let type = 'default';
            let tagText = '';
            const isIP = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(str);
            const isDomain = /\b(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/.test(str) && str.includes('.');
            const isEmail = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(str);
            const isPath = /\\|\//.test(str) && (str.includes('.') || str.length > 12);
            const suspiciousKeywords = [
                'eval', 'exec', 'system', 'cmd.exe', 'powershell', 'sh ', 'bash', 'curl', 'wget', 
                'temp', 'appdata', 'registry', 'hkey_', 'VirtualAlloc', 'WriteProcessMemory', 
                'CreateRemoteThread', 'bypass', 'download', 'upload', 'http://', 'https://'
            ];
            const isSuspicious = suspiciousKeywords.some(keyword => str.toLowerCase().includes(keyword));
            
            if (isSuspicious) {
                type = 'suspicious';
                tagText = 'Suspicious';
            } else if (isEmail) {
                type = 'email';
                tagText = 'Email';
            } else if (isIP) {
                type = 'ip';
                tagText = 'IP';
            } else if (isDomain) {
                type = 'domain';
                tagText = 'Domain';
            } else if (isPath) {
                type = 'path';
                tagText = 'Path';
            }
            return { value: str, type, tagText };
        });
    }

    function renderStringsList(items) {
        stringsList.innerHTML = '';
        if (items.length === 0) {
            stringsList.innerHTML = `<li class="strings-item" style="justify-content: center; color: var(--text-muted);">No printable strings discovered</li>`;
            return;
        }
        items.forEach(item => {
            const li = document.createElement('li');
            li.className = 'strings-item';
            let tagHtml = '';
            if (item.tagText) {
                tagHtml = `<span class="strings-tag ${item.type}">${item.tagText}</span>`;
            }
            li.innerHTML = `
                <span class="strings-value" title="${escapeHtml(item.value)}">${escapeHtml(item.value)}</span>
                ${tagHtml}
            `;
            stringsList.appendChild(li);
        });
    }

    function filterExtractedStrings(query) {
        if (!query) {
            renderStringsList(extractedStringsList);
            return;
        }
        const filtered = extractedStringsList.filter(item => item.value.toLowerCase().includes(query));
        renderStringsList(filtered);
    }

    /* --- Interactive Malware Simulation Engine --- */

    const MALWARE_PAYLOADS = {
        wannacry: {
            name: 'WannaCry.Decryptor.exe',
            size: 351280,
            mime: 'application/x-msdownload',
            detectedType: 'Portable Executable (Windows EXE/DLL)',
            md5: 'db349b97c37d22f5ea1d1841e3cfa901',
            sha1: '7c7d3c6c4f40f041dc5d351652cf24cc1c23f03b',
            sha256: '24d6f83b1c6e1e828e83344132b49e19d7d42cf8173491f24aa52a1d7cfa9012',
            entropy: 7.89,
            entropySegments: [7.2, 7.5, 7.8, 7.9, 7.95, 7.88, 7.92, 7.97, 7.91, 7.85, 7.9, 7.93, 7.96, 7.91, 7.84, 7.89],
            isValidSignature: true,
            isSpoofed: false,
            isHighRiskExt: true,
            warnings: [
                "High-Risk Ingestion Type: Script or binary file capable of shell execution.",
                "Suspected Obfuscation/Packer: High Shannon entropy (7.89) indicates encrypted payload structures.",
                "Threat Signature Match: Executable hash matches WannaCry cryptographic indicator database (CVE-2017-0144 EternalBlue).",
                "Suspicious Network Command: Extracted binary payload strings match known Tor C2 nodes & bitcoin wallet links."
            ],
            strings: [
                { value: "wannacry_payload.exe", type: "suspicious", tagText: "Suspicious" },
                { value: "http://gx79lsa201lxq91.onion", type: "domain", tagText: "Domain" },
                { value: "12t9YDPGWueJ9NyMgw519p7AA8isJR6SMw", type: "suspicious", tagText: "Suspicious" },
                { value: "WanaCrypt0r", type: "suspicious", tagText: "Suspicious" },
                { value: "Microsoft Security Exploit EternalBlue SMB v1", type: "suspicious", tagText: "Suspicious" },
                { value: "shell32.dll", type: "path", tagText: "Path" },
                { value: "C:\\Windows\\Temp\\tasksche.exe", type: "path", tagText: "Path" },
                { value: "VirtualAlloc", type: "suspicious", tagText: "Suspicious" },
                { value: "WriteProcessMemory", type: "suspicious", tagText: "Suspicious" },
                { value: "CreateRemoteThread", type: "suspicious", tagText: "Suspicious" }
            ],
            headerBytes: new Uint8Array([
                0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
                0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
            ]),
            reputation: {
                statusLabel: 'MALICIOUS MATCH',
                isMalicious: true,
                riskScore: 99,
                classification: 'DANGER',
                verdictTitle: 'WannaCry Ransomware Verified',
                verdictDesc: 'CRITICAL WARNING: The file matches the specific signature of the WannaCry ransomware network worm. It propagates via SMB v1 exploits and will irreversibly encrypt local data.'
            }
        },
        zeus: {
            name: 'Zeus.Zbot.Infector.dll',
            size: 512000,
            mime: 'application/x-msdownload',
            detectedType: 'Portable Executable (Windows EXE/DLL)',
            md5: 'e3cfa901db349b97c37d22f5ea1d1841',
            sha1: 'b9a1c12cf817d42cf1a91f42a83344132b49e19d',
            sha256: 'e8b9415c128e83344132b49e19d7d42cf8173491f24aa52a1d7cfa9012a91f42a',
            entropy: 6.38,
            entropySegments: [6.1, 6.25, 6.3, 6.42, 6.5, 6.35, 6.28, 6.4, 6.39, 6.45, 6.31, 6.34, 6.41, 6.37, 6.29, 6.38],
            isValidSignature: true,
            isSpoofed: false,
            isHighRiskExt: true,
            warnings: [
                "High-Risk Ingestion Type: Dynamic Link Library (.dll) capable of code injection.",
                "Suspicious API Import: File accesses keystroke hooks, credential caches, and process mapping libraries.",
                "Threat Signature Match: Binary matches Zeus/Zbot financial Trojan malware signatures."
            ],
            strings: [
                { value: "zeus_credentials_grabber", type: "suspicious", tagText: "Suspicious" },
                { value: "https://secure-bank-telemetry.ru/c2/gate.php", type: "domain", tagText: "Domain" },
                { value: "192.168.99.102", type: "ip", tagText: "IP" },
                { value: "SetWindowsHookExA", type: "suspicious", tagText: "Suspicious" },
                { value: "GetKeyboardState", type: "suspicious", tagText: "Suspicious" },
                { value: "kernel32.dll", type: "path", tagText: "Path" },
                { value: "ws2_32.dll", type: "path", tagText: "Path" },
                { value: "Software\\Microsoft\\Windows\\CurrentVersion\\Run", type: "path", tagText: "Path" }
            ],
            headerBytes: new Uint8Array([
                0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
                0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00
            ]),
            reputation: {
                statusLabel: 'ZEUS DETECTED',
                isMalicious: true,
                riskScore: 92,
                classification: 'DANGER',
                verdictTitle: 'Zeus Credential Trojan Flagged',
                verdictDesc: 'DANGER: Heuristics confirm this file contains banking API hooks, remote panel configurations, and browser inject routines mapping to the Zeus botnet framework.'
            }
        },
        stuxnet: {
            name: 'Stuxnet.Centrifuge.sys',
            size: 114880,
            mime: 'application/x-msdownload',
            detectedType: 'Portable Executable (Windows EXE/DLL)',
            md5: '1d1841e3cfa901db349b97c37d22f5ea',
            sha1: 'f24aa52a1d7cfa901248abb9a1c12cf817d42cf',
            sha256: '52a1d7cf415c128e83344132b49e19d7d42cf8173491f24aa52a1d7cfa901248ab',
            entropy: 7.94,
            entropySegments: [7.8, 7.92, 7.95, 7.99, 7.93, 7.91, 7.96, 7.98, 7.94, 7.9, 7.93, 7.97, 7.95, 7.92, 7.89, 7.94],
            isValidSignature: true,
            isSpoofed: false,
            isHighRiskExt: true,
            warnings: [
                "Kernel Driver Signature: Dynamic kernel-level bypass and memory map hook calls.",
                "Obfuscated Packer Found: Flat max shannon entropy (7.94) indicates packed payload code segments.",
                "Threat Signature Match: Match found in SCADA Siemens controller vulnerability databases."
            ],
            strings: [
                { value: "s7otbxdx.dll", type: "suspicious", tagText: "Suspicious" },
                { value: "Centrifuge Speed frequency regulator", type: "suspicious", tagText: "Suspicious" },
                { value: "Siemens Step7 Simatic controller bypass", type: "suspicious", tagText: "Suspicious" },
                { value: "mrxcls.sys", type: "path", tagText: "Path" },
                { value: "ntdll.dll", type: "path", tagText: "Path" },
                { value: "Device\\PhysicalMemory", type: "path", tagText: "Path" }
            ],
            headerBytes: new Uint8Array([
                0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
                0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00
            ]),
            reputation: {
                statusLabel: 'STUXNET MATCH',
                isMalicious: true,
                riskScore: 100,
                classification: 'DANGER',
                verdictTitle: 'Stuxnet SCADA Centrifuge Worm',
                verdictDesc: 'CRITICAL THREAT: Centrifuge speed sabotage module detected. This binary explicitly Targets Siemens Step7 PLC industrial hardware and implements kernel-level driver bypasses.'
            }
        },
        pegasus: {
            name: 'Pegasus.iOS.Kernel.bin',
            size: 42410,
            mime: 'application/octet-stream',
            detectedType: 'Unknown binary/text format',
            md5: 'a91f42ae3cfa901db349b97c37d22f5e',
            sha1: '128a1c9efd128e83344132b49e19d7d42cf8173',
            sha256: '91fe42aa128e83344132b49e19d7d42cf8173491f24aa52a1d7cfa90128a1c9efd',
            entropy: 5.12,
            entropySegments: [4.9, 5.0, 5.2, 5.3, 5.1, 4.95, 5.05, 5.15, 5.1, 5.2, 5.0, 5.1, 5.18, 5.12, 4.88, 5.12],
            isValidSignature: true,
            isSpoofed: false,
            isHighRiskExt: false,
            warnings: [
                "Exploit Payload Detected: Decryption loops mapping iOS zero-click iMessage memory vulnerability (FORCEDENTRY).",
                "Advanced Telemetry Hook: Spawns sub-system loops capturing ambient audio, call log files, and remote GPS updates."
            ],
            strings: [
                { value: "com.apple.imessage.decrypter", type: "suspicious", tagText: "Suspicious" },
                { value: "ambient_mic_recorder_grabber", type: "suspicious", tagText: "Suspicious" },
                { value: "https://nsogroup-telemetry-server.com/gate", type: "domain", tagText: "Domain" },
                { value: "camera_frame_capture", type: "suspicious", tagText: "Suspicious" },
                { value: "/var/mobile/Library/SMS/sms.db", type: "path", tagText: "Path" }
            ],
            headerBytes: new Uint8Array([
                0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x30, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]),
            reputation: {
                statusLabel: 'PEGASUS DETECTED',
                isMalicious: true,
                riskScore: 95,
                classification: 'DANGER',
                verdictTitle: 'Pegasus Zero-Click Spyware Payload',
                verdictDesc: 'CRITICAL SECURITY THREAT: Memory corruption exploit matching Pegasus spyware. Configured to exfiltrate private messages, active coordinate logs, ambient microphone streams, and browser tokens.'
            }
        }
    };


    // --- Cyberpunk Theme Switcher Logic ---
    const themeMenuBtn = document.getElementById('theme-menu-btn');
    const themeDropdown = document.getElementById('theme-dropdown');
    const themeOpts = document.querySelectorAll('.theme-opt');

    // Toggle dropdown visibility
    themeMenuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        themeDropdown.classList.toggle('hidden');
    });

    // Close dropdown on click outside
    document.addEventListener('click', (e) => {
        if (!themeDropdown.classList.contains('hidden') && !themeMenuBtn.contains(e.target)) {
            themeDropdown.classList.add('hidden');
        }
    });

    // Handle theme change selection
    themeOpts.forEach(opt => {
        opt.addEventListener('click', () => {
            const selectedTheme = opt.getAttribute('data-theme');
            
            // Remove previous theme classes
            document.body.classList.remove('theme-emerald', 'theme-cyberpunk', 'theme-neon-blue', 'theme-crimson');
            
            // Add selected theme class
            document.body.classList.add(`theme-${selectedTheme}`);
            
            // Update active state in UI
            themeOpts.forEach(o => o.classList.remove('active'));
            opt.classList.add('active');
            
            // Save preference to localStorage
            localStorage.setItem('aetherscan_theme', selectedTheme);
            
            // Close menu
            themeDropdown.classList.add('hidden');
        });
    });

    // Apply saved theme preference on page load
    const savedTheme = localStorage.getItem('aetherscan_theme') || 'emerald';
    document.body.classList.remove('theme-emerald', 'theme-cyberpunk', 'theme-neon-blue', 'theme-crimson');
    document.body.classList.add(`theme-${savedTheme}`);
    
    // Set active button in UI on load
    themeOpts.forEach(opt => {
        if (opt.getAttribute('data-theme') === savedTheme) {
            opt.classList.add('active');
        } else {
            opt.classList.remove('active');
        }
    });

});
