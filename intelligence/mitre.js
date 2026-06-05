// intelligence/mitre.js
const TACTICS = {
    TA0001: { name: 'Initial Access', description: 'The adversary is trying to get into your network.' },
    TA0002: { name: 'Execution', description: 'The adversary is trying to run malicious code.' },
    TA0003: { name: 'Persistence', description: 'The adversary is trying to maintain their foothold.' },
    TA0004: { name: 'Privilege Escalation', description: 'The adversary is trying to gain higher-level permissions.' },
    TA0005: { name: 'Defense Evasion', description: 'The adversary is trying to avoid being detected.' },
    TA0006: { name: 'Credential Access', description: 'The adversary is trying to steal account names and passwords.' },
    TA0007: { name: 'Discovery', description: 'The adversary is trying to figure out your environment.' },
    TA0008: { name: 'Lateral Movement', description: 'The adversary is trying to move through your environment.' },
    TA0009: { name: 'Collection', description: 'The adversary is trying to gather data of interest to their goal.' },
    TA0010: { name: 'Exfiltration', description: 'The adversary is trying to steal data.' },
    TA0011: { name: 'Command and Control', description: 'The adversary is trying to communicate with compromised systems.' },
    TA0040: { name: 'Impact', description: 'The adversary is trying to manipulate, interrupt, or destroy your systems and data.' }
};

export function mapHeuristicsToMitre(heuristics, iocs) {
    const identifiedTactics = new Set();
    const techniques = [];

    if (heuristics.entropy > 7.2) {
        identifiedTactics.add('TA0005');
        techniques.push({ id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'TA0005' });
    }

    if (!heuristics.spoofingPass) {
        identifiedTactics.add('TA0005');
        techniques.push({ id: 'T1036', name: 'Masquerading', tactic: 'TA0005' });
    }

    if (iocs.ips.length > 0 || iocs.domains.length > 0) {
        identifiedTactics.add('TA0011');
        techniques.push({ id: 'T1071', name: 'Application Layer Protocol', tactic: 'TA0011' });
    }

    if (iocs.suspicious.some(s => s.toLowerCase().includes('registry') || s.toLowerCase().includes('hkey'))) {
        identifiedTactics.add('TA0003');
        identifiedTactics.add('TA0005');
        techniques.push({ id: 'T1112', name: 'Modify Registry', tactic: 'TA0005' });
    }

    if (iocs.suspicious.some(s => s.toLowerCase().includes('powershell') || s.toLowerCase().includes('cmd.exe'))) {
        identifiedTactics.add('TA0002');
        techniques.push({ id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'TA0002' });
    }

    if (iocs.suspicious.some(s => s.toLowerCase().includes('virtualalloc') || s.toLowerCase().includes('createremotethread'))) {
        identifiedTactics.add('TA0005');
        techniques.push({ id: 'T1055', name: 'Process Injection', tactic: 'TA0005' });
    }

    if (heuristics.isHighRiskExt) {
        identifiedTactics.add('TA0002');
    }

    return {
        tactics: Array.from(identifiedTactics).map(t => ({ id: t, ...TACTICS[t] })),
        techniques
    };
}

export function generateMitreHTML(mapping) {
    if (mapping.tactics.length === 0) {
        return '<p class="text-muted">No specific MITRE ATT&CK tactics identified from static heuristics.</p>';
    }

    let html = '<div class="mitre-tactics-list">';

    mapping.tactics.forEach(tactic => {
        html += `
            <div class="mitre-tactic-card" style="margin-bottom: 12px; padding: 10px; background: rgba(255,255,255,0.05); border-left: 3px solid var(--accent-cyan);">
                <h4 style="margin-bottom: 4px; color: var(--accent-cyan);">${tactic.id}: ${tactic.name}</h4>
                <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 8px;">${tactic.description}</p>
                <ul style="list-style: none; padding-left: 10px; font-size: 0.8rem;">
        `;

        const tacticTechniques = mapping.techniques.filter(tech => tech.tactic === tactic.id);
        tacticTechniques.forEach(tech => {
            html += `<li><i class="fa-solid fa-angle-right text-muted"></i> ${tech.id}: ${tech.name}</li>`;
        });

        html += `</ul></div>`;
    });

    html += '</div>';
    return html;
}
