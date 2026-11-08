/**
 * TRUSTGUARD - Digital Trust Intelligence Engine
 * Frontend Application Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initPresetChips();
    initUrlScanner();
    initMessageScanner();
    initFileChecker();
    initHashScanner();
    initSslInspector();
    initHistoryTab();
});

/* ========================================================
   TAB NAVIGATION
   ======================================================== */
function initTabs() {
    const navTabs = document.querySelectorAll('.nav-tab');
    const tabPanels = document.querySelectorAll('.tab-panel');

    navTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetTabId = tab.getAttribute('data-tab');

            navTabs.forEach(t => t.classList.remove('active'));
            tabPanels.forEach(p => p.classList.remove('active'));

            tab.classList.add('active');
            const targetPanel = document.getElementById(targetTabId);
            if (targetPanel) {
                targetPanel.classList.add('active');
            }

            // If navigating to History, refresh table data
            if (targetTabId === 'tab-history') {
                loadHistoryData();
            }
        });
    });
}

/* ========================================================
   PRESET CHIPS (1-Click Demonstration Samples)
   ======================================================== */
function initPresetChips() {
    // Fill URL
    document.querySelectorAll('[data-fill-url]').forEach(chip => {
        chip.addEventListener('click', () => {
            const val = chip.getAttribute('data-fill-url');
            const input = document.getElementById('urlInput');
            if (input) {
                input.value = val;
                document.getElementById('urlScanForm').dispatchEvent(new Event('submit'));
            }
        });
    });

    // Fill Message
    document.querySelectorAll('[data-fill-msg]').forEach(chip => {
        chip.addEventListener('click', () => {
            const val = chip.getAttribute('data-fill-msg');
            const textarea = document.getElementById('messageInput');
            if (textarea) {
                textarea.value = val;
                document.getElementById('messageScanForm').dispatchEvent(new Event('submit'));
            }
        });
    });

    // Fill Hash
    document.querySelectorAll('[data-fill-hash]').forEach(chip => {
        chip.addEventListener('click', () => {
            const val = chip.getAttribute('data-fill-hash');
            const input = document.getElementById('hashInput');
            if (input) {
                input.value = val;
                document.getElementById('hashScanForm').dispatchEvent(new Event('submit'));
            }
        });
    });

    // Fill SSL
    document.querySelectorAll('[data-fill-ssl]').forEach(chip => {
        chip.addEventListener('click', () => {
            const val = chip.getAttribute('data-fill-ssl');
            const input = document.getElementById('sslInput');
            if (input) {
                input.value = val;
                document.getElementById('sslScanForm').dispatchEvent(new Event('submit'));
            }
        });
    });
}

/* ========================================================
   1. WEBSITE / URL SCANNER
   ======================================================== */
function initUrlScanner() {
    const form = document.getElementById('urlScanForm');
    const input = document.getElementById('urlInput');
    const btn = document.getElementById('btnScanUrl');
    const resultBox = document.getElementById('urlResultBox');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = input.value.trim();
        if (!url) return;

        setLoading(btn, true);
        resultBox.classList.add('hidden');

        try {
            const res = await fetch('/api/scan-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Failed to scan website.', 'error');
            } else {
                renderUrlResult(resultBox, data);
                updateStatsCounters();
                showToast(`Scan complete: ${data.status.toUpperCase()}`);
            }
        } catch (err) {
            showToast('Network error while connecting to scanner backend.', 'error');
        } finally {
            setLoading(btn, false);
        }
    });
}

function renderUrlResult(box, data) {
    const statusClass = data.status; // 'safe', 'suspicious', 'dangerous'
    const statusIcon = getStatusIconSvg(statusClass);

    let threatHtml = '';
    if (data.threat_flags && data.threat_flags.length > 0) {
        threatHtml = `
            <div class="findings-section">
                <span class="summary-heading" style="color: #9B2C2C;">Identified Risk Indicators (${data.threat_flags.length})</span>
                ${data.threat_flags.map(f => `
                    <div class="finding-item threat">
                        <div class="finding-icon">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="12" y1="8" x2="12" y2="12"></line>
                                <line x1="12" y1="16" x2="12.01" y2="16"></line>
                            </svg>
                        </div>
                        <div>
                            <strong>${escapeHtml(f.title)}:</strong> ${escapeHtml(f.desc)}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    let positiveHtml = '';
    if (data.positive_flags && data.positive_flags.length > 0) {
        positiveHtml = `
            <div class="findings-section">
                <span class="summary-heading" style="color: #22543D;">Positive Security Attributes (${data.positive_flags.length})</span>
                ${data.positive_flags.map(p => `
                    <div class="finding-item positive">
                        <div class="finding-icon">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                        </div>
                        <div>${escapeHtml(p)}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    const details = data.details || {};
    const ssl = details.ssl_info || {};

    box.innerHTML = `
        <div class="result-status-banner ${statusClass}">
            <div class="status-left">
                <div class="status-icon-badge ${statusClass}">
                    ${statusIcon}
                </div>
                <div>
                    <div class="status-badge-title ${statusClass}">${data.status_label}</div>
                    <div class="status-target-label">${escapeHtml(data.target)}</div>
                </div>
            </div>
            <div class="score-box">
                <div class="score-number ${statusClass}">${data.trust_score} / 100</div>
                <div class="score-label">Trust Intelligence Score</div>
            </div>
        </div>

        <div class="result-body">
            <div class="summary-block">
                <div class="summary-heading">Verdict Summary</div>
                <div class="summary-text">${escapeHtml(data.summary)}</div>
            </div>

            <div class="action-block">
                <div class="action-heading">Recommended Action</div>
                <div class="action-text">${escapeHtml(data.recommendation)}</div>
            </div>

            ${threatHtml}
            ${positiveHtml}

            <!-- Expandable Technical Details (For College Evaluation) -->
            <div class="tech-details-box">
                <button type="button" class="tech-details-toggle" onclick="toggleDetails(this)">
                    <span>Technical Security Checks & Headers</span>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                </button>
                <div class="tech-details-content" style="display: none;">
                    <div class="tech-grid">
                        <div>
                            <div class="tech-item-label">Domain / Host</div>
                            <div class="tech-item-val">${escapeHtml(data.domain || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">Resolved IP Address</div>
                            <div class="tech-item-val">${escapeHtml(details.resolved_ip || 'None / Offline')}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">Host Type</div>
                            <div class="tech-item-val">${escapeHtml(details.ip_type || 'Domain')}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">SSL Certificate Authority</div>
                            <div class="tech-item-val">${escapeHtml(ssl.issuer || 'None')}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">SSL Expiry Date</div>
                            <div class="tech-item-val">${ssl.valid_to ? `${ssl.valid_to} (${ssl.days_remaining} days left)` : 'None'}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">HTTP Status Code</div>
                            <div class="tech-item-val">${escapeHtml(String(details.http_status || 'N/A'))}</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    box.classList.remove('hidden');
}


/* ========================================================
   2. MESSAGE / SCAM DETECTOR
   ======================================================== */
function initMessageScanner() {
    const form = document.getElementById('messageScanForm');
    const input = document.getElementById('messageInput');
    const btn = document.getElementById('btnScanMessage');
    const resultBox = document.getElementById('messageResultBox');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const message = input.value.trim();
        if (!message) return;

        setLoading(btn, true);
        resultBox.classList.add('hidden');

        try {
            const res = await fetch('/api/scan-message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message })
            });

            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Failed to analyze message.', 'error');
            } else {
                renderMessageResult(resultBox, data);
                updateStatsCounters();
                showToast(`Message Analyzed: ${data.status.toUpperCase()}`);
            }
        } catch (err) {
            showToast('Network error while analyzing message.', 'error');
        } finally {
            setLoading(btn, false);
        }
    });
}

function renderMessageResult(box, data) {
    const statusClass = data.status;
    const statusIcon = getStatusIconSvg(statusClass);

    let threatsHtml = '';
    if (data.threat_flags && data.threat_flags.length > 0) {
        threatsHtml = `
            <div class="findings-section">
                <span class="summary-heading" style="color: #9B2C2C;">Phishing / Scam Triggers Detected</span>
                ${data.threat_flags.map(f => `
                    <div class="finding-item threat">
                        <div class="finding-icon">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="12" y1="8" x2="12" y2="12"></line>
                                <line x1="12" y1="16" x2="12.01" y2="16"></line>
                            </svg>
                        </div>
                        <div>
                            <strong>${escapeHtml(f.title)}:</strong> ${escapeHtml(f.desc)} 
                            ${f.matched ? `<code style="margin-left:6px; font-size:0.8rem; background:#FED7D7; padding:2px 4px; border-radius:3px;">"${escapeHtml(f.matched)}"</code>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    let urlsHtml = '';
    if (data.extracted_urls && data.extracted_urls.length > 0) {
        urlsHtml = `
            <div style="font-size: 0.85rem; color: var(--text-muted); background: var(--bg-secondary); padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border-color);">
                <strong>Extracted Links in Message:</strong>
                <ul style="margin-top: 4px; padding-left: 20px;">
                    ${data.extracted_urls.map(u => `<li><code>${escapeHtml(u)}</code></li>`).join('')}
                </ul>
            </div>
        `;
    }

    box.innerHTML = `
        <div class="result-status-banner ${statusClass}">
            <div class="status-left">
                <div class="status-icon-badge ${statusClass}">
                    ${statusIcon}
                </div>
                <div>
                    <div class="status-badge-title ${statusClass}">${data.status_label}</div>
                    <div class="status-target-label">Analyzed Text Message / Email</div>
                </div>
            </div>
            <div class="score-box">
                <div class="score-number ${statusClass}">${data.trust_score} / 100</div>
                <div class="score-label">Trust Score</div>
            </div>
        </div>

        <div class="result-body">
            <div class="summary-block">
                <div class="summary-heading">Evaluation Verdict</div>
                <div class="summary-text">${escapeHtml(data.summary)}</div>
            </div>

            <div class="action-block">
                <div class="action-heading">Safety Advice</div>
                <div class="action-text">${escapeHtml(data.recommendation)}</div>
            </div>

            ${threatsHtml}
            ${urlsHtml}
        </div>
    `;

    box.classList.remove('hidden');
}


/* ========================================================
   3. FILE & HASH INTEGRITY CHECKER
   ======================================================== */
function initFileChecker() {
    const fileInput = document.getElementById('fileInput');
    const dropzoneText = document.getElementById('dropzoneText');
    const uploadForm = document.getElementById('fileUploadForm');
    const btnUpload = document.getElementById('btnUploadFile');
    const resultBox = document.getElementById('fileResultBox');

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            const file = fileInput.files[0];
            dropzoneText.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            btnUpload.disabled = false;
        } else {
            dropzoneText.textContent = 'Click to browse or drop file here';
            btnUpload.disabled = true;
        }
    });

    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!fileInput.files.length) return;

        const formData = new FormData();
        formData.append('file', fileInput.files[0]);

        setLoading(btnUpload, true);
        resultBox.classList.add('hidden');

        try {
            const res = await fetch('/api/scan-file', {
                method: 'POST',
                body: formData
            });

            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Failed to inspect file.', 'error');
            } else {
                renderFileResult(resultBox, data);
                updateStatsCounters();
                showToast(`File Verified: ${data.status.toUpperCase()}`);
            }
        } catch (err) {
            showToast('Error uploading file.', 'error');
        } finally {
            setLoading(btnUpload, false);
        }
    });
}

function initHashScanner() {
    const form = document.getElementById('hashScanForm');
    const input = document.getElementById('hashInput');
    const btn = document.getElementById('btnScanHash');
    const resultBox = document.getElementById('fileResultBox');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const hash = input.value.trim();
        if (!hash) return;

        setLoading(btn, true);
        resultBox.classList.add('hidden');

        try {
            const res = await fetch('/api/scan-file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hash })
            });

            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Failed to verify hash.', 'error');
            } else {
                renderFileResult(resultBox, data);
                updateStatsCounters();
                showToast(`Hash Verified: ${data.status.toUpperCase()}`);
            }
        } catch (err) {
            showToast('Error verifying hash.', 'error');
        } finally {
            setLoading(btn, false);
        }
    });
}

function renderFileResult(box, data) {
    const statusClass = data.status;
    const statusIcon = getStatusIconSvg(statusClass);

    let threatsHtml = '';
    if (data.threat_flags && data.threat_flags.length > 0) {
        threatsHtml = `
            <div class="findings-section">
                <span class="summary-heading" style="color: #9B2C2C;">Threat Flags</span>
                ${data.threat_flags.map(f => `
                    <div class="finding-item threat">
                        <div class="finding-icon">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="12" y1="8" x2="12" y2="12"></line>
                                <line x1="12" y1="16" x2="12.01" y2="16"></line>
                            </svg>
                        </div>
                        <div><strong>${escapeHtml(f.title)}:</strong> ${escapeHtml(f.desc)}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    let positiveHtml = '';
    if (data.positive_flags && data.positive_flags.length > 0) {
        positiveHtml = `
            <div class="findings-section">
                ${data.positive_flags.map(p => `
                    <div class="finding-item positive">
                        <div class="finding-icon">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                        </div>
                        <div>${escapeHtml(p)}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    const titleTarget = data.filename ? `File: ${data.filename} (${data.file_size_kb} KB)` : `Hash: ${data.hash}`;

    box.innerHTML = `
        <div class="result-status-banner ${statusClass}">
            <div class="status-left">
                <div class="status-icon-badge ${statusClass}">
                    ${statusIcon}
                </div>
                <div>
                    <div class="status-badge-title ${statusClass}">${data.status_label}</div>
                    <div class="status-target-label">${escapeHtml(titleTarget)}</div>
                </div>
            </div>
            <div class="score-box">
                <div class="score-number ${statusClass}">${data.trust_score} / 100</div>
                <div class="score-label">Integrity Score</div>
            </div>
        </div>

        <div class="result-body">
            <div class="summary-block">
                <div class="summary-heading">Analysis Result</div>
                <div class="summary-text">${escapeHtml(data.summary)}</div>
            </div>

            <div class="action-block">
                <div class="action-heading">Recommendation</div>
                <div class="action-text">${escapeHtml(data.recommendation)}</div>
            </div>

            ${threatsHtml}
            ${positiveHtml}

            <!-- Hashes Breakdown Table -->
            <div class="tech-details-box">
                <div class="summary-heading" style="margin-bottom: 8px;">Cryptographic Hash Fingerprints (hashlib)</div>
                <div class="tech-details-content">
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        ${data.sha256 ? `
                            <div>
                                <div class="tech-item-label">SHA-256 (Modern Standard)</div>
                                <div class="tech-item-val" style="font-size:0.8rem;">${data.sha256}</div>
                            </div>
                        ` : ''}
                        ${data.md5 ? `
                            <div>
                                <div class="tech-item-label">MD5 (Legacy Checksum)</div>
                                <div class="tech-item-val" style="font-size:0.8rem;">${data.md5}</div>
                            </div>
                        ` : ''}
                        ${data.sha1 ? `
                            <div>
                                <div class="tech-item-label">SHA-1</div>
                                <div class="tech-item-val" style="font-size:0.8rem;">${data.sha1}</div>
                            </div>
                        ` : ''}
                        ${data.hash ? `
                            <div>
                                <div class="tech-item-label">${data.hash_type || 'Hash'}</div>
                                <div class="tech-item-val" style="font-size:0.8rem;">${data.hash}</div>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        </div>
    `;

    box.classList.remove('hidden');
}


/* ========================================================
   4. SSL CERTIFICATE INSPECTOR
   ======================================================== */
function initSslInspector() {
    const form = document.getElementById('sslScanForm');
    const input = document.getElementById('sslInput');
    const btn = document.getElementById('btnScanSsl');
    const resultBox = document.getElementById('sslResultBox');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = input.value.trim();
        if (!domain) return;

        setLoading(btn, true);
        resultBox.classList.add('hidden');

        try {
            const res = await fetch('/api/inspect-ssl', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain })
            });

            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Failed to inspect SSL.', 'error');
            } else {
                renderSslResult(resultBox, data);
                updateStatsCounters();
                showToast(`SSL Inspected: ${data.status.toUpperCase()}`);
            }
        } catch (err) {
            showToast('Error connecting to SSL inspection engine.', 'error');
        } finally {
            setLoading(btn, false);
        }
    });
}

function renderSslResult(box, data) {
    const statusClass = data.status;
    const statusIcon = getStatusIconSvg(statusClass);
    const details = data.details || {};

    let positiveHtml = '';
    if (data.positive_flags && data.positive_flags.length > 0) {
        positiveHtml = `
            <div class="findings-section">
                ${data.positive_flags.map(p => `
                    <div class="finding-item positive">
                        <div class="finding-icon">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                        </div>
                        <div>${escapeHtml(p)}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    let threatHtml = '';
    if (data.threat_flags && data.threat_flags.length > 0) {
        threatHtml = `
            <div class="findings-section">
                ${data.threat_flags.map(f => `
                    <div class="finding-item threat">
                        <div class="finding-icon">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="12" y1="8" x2="12" y2="12"></line>
                                <line x1="12" y1="16" x2="12.01" y2="16"></line>
                            </svg>
                        </div>
                        <div><strong>${escapeHtml(f.title)}:</strong> ${escapeHtml(f.desc)}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    box.innerHTML = `
        <div class="result-status-banner ${statusClass}">
            <div class="status-left">
                <div class="status-icon-badge ${statusClass}">
                    ${statusIcon}
                </div>
                <div>
                    <div class="status-badge-title ${statusClass}">${data.status_label}</div>
                    <div class="status-target-label">SSL/TLS Inspection for ${escapeHtml(data.domain)}</div>
                </div>
            </div>
            <div class="score-box">
                <div class="score-number ${statusClass}">${data.trust_score} / 100</div>
                <div class="score-label">Encryption Score</div>
            </div>
        </div>

        <div class="result-body">
            <div class="summary-block">
                <div class="summary-heading">SSL Security Status</div>
                <div class="summary-text">${escapeHtml(data.summary)}</div>
            </div>

            <div class="action-block">
                <div class="action-heading">Advice</div>
                <div class="action-text">${escapeHtml(data.recommendation)}</div>
            </div>

            ${positiveHtml}
            ${threatHtml}

            <!-- Certificate Details Grid -->
            <div class="tech-details-box">
                <div class="summary-heading" style="margin-bottom: 10px;">Certificate Details (Python ssl & socket)</div>
                <div class="tech-details-content">
                    <div class="tech-grid">
                        <div>
                            <div class="tech-item-label">Certificate Authority (Issuer)</div>
                            <div class="tech-item-val">${escapeHtml(details.issuer || 'None')}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">Issued To (Subject)</div>
                            <div class="tech-item-val">${escapeHtml(details.subject || data.domain)}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">Valid From</div>
                            <div class="tech-item-val">${escapeHtml(details.valid_from || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">Valid Until</div>
                            <div class="tech-item-val">${escapeHtml(details.valid_to || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">Days Remaining</div>
                            <div class="tech-item-val">${details.days_remaining !== undefined ? `${details.days_remaining} days` : 'N/A'}</div>
                        </div>
                        <div>
                            <div class="tech-item-label">TLS Protocol & Cipher</div>
                            <div class="tech-item-val">${escapeHtml(details.protocol || 'N/A')} (${escapeHtml(details.cipher || 'N/A')})</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    box.classList.remove('hidden');
}


/* ========================================================
   5. SCAN HISTORY & AUDIT LOGS
   ======================================================== */
function initHistoryTab() {
    const filterType = document.getElementById('filterType');
    const filterStatus = document.getElementById('filterStatus');
    const filterSearch = document.getElementById('filterSearch');
    const btnRefresh = document.getElementById('btnRefreshHistory');
    const btnClear = document.getElementById('btnClearHistory');

    [filterType, filterStatus].forEach(el => {
        el.addEventListener('change', () => loadHistoryData());
    });

    let searchTimer = null;
    filterSearch.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => loadHistoryData(), 300);
    });

    btnRefresh.addEventListener('click', () => {
        loadHistoryData();
        showToast('History refreshed.');
    });

    btnClear.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to clear all scan history logs?')) return;
        try {
            const res = await fetch('/api/history/clear', { method: 'POST' });
            if (res.ok) {
                loadHistoryData();
                updateStatsCounters();
                showToast('Audit log cleared.');
            }
        } catch (err) {
            showToast('Failed to clear history.', 'error');
        }
    });

    // Initial load
    loadHistoryData();
}

async function loadHistoryData() {
    const type = document.getElementById('filterType').value;
    const status = document.getElementById('filterStatus').value;
    const search = document.getElementById('filterSearch').value.trim();
    const tbody = document.getElementById('historyTableBody');

    try {
        const queryParams = new URLSearchParams({ type, status, search });
        const res = await fetch(`/api/history?${queryParams.toString()}`);
        const data = await res.json();

        if (!data.scans || data.scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-4" style="color: var(--text-muted);">
                        No scan records found matching filters.
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = data.scans.map(scan => `
            <tr>
                <td style="font-size: 0.8rem; color: var(--text-muted); white-space: nowrap;">
                    ${escapeHtml(scan.created_at)}
                </td>
                <td>
                    <span class="type-tag">${escapeHtml(scan.scan_type)}</span>
                </td>
                <td style="font-weight: 600; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(scan.target)}">
                    ${escapeHtml(scan.target)}
                </td>
                <td>
                    <span style="font-weight: 700; color: var(--${scan.status === 'safe' ? 'status-safe' : scan.status === 'suspicious' ? 'status-suspicious' : 'status-dangerous'});">
                        ${scan.trust_score} / 100
                    </span>
                </td>
                <td>
                    <span class="status-badge ${scan.status}">
                        <span class="badge-dot ${scan.status}"></span>
                        ${scan.status.toUpperCase()}
                    </span>
                </td>
                <td style="font-size: 0.85rem; color: var(--text-muted); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(scan.summary)}">
                    ${escapeHtml(scan.summary)}
                </td>
            </tr>
        `).join('');
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-4" style="color: var(--status-dangerous);">
                    Error loading scan history from database.
                </td>
            </tr>
        `;
    }
}

async function updateStatsCounters() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        
        document.getElementById('statTotal').textContent = stats.total || 0;
        document.getElementById('statSafe').textContent = stats.safe || 0;
        document.getElementById('statSuspicious').textContent = stats.suspicious || 0;
        document.getElementById('statDangerous').textContent = stats.dangerous || 0;
    } catch (e) {
        // Silent fail on stats sync
    }
}


/* ========================================================
   UI UTILITIES & HELPERS
   ======================================================== */

function setLoading(btn, isLoading) {
    if (isLoading) {
        btn.classList.add('loading');
        btn.disabled = true;
    } else {
        btn.classList.remove('loading');
        btn.disabled = false;
    }
}

function toggleDetails(btn) {
    const content = btn.nextElementSibling;
    if (content.style.display === 'none') {
        content.style.display = 'block';
    } else {
        content.style.display = 'none';
    }
}

function getStatusIconSvg(status) {
    if (status === 'safe') {
        return `
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
        `;
    } else if (status === 'suspicious') {
        return `
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
        `;
    } else {
        return `
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
        `;
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;

    if (type === 'error') {
        toast.style.backgroundColor = 'var(--status-dangerous)';
    }

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3200);
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
