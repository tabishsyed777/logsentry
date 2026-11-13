(() => {
  'use strict';

  const SAMPLE_LOG = `192.0.2.10 - - [13/Nov/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 810
198.51.100.23 - - [13/Nov/2026:09:01:00 +0000] "POST /login HTTP/1.1" 401 120
198.51.100.23 - - [13/Nov/2026:09:02:00 +0000] "POST /login HTTP/1.1" 401 120
203.0.113.8 - - [13/Nov/2026:09:03:00 +0000] "POST /login HTTP/1.1" 401 120
198.51.100.23 - - [13/Nov/2026:09:04:00 +0000] "POST /login HTTP/1.1" 403 120
198.51.100.23 - - [13/Nov/2026:09:05:00 +0000] "POST /auth/session HTTP/1.1" 401 120
198.51.100.23 - - [13/Nov/2026:09:06:00 +0000] "POST /login HTTP/1.1" 401 120
192.0.2.10 - - [13/Nov/2026:09:07:00 +0000] "GET /about HTTP/1.1" 200 810`;

  const els = {
    fileInput: document.querySelector('#fileInput'), dropZone: document.querySelector('#dropZone'), fileName: document.querySelector('#fileName'),
    logInput: document.querySelector('#logInput'), sampleButton: document.querySelector('#sampleButton'), clearButton: document.querySelector('#clearButton'),
    analyzeButton: document.querySelector('#analyzeButton'), downloadButton: document.querySelector('#downloadButton'), threshold: document.querySelector('#threshold'),
    windowMinutes: document.querySelector('#windowMinutes'), flaggedSources: document.querySelector('#flaggedSources'), authFailures: document.querySelector('#authFailures'),
    parsedLines: document.querySelector('#parsedLines'), windowSummary: document.querySelector('#windowSummary'), flaggedHint: document.querySelector('#flaggedHint'),
    alertCount: document.querySelector('#alertCount'), alertsList: document.querySelector('#alertsList'), reportStatus: document.querySelector('#reportStatus'), clock: document.querySelector('#clock')
  };
  let latestReport = null;
  const logPattern = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^\"]*)"\s+(\d{3})\s+\S+/;
  const authPath = /(?:login|signin|auth|session)/i;

  const parseTimestamp = (value) => {
    const match = value.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/);
    if (!match) return null;
    const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    const offset = `${match[7].slice(0, 3)}:${match[7].slice(3)}`;
    const date = new Date(`${match[3]}-${String(months[match[2]] + 1).padStart(2, '0')}-${match[1]}T${match[4]}:${match[5]}:${match[6]}${offset}`);
    return Number.isNaN(date.getTime()) ? null : date;
  };

  function parseLine(line) {
    const match = line.trim().match(logPattern);
    if (!match) return null;
    const request = match[3].split(/\s+/);
    const timestamp = parseTimestamp(match[2]);
    if (!timestamp || request.length < 2) return null;
    return { ip: match[1], timestamp, status: Number(match[4]), path: request[1].split('?')[0] };
  }

  function analyze(text, threshold, windowMinutes, sourceFile = 'pasted-log.txt') {
    const failures = new Map(); let parsedLines = 0;
    text.split(/\r?\n/).forEach((line) => {
      const record = parseLine(line); if (!record) return; parsedLines += 1;
      if ((record.status === 401 || record.status === 403) && authPath.test(record.path)) {
        if (!failures.has(record.ip)) failures.set(record.ip, []); failures.get(record.ip).push(record);
      }
    });
    const windowMs = windowMinutes * 60 * 1000; const alerts = [];
    failures.forEach((records, ip) => {
      records.sort((a, b) => a.timestamp - b.timestamp); let left = 0; let best = { count: 0, start: records[0], end: records[0] };
      records.forEach((record, right) => {
        while (record.timestamp - records[left].timestamp > windowMs) left += 1;
        const count = right - left + 1; if (count > best.count) best = { count, start: records[left], end: record };
      });
      if (best.count >= threshold) alerts.push({ source_ip: ip, failures_in_window: best.count, window_start: best.start.timestamp.toISOString(), window_end: best.end.timestamp.toISOString(), paths: [...new Set(records.map((r) => r.path))].sort().slice(0, 5) });
    });
    alerts.sort((a, b) => b.failures_in_window - a.failures_in_window || a.source_ip.localeCompare(b.source_ip));
    return { generated_at: new Date().toISOString(), source_file: sourceFile, settings: { threshold, window_minutes: windowMinutes }, summary: { parsed_lines: parsedLines, authentication_failures: [...failures.values()].reduce((sum, records) => sum + records.length, 0), flagged_sources: alerts.length }, alerts };
  }

  const formatTime = (iso) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }) + ' UTC';
  function renderReport(report) {
    latestReport = report; const { summary, settings } = report;
    els.flaggedSources.textContent = summary.flagged_sources; els.authFailures.textContent = summary.authentication_failures; els.parsedLines.textContent = summary.parsed_lines; els.windowSummary.textContent = `${settings.window_minutes}m`;
    els.flaggedHint.textContent = summary.flagged_sources ? 'Sources crossed the threshold' : 'No sources crossed the threshold'; els.alertCount.textContent = `${report.alerts.length} alert${report.alerts.length === 1 ? '' : 's'}`;
    els.reportStatus.textContent = `Analyzed ${report.source_file}`; els.reportStatus.classList.add('is-ready'); els.downloadButton.disabled = false;
    if (!report.alerts.length) { els.alertsList.innerHTML = '<div class="empty-state"><span class="empty-cross">✓</span><strong>No threshold crossings</strong><p>The selected source has no burst matching the current detection lens.</p></div>'; return; }
    els.alertsList.innerHTML = report.alerts.map((alert) => `<article class="alert-card"><div><div class="alert-ip">${escapeHtml(alert.source_ip)}</div><div class="alert-meta">${formatTime(alert.window_start)} — ${formatTime(alert.window_end)}</div></div><div class="alert-count">${alert.failures_in_window} FAILURES</div><div class="alert-paths">PATHS / ${alert.paths.map(escapeHtml).join(' · ')}</div></article>`).join('');
  }
  const escapeHtml = (value) => String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
  function runAnalysis() {
    const text = els.logInput.value.trim(); const threshold = Number(els.threshold.value); const windowMinutes = Number(els.windowMinutes.value);
    if (!text) { els.logInput.focus(); els.reportStatus.textContent = 'Add a log source first'; els.reportStatus.classList.remove('is-ready'); return; }
    if (!Number.isInteger(threshold) || threshold < 1 || !Number.isInteger(windowMinutes) || windowMinutes < 1) { els.reportStatus.textContent = 'Use positive whole numbers for the lens'; els.reportStatus.classList.remove('is-ready'); return; }
    renderReport(analyze(text, threshold, windowMinutes, els.fileName.dataset.source || 'pasted-log.txt')); document.querySelector('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function loadSample() { els.logInput.value = SAMPLE_LOG; els.fileName.textContent = 'Synthetic sample / access.log'; els.fileName.dataset.source = 'access.log'; runAnalysis(); }
  function clearSource() { els.logInput.value = ''; els.fileInput.value = ''; els.fileName.textContent = 'No file selected'; delete els.fileName.dataset.source; latestReport = null; els.reportStatus.textContent = 'Waiting for a source'; els.reportStatus.classList.remove('is-ready'); els.downloadButton.disabled = true; els.flaggedSources.textContent = '—'; els.authFailures.textContent = '—'; els.parsedLines.textContent = '—'; els.windowSummary.textContent = '—'; els.alertCount.textContent = '0 alerts'; els.alertsList.innerHTML = '<div class="empty-state"><span class="empty-cross">＋</span><strong>No signals yet</strong><p>Load the sample or add your own authorized log to generate a report.</p></div>'; }
  function readFile(file) { if (!file) return; const reader = new FileReader(); reader.onload = () => { els.logInput.value = String(reader.result); els.fileName.textContent = file.name; els.fileName.dataset.source = file.name; runAnalysis(); }; reader.readAsText(file); }
  els.fileInput.addEventListener('change', (event) => readFile(event.target.files[0])); els.sampleButton.addEventListener('click', loadSample); els.clearButton.addEventListener('click', clearSource); els.analyzeButton.addEventListener('click', runAnalysis);
  els.dropZone.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); els.fileInput.click(); } });
  ['dragenter', 'dragover'].forEach((eventName) => els.dropZone.addEventListener(eventName, (event) => { event.preventDefault(); els.dropZone.classList.add('is-dragging'); }));
  ['dragleave', 'drop'].forEach((eventName) => els.dropZone.addEventListener(eventName, (event) => { event.preventDefault(); els.dropZone.classList.remove('is-dragging'); })); els.dropZone.addEventListener('drop', (event) => readFile(event.dataTransfer.files[0]));
  els.downloadButton.addEventListener('click', () => { if (!latestReport) return; const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: 'application/json' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'logsentry-report.json'; link.click(); URL.revokeObjectURL(link.href); });
  function tick() { const now = new Date(); els.clock.textContent = `${now.toISOString().slice(11, 19)} UTC`; } tick(); setInterval(tick, 1000);
})();
