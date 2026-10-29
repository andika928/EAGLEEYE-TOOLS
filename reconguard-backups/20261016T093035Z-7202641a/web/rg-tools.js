/* Dalfox/Nikto dashboard integration. All imported values render as text. */
document.addEventListener('DOMContentLoaded', () => {
  const view = document.getElementById('view-reconguard');
  if (!view) return;
  let latest = null;
  let busy = false;
  const panel = document.createElement('section');
  panel.className = 'rg-tools-panel';
  panel.innerHTML = `
    <div class="rg-tools-heading"><div><h3>Dalfox & Nikto · Active checks + evidence review</h3>
      <p>Opt-in scans on the supplied origin. Tool matches remain observations until independently validated.</p></div>
      <span class="rg-tools-state" id="rgToolsAvailability">Checking installed tools…</span></div>
    <div class="rg-tools-grid">
      <label><input type="checkbox" id="rgEnableDalfox"> <strong>DALFOX</strong> · XSS analysis
        <small>Reflection ≠ browser execution. Native mode requires Dalfox v3.</small>
        <input type="file" id="rgDalfoxFile" accept=".json,.jsonl" aria-label="Dalfox JSON report"></label>
      <label><input type="checkbox" id="rgEnableNikto"> <strong>NIKTO</strong> · Web server checks
        <small>Messages are leads, not vulnerability proof. Native scans require whole-origin scope.</small>
        <input type="file" id="rgNiktoFile" accept=".json" aria-label="Nikto JSON report"></label>
    </div>
    <p class="rg-tools-note">Uses the target, scope and exclusion fields above. Native scans may test additional paths and parameters. Nikto refuses regex exclusions; use import when program rules restrict paths. Imports filter results after the external scan.</p>
    <div class="rg-tools-actions">
      <button type="button" class="enterprise-btn-gold" id="rgRunTools">Run selected tools</button>
      <button type="button" class="enterprise-btn-blue" id="rgImportTools">Import selected JSON reports</button>
      <button type="button" class="enterprise-btn-blue" id="rgExportTools" disabled>Export tool review (.md)</button>
    </div>
    <p id="rgToolsStatus" role="status" aria-live="polite">No tool run started. Zero false positives cannot be guaranteed.</p>
    <div id="rgToolsResults"></div>`;
  const tracker = view.querySelector('.enterprise-recon-pipeline');
  tracker.before(panel);
  const badges = view.querySelector('.enterprise-pills-group');
  for (const name of ['DALFOX', 'NIKTO']) {
    const badge = document.createElement('span');
    badge.className = 'enterprise-badge-gold';
    badge.textContent = name;
    badges.append(badge);
  }
  const get = id => document.getElementById(id);
  const status = message => { get('rgToolsStatus').textContent = message; };
  const split = id => get(id).value.split(',').map(x => x.trim()).filter(Boolean);
  function render(report) {
    latest = report;
    const container = get('rgToolsResults');
    container.replaceChildren();
    const summary = document.createElement('p');
    summary.textContent = `${report.results.length} observations · ${report.blocked.length} blocked at intake · 0 independently confirmed vulnerabilities`;
    container.append(summary);
    if ((report.sources || []).some(x => x.scan_metadata && x.scan_metadata.incomplete)) {
      const warning = document.createElement('p');
      warning.className = 'rg-tools-warning';
      warning.textContent = 'INCOMPLETE SCAN — source testing did not finish. No clean assessment can be inferred.';
      container.append(warning);
    }
    for (const run of report.tool_runs || []) {
      const line = document.createElement('p');
      line.textContent = `${run.engine}: ${run.state}${run.exit_code === undefined ? '' : ' (exit ' + run.exit_code + ')'}`;
      container.append(line);
    }
    for (const row of report.results) {
      const card = document.createElement('article');
      card.className = 'rg-tools-result';
      const heading = document.createElement('strong');
      heading.textContent = `${row.engine} · ${row.status} · scanner severity: ${row.reported_severity}`;
      card.append(heading);
      for (const text of [row.title, row.location, row.validation_required]) {
        const p = document.createElement('p'); p.textContent = text; card.append(p);
      }
      const details = document.createElement('details');
      const label = document.createElement('summary'); label.textContent = 'Inspect evidence';
      const proof = document.createElement('pre');
      proof.textContent = `${row.evidence_kind || 'source evidence'}\n${row.evidence_excerpt || 'No raw response supplied'}\nSHA-256: ${row.evidence_sha256 || 'not available'}`;
      details.append(label, proof); card.append(details); container.append(card);
    }
    if (report.blocked.length) {
      const details = document.createElement('details');
      const label = document.createElement('summary'); label.textContent = 'Show rejected records';
      const pre = document.createElement('pre'); pre.textContent = JSON.stringify(report.blocked, null, 2);
      details.append(label, pre); container.append(details);
    }
    get('rgExportTools').disabled = false;
  }
  async function submit(mode) {
    if (busy) return;
    const body = {target: get('rgTargetInput').value.trim(), in_scope: split('rgInScopeInput'), out_of_scope: split('rgOutOfScopeInput'), tools: [], reports: {}};
    if (!body.in_scope.length) { status('Enter explicit scope rules before continuing.'); return; }
    busy = true;
    get('rgRunTools').disabled = get('rgImportTools').disabled = true;
    try {
      for (const [name, enabled, fileId] of [['dalfox', 'rgEnableDalfox', 'rgDalfoxFile'], ['nikto', 'rgEnableNikto', 'rgNiktoFile']]) {
        if (!get(enabled).checked) continue;
        body.tools.push(name);
        if (mode === 'import') {
          const file = get(fileId).files[0];
          if (!file) throw new Error(`Select a ${name} JSON report.`);
          if (file.size > 1024 * 1024) throw new Error('Maximum upload size is 1 MiB per file.');
          body.reports[name] = await file.text();
        }
      }
      if (!body.tools.length) throw new Error('Select Dalfox and/or Nikto.');
      status(mode === 'scan' ? 'Selected tools running; allow up to 120 seconds per tool. No findings are confirmed automatically.' : 'Validating report formats and scope…');
      const response = await fetch('/api/reconguard/integrations/' + mode, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
      const report = await response.json();
      if (!response.ok || report.error) throw new Error(report.error || `HTTP ${response.status}`);
      render(report);
      status('Review updated. Inspect evidence and run states before interpreting results.');
    } catch (error) { status(error.message); }
    finally { busy = false; get('rgRunTools').disabled = get('rgImportTools').disabled = false; }
  }
  get('rgRunTools').addEventListener('click', () => submit('scan'));
  get('rgImportTools').addEventListener('click', () => submit('import'));
  get('rgExportTools').addEventListener('click', () => {
    if (!latest) return;
    const json = JSON.stringify(latest, null, 2).replace(/```/g, 'ˋˋˋ');
    const blob = new Blob(['# ReconGuard Dalfox / Nikto evidence review\n\nNo automatically confirmed vulnerabilities.\n\n```json\n' + json + '\n```\n'], {type: 'text/markdown;charset=utf-8'});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob); link.download = 'ReconGuard-tool-review.md'; link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  });
  fetch('/api/reconguard/integrations/status').then(x => x.json()).then(data => {
    get('rgToolsAvailability').textContent = Object.entries(data.tools).map(([name, tool]) => `${name}: ${tool.available ? 'installed (CLI check on run)' : 'unavailable · import supported'}`).join(' | ');
  }).catch(() => { get('rgToolsAvailability').textContent = 'Backend unavailable · start/restart server.py'; });
  fetch('/api/reconguard/integrations/results').then(x => x.json()).then(report => {
    if (report.results && (report.results.length || report.tool_runs?.length || report.sources?.length)) render(report);
  }).catch(() => {});
});
