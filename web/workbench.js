document.addEventListener('DOMContentLoaded', () => {
  'use strict';
  const root = document.getElementById('httpWorkbench');
  if (!root) return;
  root.innerHTML = `
    <div class="wb-heading">
      <div><p class="wb-kicker">MANUAL HTTP SECURITY WORKBENCH</p><h2>Request · review · response</h2>
        <p>Use one authorized scope and inspect one request at a time. The server enforces the scope and requires a fresh preview before sending.</p></div>
      <span class="wb-tag">LOCAL PROJECT</span>
    </div>
    <div class="wb-grid">
      <div class="wb-main">
        <form id="wbProjectForm" class="wb-card">
          <h3>Project scope</h3>
          <p>Enter an authorized HTTP(S) URL. Its path becomes the scope; any query stays in the Repeater URL. Use the root URL to cover a whole origin.</p>
          <div class="wb-row"><input id="wbScope" class="tools-input" type="url" required placeholder="https://example.com/search?q=test" autocomplete="off"><button id="wbSetScope" class="wb-button" type="submit">Set scope</button></div>
          <label class="wb-check"><input id="wbAuthorized" type="checkbox" required> I own this target or have explicit authorization for this scope.</label>
          <div id="wbScopeState" class="wb-status" role="status">No project scope set.</div>
        </form>
        <form id="wbRequestForm" class="wb-card">
          <div class="wb-card-title"><h3>Repeater</h3><span>One request per approval</span></div>
          <div class="wb-row"><select id="wbMethod" class="tools-input"><option>GET</option><option>HEAD</option><option>OPTIONS</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option></select><input id="wbUrl" class="tools-input" type="url" required placeholder="https://example.com/path"></div>
          <label class="wb-label">Request headers <span>One Name: value per line. Host and transport headers are managed by the server.</span><textarea id="wbHeaders" class="tools-input" rows="4" placeholder="Accept: text/html"></textarea></label>
          <label class="wb-label">Request body <span>UTF-8 text; max 64 KiB.</span><textarea id="wbBody" class="tools-input" rows="5" placeholder="Optional body for POST, PUT, PATCH or DELETE"></textarea></label>
          <div class="wb-actions"><button id="wbPreview" class="wb-button" type="submit">Preview request</button><label class="wb-check"><input id="wbApprove" type="checkbox" disabled> I reviewed this exact request.</label><button id="wbSend" class="wb-button wb-button-accent" type="button" disabled>Send once</button></div>
          <div id="wbMessage" class="wb-status" role="status">Set scope, then preview a request.</div>
        </form>
        <div class="wb-card" id="wbPreviewPanel" hidden><div class="wb-card-title"><h3>Action preview</h3><span>Expires after 5 minutes</span></div><pre id="wbPreviewText"></pre><p id="wbPreviewNote"></p></div>
        <div class="wb-card" id="wbResponsePanel" hidden><div class="wb-card-title"><h3>Response</h3><span id="wbResponseMeta"></span></div><div id="wbObservations" class="wb-observations"></div><details open><summary>Headers</summary><pre id="wbResponseHeaders"></pre></details><details open><summary>Body preview</summary><pre id="wbResponseBody"></pre></details><p id="wbResponseLimit"></p><button id="wbCompare" class="wb-button wb-button-quiet" type="button" disabled>Compare last two responses</button><pre id="wbCompareResult" hidden></pre></div>
      </div>
      <aside><div class="wb-card wb-history"><div class="wb-card-title"><h3>Project history</h3><button id="wbExport" class="wb-button wb-button-quiet" type="button">Export JSON</button></div><p>Recent request metadata only. Headers and bodies are not saved; URLs may contain sensitive query values.</p><div id="wbHistoryList" class="wb-history-list"></div></div>
      <div class="wb-card"><h3>Decoder</h3><p>Transform text locally in this browser. No request is sent.</p><textarea id="wbDecodeInput" class="tools-input wb-decoder-input" rows="4" placeholder="Paste text to encode or decode"></textarea><div class="wb-decoder-actions"><button type="button" class="wb-button wb-button-quiet" data-transform="url-encode">URL encode</button><button type="button" class="wb-button wb-button-quiet" data-transform="url-decode">URL decode</button><button type="button" class="wb-button wb-button-quiet" data-transform="base64-encode">Base64 encode</button><button type="button" class="wb-button wb-button-quiet" data-transform="base64-decode">Base64 decode</button></div><pre id="wbDecodeOutput">Output appears here.</pre></div></aside>
    </div>`;
  root.insertAdjacentHTML('beforeend', `
    <div class="wb-advanced-grid">
      <div class="wb-card"><div class="wb-card-title"><h3>Proxy · Intercept</h3><span id="wbProxyAddr">Loading listener…</span></div>
        <p>Set your browser's HTTP proxy to the loopback address shown here. Only the authorized project scope is accepted. HTTPS CONNECT tunnels pass through without decrypting content.</p>
        <div class="wb-actions"><button id="wbInterceptToggle" class="wb-button" type="button">Turn Intercept on</button><button id="wbProxyRefresh" class="wb-button wb-button-quiet" type="button">Refresh queue</button></div>
        <div id="wbProxyMessage" class="wb-status" role="status"></div><div id="wbPending" class="wb-pending"></div>
      </div>
      <div class="wb-card"><div class="wb-card-title"><h3>HTTP history</h3><span>Scope-bound traffic</span></div>
        <p>Repeater, proxy, and Intruder request metadata appear in Project history above. Select a row to load its URL into Repeater.</p>
      </div>
      <div class="wb-card"><div class="wb-card-title"><h3>Intruder</h3><span>Bounded request testing</span></div>
        <p>Use the Repeater request as a template. Put <code>{{1}}</code> (up to <code>{{4}}</code>) in the URL, a header value, or body. Sniper tests each position separately; Battering ram sends the same payload to all positions. Maximum 12 payloads and 24 requests, sequentially.</p>
        <div class="wb-row"><select id="wbIntruderMode" class="tools-input"><option value="sniper">Sniper</option><option value="battering_ram">Battering ram</option></select><button id="wbIntruderCopy" class="wb-button wb-button-quiet" type="button">Copy Repeater request</button></div>
        <label class="wb-label">Template URL<input id="wbIntruderUrl" class="tools-input" type="text" placeholder="https://example.com/search?q={{1}}"></label>
        <label class="wb-label">Template headers<textarea id="wbIntruderHeaders" class="tools-input" rows="3" placeholder="X-Test: {{2}}"></textarea></label>
        <label class="wb-label">Template body<textarea id="wbIntruderBody" class="tools-input" rows="3"></textarea></label>
        <label class="wb-label">Payloads <span>One text value per line. URL-encode characters where appropriate.</span><textarea id="wbIntruderPayloads" class="tools-input" rows="5" placeholder="sample\ntest\n123"></textarea></label>
        <div class="wb-actions"><button id="wbIntruderPreview" class="wb-button" type="button">Preview Intruder</button><label class="wb-check"><input id="wbIntruderApprove" type="checkbox" disabled> I reviewed this run.</label><button id="wbIntruderStart" class="wb-button wb-button-accent" type="button" disabled>Start run</button><button id="wbIntruderCancel" class="wb-button wb-button-quiet" type="button" disabled>Cancel</button></div>
        <div id="wbIntruderMessage" class="wb-status" role="status"></div><pre id="wbIntruderSummary" hidden></pre><div id="wbIntruderResults"></div>
      </div>
      <div class="wb-card"><div class="wb-card-title"><h3>Browser preview</h3><span>Read-only HTML snapshot</span></div>
        <p>Fetch one scoped GET over verified HTTPS or HTTP. This preview blocks scripts, forms, links, and external assets; it is not a full interactive browser. For live browsing, configure a separate browser's HTTP proxy using the listener above.</p>
        <div class="wb-row"><input id="wbBrowserUrl" class="tools-input" type="url" placeholder="https://example.com/"><button id="wbBrowserPreview" class="wb-button" type="button">Preview GET</button><button id="wbBrowserFetch" class="wb-button wb-button-accent" type="button" disabled>Fetch page</button></div>
        <div id="wbBrowserMessage" class="wb-status" role="status"></div><pre id="wbBrowserRequest" hidden></pre><iframe id="wbBrowserFrame" title="Read-only page preview" sandbox="" referrerpolicy="no-referrer" hidden></iframe><details id="wbBrowserSource" hidden><summary>Response source</summary><pre id="wbBrowserText"></pre></details>
      </div>
    </div>`);

  const el = id => document.getElementById(id);
  const esc = value => String(value == null ? '' : value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let project = null, history = [], approval = null, lastResponse = null, previousResponse = null, busy = false;

  async function api(path, options) {
    const response = await fetch(path, options);
    if (!(response.headers.get('Content-Type') || '').toLowerCase().includes('application/json')) {
      throw new Error('Workbench API is unavailable on this server. Restart the dashboard server, then reload this page.');
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  }
  const post = (path, data) => api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
  function message(text, error = false) { el('wbMessage').textContent = text; el('wbMessage').classList.toggle('wb-error', error); }
  function invalidate() {
    approval = null;
    el('wbApprove').checked = false;
    el('wbApprove').disabled = true;
    el('wbSend').disabled = true;
    el('wbPreviewPanel').hidden = true;
  }
  function readRequest() {
    const headers = {};
    for (const raw of el('wbHeaders').value.split(/\r?\n/)) {
      if (!raw.trim()) continue;
      const index = raw.indexOf(':');
      if (index < 1) throw new Error('Use one Header-Name: value per line.');
      const key = raw.slice(0, index).trim();
      if (Object.keys(headers).some(existing => existing.toLowerCase() === key.toLowerCase())) throw new Error(`Duplicate header: ${key}`);
      headers[key] = raw.slice(index + 1).trim();
    }
    return {method:el('wbMethod').value, url:el('wbUrl').value.trim(), headers, body:el('wbBody').value};
  }
  function renderHistory() {
    const list = el('wbHistoryList');
    if (!history.length) { list.innerHTML = '<p class="wb-empty">No requests have been sent in this project.</p>'; return; }
    list.innerHTML = history.map((row, index) => `<button class="wb-history-item" type="button" data-index="${index}"><strong>${esc(row.method)} <span>${esc(row.status)}</span></strong><small>${esc(row.url)}</small><em>${esc(row.source || 'repeater')} · ${esc(row.elapsed_ms)} ms · ${esc(row.checked_at)}</em></button>`).join('');
    list.querySelectorAll('[data-index]').forEach(button => button.addEventListener('click', () => {
      const row = history[Number(button.dataset.index)];
      el('wbMethod').value = row.method;
      el('wbUrl').value = row.url;
      el('wbHeaders').value = '';
      el('wbBody').value = '';
      invalidate();
      message('History URL loaded. Add any needed headers or body, then preview again.');
    }));
  }
  async function refresh() {
    try {
      const state = await api('/api/workbench/state');
      project = state.project;
      history = state.history || [];
      el('wbScopeState').textContent = project ? `Enforced scope: ${project.scope_url}` : 'No project scope set.';
      el('wbScopeState').classList.remove('wb-error');
      if (project && !el('wbScope').value) el('wbScope').value = project.scope_url;
      if (project && !el('wbUrl').value) el('wbUrl').value = project.initial_url || project.scope_url;
      renderHistory();
    } catch (error) { el('wbScopeState').textContent = error.message; el('wbScopeState').classList.add('wb-error'); message(error.message, true); }
  }
  el('wbProjectForm').addEventListener('submit', async event => {
    event.preventDefault();
    const button = el('wbSetScope');
    button.disabled = true;
    button.textContent = 'Setting scope…';
    el('wbScopeState').textContent = 'Checking project scope…';
    el('wbScopeState').classList.remove('wb-error');
    try {
      const saved = await post('/api/workbench/project', {scope_url:el('wbScope').value.trim(), authorized:el('wbAuthorized').checked});
      project = saved;
      history = [];
      lastResponse = null;
      previousResponse = null;
      invalidate();
      el('wbResponsePanel').hidden = true;
      el('wbCompare').disabled = true;
      el('wbCompareResult').hidden = true;
      el('wbScopeState').textContent = `Enforced scope: ${saved.scope_url}`;
      el('wbScopeState').classList.remove('wb-error');
      el('wbUrl').value = saved.initial_url || saved.scope_url;
      renderHistory();
      message('Scope set. Preview the first request before sending.');
    } catch (error) { el('wbScopeState').textContent = error.message; el('wbScopeState').classList.add('wb-error'); message(error.message, true); }
    finally { button.disabled = false; button.textContent = 'Set scope'; }
  });
  ['wbMethod','wbUrl','wbHeaders','wbBody'].forEach(id => el(id).addEventListener('input', invalidate));
  el('wbRequestForm').addEventListener('submit', async event => {
    event.preventDefault();
    invalidate();
    try {
      if (!project) throw new Error('Set the authorized project scope first.');
      const result = await post('/api/workbench/preview', readRequest());
      approval = result.approval_token;
      el('wbPreviewText').textContent = result.request_preview;
      el('wbPreviewNote').textContent = `${result.note} Scope: ${result.scope_url}`;
      el('wbPreviewPanel').hidden = false;
      el('wbApprove').disabled = false;
      message('Review the preview and approve this exact request.');
    } catch (error) { message(error.message, true); }
  });
  el('wbApprove').addEventListener('change', () => { el('wbSend').disabled = !approval || !el('wbApprove').checked || busy; });
  el('wbSend').addEventListener('click', async () => {
    if (!approval || !el('wbApprove').checked || busy) return;
    busy = true;
    el('wbSend').disabled = true;
    try {
      const result = await post('/api/workbench/send', {...readRequest(), approval_token:approval});
      previousResponse = lastResponse;
      lastResponse = result;
      invalidate();
      el('wbResponsePanel').hidden = false;
      el('wbResponseMeta').textContent = `${result.status} ${result.reason} · ${result.elapsed_ms} ms`;
      el('wbObservations').innerHTML = result.observations.length
        ? `<strong>Passive observations · not confirmed vulnerabilities</strong><ul>${result.observations.map(note => `<li>${esc(note)}</li>`).join('')}</ul>`
        : '<strong>No passive header observations for this response.</strong>';
      el('wbResponseHeaders').textContent = result.headers.map(([key,value]) => `${key}: ${value}`).join('\n');
      el('wbResponseBody').textContent = result.body_preview;
      el('wbResponseLimit').textContent = result.body_truncated ? 'Body preview truncated at 64 KiB.' : `Sample SHA-256: ${result.body_sha256}`;
      el('wbCompare').disabled = !previousResponse;
      el('wbCompareResult').hidden = true;
      message(`Request completed: HTTP ${result.status}. No vulnerability is automatically confirmed.`);
      await refresh();
    } catch (error) { invalidate(); message(error.message, true); }
    finally { busy = false; }
  });
  el('wbExport').addEventListener('click', () => {
    const exportData = {project, history, latest_response: lastResponse && {
      method:lastResponse.method, url:lastResponse.url, status:lastResponse.status,
      elapsed_ms:lastResponse.elapsed_ms, headers:lastResponse.headers,
      body_sha256:lastResponse.body_sha256, body_truncated:lastResponse.body_truncated,
      observations:lastResponse.observations, checked_at:lastResponse.checked_at,
      confirmed_vulnerabilities:0
    }};
    const url = URL.createObjectURL(new Blob([JSON.stringify(exportData, null, 2)], {type:'application/json'}));
    const link = document.createElement('a'); link.href=url; link.download='http-workbench-history.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  el('wbCompare').addEventListener('click', () => {
    if (!previousResponse || !lastResponse) return;
    const a = previousResponse.body_preview, b = lastResponse.body_preview;
    let index = 0;
    while (index < Math.min(a.length, b.length) && a[index] === b[index]) index++;
    const summary = [
      `Previous: ${previousResponse.status} ${previousResponse.url}`,
      `Current:  ${lastResponse.status} ${lastResponse.url}`,
      `Previous sample SHA-256: ${previousResponse.body_sha256}`,
      `Current sample SHA-256:  ${lastResponse.body_sha256}`,
      a === b ? 'Body previews match.' : `First differing character: ${index + 1}`,
      a === b ? '' : `Previous excerpt: ${JSON.stringify(a.slice(Math.max(0,index-40), index+100))}`,
      a === b ? '' : `Current excerpt:  ${JSON.stringify(b.slice(Math.max(0,index-40), index+100))}`,
      (previousResponse.body_truncated || lastResponse.body_truncated) ? 'At least one preview was truncated; comparison is partial.' : ''
    ].filter(Boolean).join('\n');
    el('wbCompareResult').textContent = summary;
    el('wbCompareResult').hidden = false;
  });
  root.querySelectorAll('[data-transform]').forEach(button => button.addEventListener('click', () => {
    try {
      const value = el('wbDecodeInput').value;
      let output;
      switch (button.dataset.transform) {
        case 'url-encode': output = encodeURIComponent(value); break;
        case 'url-decode': output = decodeURIComponent(value); break;
        case 'base64-encode': {
          const bytes = new TextEncoder().encode(value);
          let binary = '';
          for (const byte of bytes) binary += String.fromCharCode(byte);
          output = btoa(binary);
          break;
        }
        case 'base64-decode': output = new TextDecoder('utf-8', {fatal:true}).decode(Uint8Array.from(atob(value), c => c.charCodeAt(0))); break;
        default: return;
      }
      el('wbDecodeOutput').textContent = output;
    } catch (error) { el('wbDecodeOutput').textContent = error.message; }
  }));
  let advanced = null, intruderApproval = null, intruderRun = null, browserApproval = null;
  function headersFromText(value) {
    const headers = {};
    for (const raw of value.split(/\r?\n/)) {
      if (!raw.trim()) continue;
      const index = raw.indexOf(':');
      if (index < 1) throw new Error('Use Header-Name: value on each line.');
      headers[raw.slice(0, index).trim()] = raw.slice(index + 1).trim();
    }
    return headers;
  }
  function intruderData() {
    return {mode:el('wbIntruderMode').value, request:{method:el('wbMethod').value,
      url:el('wbIntruderUrl').value.trim(), headers:headersFromText(el('wbIntruderHeaders').value),
      body:el('wbIntruderBody').value}, payloads:el('wbIntruderPayloads').value.split(/\r?\n/).map(x => x.trim()).filter(Boolean)};
  }
  function invalidateIntruder() {
    intruderApproval = null;
    el('wbIntruderApprove').checked = false;
    el('wbIntruderApprove').disabled = true;
    el('wbIntruderStart').disabled = true;
    el('wbIntruderSummary').hidden = true;
  }
  ['wbIntruderMode','wbIntruderUrl','wbIntruderHeaders','wbIntruderBody','wbIntruderPayloads','wbMethod'].forEach(id => el(id).addEventListener('input', invalidateIntruder));
  el('wbIntruderCopy').addEventListener('click', () => {
    el('wbIntruderUrl').value = el('wbUrl').value;
    el('wbIntruderHeaders').value = el('wbHeaders').value;
    el('wbIntruderBody').value = el('wbBody').value;
    invalidateIntruder();
    el('wbIntruderMessage').textContent = 'Template copied. Add {{1}} at an injection position.';
  });
  el('wbIntruderPreview').addEventListener('click', async () => {
    invalidateIntruder();
    try {
      const result = await post('/api/workbench/advanced/intruder/preview', intruderData());
      intruderApproval = result.approval_token;
      el('wbIntruderSummary').textContent = `${result.mode}: ${result.request_count} requests across ${result.positions.join(', ')}\nFirst request:\n${result.first_request}\n${result.note}`;
      el('wbIntruderSummary').hidden = false;
      el('wbIntruderApprove').disabled = false;
      el('wbIntruderMessage').textContent = 'Review the exact run and check approval.';
    } catch (error) { el('wbIntruderMessage').textContent = error.message; }
  });
  el('wbIntruderApprove').addEventListener('change', () => {
    el('wbIntruderStart').disabled = !intruderApproval || !el('wbIntruderApprove').checked;
  });
  el('wbIntruderStart').addEventListener('click', async () => {
    if (!intruderApproval || !el('wbIntruderApprove').checked) return;
    el('wbIntruderStart').disabled = true;
    try {
      const result = await post('/api/workbench/advanced/intruder/start', {...intruderData(), approval_token:intruderApproval});
      intruderRun = result.id;
      invalidateIntruder();
      el('wbIntruderCancel').disabled = false;
      el('wbIntruderMessage').textContent = `Running ${result.total} requests, one at a time.`;
      await refreshAdvanced();
    } catch (error) { el('wbIntruderMessage').textContent = error.message; }
  });
  el('wbIntruderCancel').addEventListener('click', async () => {
    if (!intruderRun) return;
    try { await post('/api/workbench/advanced/intruder/cancel', {id:intruderRun});
      el('wbIntruderMessage').textContent = 'Cancelling after the current request.';
    } catch (error) { el('wbIntruderMessage').textContent = error.message; }
  });
  function renderIntruder() {
    const run = advanced && advanced.runs.find(item => item.id === intruderRun);
    if (!run) return;
    el('wbIntruderMessage').textContent = `${run.status}: ${run.results.length}/${run.total} requests. Different responses require manual validation; no vulnerability is confirmed automatically.`;
    el('wbIntruderCancel').disabled = run.status !== 'running';
    el('wbIntruderResults').innerHTML = `<div class="wb-table-wrap"><table class="wb-table"><thead><tr><th>Position</th><th>Payload</th><th>Status</th><th>Sample bytes</th><th>Time</th><th>Sample SHA-256</th></tr></thead><tbody>${run.results.map(row => `<tr><td>${esc(row.position)}</td><td>${esc(row.payload)}</td><td>${esc(row.status ?? row.error)}</td><td>${esc(row.body_truncated ? '≥' + row.body_bytes : (row.body_bytes ?? ''))}</td><td>${esc(row.elapsed_ms ?? '')}</td><td><code>${esc(row.body_sha256 || '')}</code></td></tr>`).join('')}</tbody></table></div>`;
    if (run.status !== 'running') refresh();
  }
  function renderPending() {
    const box = el('wbPending');
    if (!advanced.pending.length) { box.innerHTML = '<p class="wb-empty">No intercepted HTTP requests.</p>'; return; }
    box.innerHTML = advanced.pending.map(item => `<div class="wb-pending-item" data-id="${esc(item.id)}"><strong>${esc(item.method)} ${esc(item.url)}</strong><label>Method<input class="tools-input wb-p-method" value="${esc(item.request.method)}"></label><label>URL<input class="tools-input wb-p-url" value="${esc(item.request.url)}"></label><label>Headers<textarea class="tools-input wb-p-headers" rows="3">${esc(Object.entries(item.request.headers).map(([k,v]) => `${k}: ${v}`).join('\n'))}</textarea></label><label>Body<textarea class="tools-input wb-p-body" rows="3">${esc(item.request.body)}</textarea></label><div class="wb-actions"><button class="wb-button wb-p-forward" type="button">Forward</button><button class="wb-button wb-button-quiet wb-p-drop" type="button">Drop</button></div></div>`).join('');
    box.querySelectorAll('.wb-pending-item').forEach(card => {
      const id = card.dataset.id;
      card.querySelector('.wb-p-forward').addEventListener('click', async () => {
        try {
          const request = {method:card.querySelector('.wb-p-method').value.toUpperCase(), url:card.querySelector('.wb-p-url').value.trim(), headers:headersFromText(card.querySelector('.wb-p-headers').value), body:card.querySelector('.wb-p-body').value};
          await post('/api/workbench/advanced/decision', {id, action:'forward', request});
          el('wbProxyMessage').textContent = 'Request forwarded.';
          await refreshAdvanced();
        } catch (error) { el('wbProxyMessage').textContent = error.message; }
      });
      card.querySelector('.wb-p-drop').addEventListener('click', async () => {
        try { await post('/api/workbench/advanced/decision', {id, action:'drop'});
          el('wbProxyMessage').textContent = 'Request dropped.'; await refreshAdvanced();
        } catch (error) { el('wbProxyMessage').textContent = error.message; }
      });
    });
  }
  async function refreshAdvanced() {
    try {
      const next = await api('/api/workbench/advanced/state');
      const pendingChanged = !advanced || JSON.stringify(next.pending) !== JSON.stringify(advanced.pending);
      advanced = next;
      el('wbProxyAddr').textContent = next.proxy_port ? `127.0.0.1:${next.proxy_port}` : 'Listener unavailable';
      el('wbInterceptToggle').textContent = next.intercept ? 'Turn Intercept off' : 'Turn Intercept on';
      el('wbInterceptToggle').classList.toggle('wb-button-accent', next.intercept);
      if (pendingChanged) renderPending();
      renderIntruder();
    } catch (error) { el('wbProxyMessage').textContent = error.message; }
  }
  el('wbInterceptToggle').addEventListener('click', async () => {
    try { await post('/api/workbench/advanced/intercept', {enabled:!advanced.intercept});
      el('wbProxyMessage').textContent = !advanced.intercept ? 'Intercept enabled.' : 'Intercept disabled; queued requests dropped.';
      await refreshAdvanced();
    } catch (error) { el('wbProxyMessage').textContent = error.message; }
  });
  el('wbProxyRefresh').addEventListener('click', async () => { await refreshAdvanced(); await refresh(); });
  el('wbBrowserUrl').addEventListener('input', () => { browserApproval = null; el('wbBrowserFetch').disabled = true; el('wbBrowserRequest').hidden = true; });
  el('wbBrowserPreview').addEventListener('click', async () => {
    browserApproval = null;
    el('wbBrowserFetch').disabled = true;
    try {
      const result = await post('/api/workbench/preview', {method:'GET', url:el('wbBrowserUrl').value.trim(), headers:{}, body:''});
      browserApproval = result.approval_token;
      el('wbBrowserRequest').textContent = result.request_preview;
      el('wbBrowserRequest').hidden = false;
      el('wbBrowserFetch').disabled = false;
      el('wbBrowserMessage').textContent = 'Review the GET above, then fetch once.';
    } catch (error) { el('wbBrowserMessage').textContent = error.message; }
  });
  el('wbBrowserFetch').addEventListener('click', async () => {
    if (!browserApproval) return;
    el('wbBrowserFetch').disabled = true;
    try {
      const result = await post('/api/workbench/send', {method:'GET', url:el('wbBrowserUrl').value.trim(), headers:{}, body:'', approval_token:browserApproval});
      browserApproval = null;
      el('wbBrowserMessage').textContent = `HTTP ${result.status} · ${result.elapsed_ms} ms · ${result.body_truncated ? 'first 64 KiB only' : 'complete sample'}.`;
      el('wbBrowserText').textContent = result.body_preview;
      el('wbBrowserSource').hidden = false;
      const html = (result.headers.find(([k]) => k.toLowerCase() === 'content-type') || ['', ''])[1].toLowerCase().includes('text/html');
      el('wbBrowserFrame').hidden = !html;
      if (html) el('wbBrowserFrame').srcdoc = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><meta name="referrer" content="no-referrer">' + result.body_preview;
      await refresh();
    } catch (error) { el('wbBrowserMessage').textContent = error.message; }
  });
  refreshAdvanced();
  setInterval(() => { if (!document.hidden) refreshAdvanced(); }, 2500);
  refresh();
});
