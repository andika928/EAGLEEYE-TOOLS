document.addEventListener('DOMContentLoaded', () => {
  'use strict';
  const slot = document.getElementById('dalfoxTool');
  if (!slot) return;
  const esc = x => String(x == null ? '' : x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let available = false, busy = false, latest = null, timer;
  slot.innerHTML = `<div class="sq-heading"><div><p class="sq-eyebrow">SEPARATE TOOL / CROSS-SITE SCRIPTING</p><h2>Dalfox XSS evidence desk</h2></div><span id="dfAvailability" role="status">Checking Dalfox…</span></div>
    <p>Enter one URL. Dalfox tests the supplied URL and may discover parameters on that same origin. The preview makes no requests. Native runs use one worker, a 1 request/second cap, same-origin scope, at most 5 discovered targets and 10 base payloads per parameter, and a 2-minute process limit; redirects and remote wordlists are off. Scanner output stays unconfirmed until reviewed.</p>
    <form id="dfForm"><div class="sq-fields"><label>Target URL<input id="dfTarget" class="tools-input" type="url" placeholder="https://example.com/search" required></label></div>
    <p id="dfPreview" class="sq-detected">Enter a URL to preview its hostname and query parameters. No requests are made by this preview.</p>
    <label class="sq-auth"><input id="dfAuthorized" type="checkbox" required> I own this target or have explicit authorization to run active XSS tests.</label>
    <div class="sq-actions"><button id="dfRun" class="tools-run-btn" disabled>Run Dalfox</button><button id="dfRefresh" type="button" class="site-gate-btn">Refresh results</button></div></form>
    <p class="sq-note">False-positive controls: fixed same-origin scope, bounded request rate, no redirect following, raw report evidence, and Dalfox tier display. No scanner result is independently confirmed here; zero false positives cannot be guaranteed.</p>
    <div id="dfResult" aria-live="polite"></div>
    <details class="sq-guide" open><summary>XSS mitigation tutorial</summary><ol>
      <li><strong>Find the output context.</strong> Trace the affected URL parameter into the response and identify whether it reaches HTML text, an attribute, JavaScript, CSS, or a URL.</li>
      <li><strong>Prefer safe DOM APIs.</strong> Render untrusted text with <code>textContent</code> or framework auto-escaping. Avoid <code>innerHTML</code>, <code>document.write</code>, and string-built event handlers.</li>
      <li><strong>Encode for the exact context.</strong> Use the framework’s context-aware output encoder at the final output point. HTML encoding alone is not safe for JavaScript, CSS, or URL contexts.</li>
      <li><strong>Sanitize required rich HTML.</strong> Use a maintained allowlist sanitizer and safe URL schemes. Do not try to remove dangerous strings with regular expressions.</li>
      <li><strong>Add defense in depth.</strong> Deploy a restrictive Content-Security-Policy with nonces or hashes, then test it in report-only mode before enforcement. CSP supplements output handling; it does not replace it.</li>
      <li><strong>Retest in staging.</strong> Reproduce the exact parameter and browser context, compare a negative control, verify script execution does not occur, and add a regression test for the fixed output path.</li>
    </ol><a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer">OWASP XSS Prevention Cheat Sheet</a> · <a href="https://github.com/hahwul/dalfox/blob/main/docs/content/reference/cli.md" target="_blank" rel="noopener noreferrer">Dalfox CLI reference</a></details>`;
  const el = id => document.getElementById(id);
  function buttons() { el('dfRun').disabled = !available || busy; el('dfRun').textContent = busy ? 'Dalfox running…' : 'Run Dalfox'; }
  async function request(path, options) { const r = await fetch(path, options); const d = await r.json(); if (!r.ok) throw Error(d.error || `HTTP ${r.status}`); return d; }
  function render(r) {
    latest = r;
    busy = ['queued','running'].includes(r.state);
    buttons();
    if (r.state === 'not_run') { el('dfResult').innerHTML = '<p class="sq-empty">No Dalfox run yet. Evidence, observations, and browser-reproduction notes will appear here.</p>'; return; }
    const results = (r.results || []).map(x => `<section class="sq-observation"><h4>${esc(x.title)}</h4><p>${esc(x.status)} · Dalfox tier ${esc(x.dalfox_tier || 'unknown')} · ${esc(x.location)}</p><p>Scanner severity: ${esc(x.reported_severity)} · Independently confirmed: no</p><p>${esc(x.validation_required)}</p><details><summary>Evidence preview / scanner PoC</summary><pre>${esc(x.evidence_excerpt || 'Dalfox did not include a raw response excerpt.')}</pre><p>Evidence SHA-256: ${esc(x.evidence_sha256 || 'Not provided')}</p><p>The location and payload are a reproduction lead. Verify execution in an isolated browser with a control before calling this XSS.</p></details></section>`).join('');
    const args = r.command_argv ? `<details><summary>PoC / reproduce this bounded check</summary><p>This re-runs active testing against the supplied authorized origin. Use the exact URL and inspect Dalfox’s raw report; this is not a confirmed exploit.</p><pre>${esc(JSON.stringify(r.command_argv, null, 2))}</pre></details>` : '';
    const endpoints = (r.results || []).map(x => x.location).filter((x, i, a) => a.indexOf(x) === i);
    el('dfResult').innerHTML = `<article class="sq-report"><p class="sq-eyebrow">${esc(r.verdict || 'PENDING')} · ${esc(r.state)}</p><h3>${esc(r.target)}</h3><p>Scope: exact hostname <strong>${esc(r.scope_host || '')}</strong> · Elapsed: ${esc(r.elapsed_seconds || 0)}s · Finished: ${esc(r.finished_at || 'Pending')}</p><p>${esc(r.reason || 'Collecting scan evidence.')}</p>${endpoints.length ? `<details open><summary>Observed URLs (${endpoints.length})</summary><ul>${endpoints.map(x => `<li><code>${esc(x)}</code></li>`).join('')}</ul></details>` : ''}<p>Scanner observations: ${(r.results || []).length} · Confirmed vulnerabilities: 0</p>${results}<details><summary>Evidence preview / scan metadata</summary><pre>${esc(JSON.stringify({metadata:r.scan_metadata || {},source_sha256:r.source_sha256 || null,log_sha256:r.evidence_sha256 || null},null,2))}</pre></details>${args}<details><summary>Dalfox source log</summary><pre>${esc(r.log || 'No log collected.')}</pre></details>${r.save_error ? `<p>${esc(r.save_error)}</p>` : ''}<button id="dfExport" type="button" class="site-gate-btn">Download Dalfox report</button></article>`;
    el('dfExport').onclick = () => { const href = URL.createObjectURL(new Blob([JSON.stringify(latest,null,2)],{type:'application/json'})); const a=document.createElement('a'); a.href=href; a.download='dalfox-evidence.json'; a.click(); setTimeout(()=>URL.revokeObjectURL(href),1000); };
  }
  async function refresh() {
    clearTimeout(timer);
    try { const status = await request('/api/dalfox/status'); available=status.available; el('dfAvailability').textContent=available?'Dalfox v3 installed':'Dalfox unavailable — install v3 or configure RECONGUARD_DALFOX'; render(await request('/api/dalfox/results')); }
    catch(e) { el('dfAvailability').textContent=e.message; buttons(); }
    if (busy) timer=setTimeout(refresh,1500);
  }
  el('dfTarget').addEventListener('input', () => {
    try { const u=new URL(el('dfTarget').value); if (!['http:','https:'].includes(u.protocol)||u.username||u.password) throw Error(); const params=[...new Set(u.searchParams.keys())]; el('dfPreview').textContent='Target: '+u.hostname+' · '+(params.length?'Detected URL parameters: '+params.join(', '):'No query parameters. Dalfox discovery/mining remains enabled for this same origin after you authorize the run; preview makes no requests.'); }
    catch (_) { el('dfPreview').textContent='Enter a valid HTTP(S) URL without embedded credentials.'; }
  });
  el('dfForm').onsubmit=async e=>{e.preventDefault();if(busy)return;busy=true;buttons();try{render(await request('/api/dalfox/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:el('dfTarget').value,authorized:el('dfAuthorized').checked})}));timer=setTimeout(refresh,500);}catch(err){busy=false;buttons();el('dfResult').textContent=err.message;}};
  el('dfRefresh').onclick=refresh;
  refresh();
});
