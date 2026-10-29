/* Recorded scan review: no target requests are made by this viewer. */
(function (root) {
  'use strict';
  const policies = {
    'Content-Security-Policy': ["default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'", 'Mulai dengan Content-Security-Policy-Report-Only di staging. Catat sumber skrip, gaya, gambar, dan koneksi yang memang diperlukan. Gunakan nonce atau hash untuk skrip inline yang sah. Uji login dan konten tersemat sebelum menerapkan kebijakan.'],
    'Strict-Transport-Security': ['max-age=300', 'Pastikan semua halaman memakai HTTPS yang valid. Mulai dengan masa singkat di staging, lalu tingkatkan setelah pemeriksaan. Tambahkan includeSubDomains hanya jika seluruh subdomain sudah siap HTTPS; jangan aktifkan preload secara otomatis.'],
    'X-Content-Type-Options': ['nosniff', 'Pastikan Content-Type untuk skrip, gaya, dan unduhan sudah benar. Uji aplikasi setelah mengaktifkan nosniff.'],
    'X-Frame-Options': ['SAMEORIGIN', 'Periksa apakah situs memang perlu ditampilkan di dalam frame. Untuk browser modern, atur CSP frame-ancestors. Pastikan hanya ada satu kebijakan yang sesuai dengan kebutuhan.'],
    'Referrer-Policy': ['strict-origin-when-cross-origin', 'Pilih informasi referrer yang memang dibutuhkan dan jangan menaruh rahasia di URL. Header ini tidak ada saja belum membuktikan kebocoran data.'],
    'Permissions-Policy': ['camera=(), microphone=(), geolocation=()', 'Izinkan hanya fitur browser yang dipakai aplikasi. Uji alur kamera, mikrofon, dan lokasi sebelum menerapkan aturan. Ketiadaan header saja bukan bukti eksploitasi.']
  };
  const translations = {
    'Server': ['Kurangi detail banner web server, sembunyikan nomor versi bila memungkinkan, dan tetap pasang pembaruan keamanan. Informasi versi saja tidak membuktikan server rentan.'],
    'X-Powered-By': ['Matikan header X-Powered-By melalui konfigurasi PHP atau framework, lalu pastikan versi runtime tetap diperbarui. Pengungkapan teknologi saja bukan bukti kerentanan.'],
    'Cookie': ['Untuk cookie sesi pada HTTPS, aktifkan Secure dan HttpOnly. Pilih SameSite=Lax atau Strict sesuai alur login dan integrasi. Uji login, logout, serta alur lintas situs yang sah.']
  };
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  function safeUrl(value) {
    try { const u = new URL(value); return /^https?:$/.test(u.protocol) && !u.username && !u.password ? u.href : null; } catch (_) { return null; }
  }
  function command(url) {
    const u = safeUrl(url);
    if (!u) return 'No valid HTTP(S) URL recorded.';
    // PowerShell single-quoted argument: no interpolation or command substitution.
    return "curl.exe --silent --show-error --max-time 15 --dump-header - --output NUL --url '" + u.replace(/'/g, "''") + "'";
  }
  function review(asset, scan) {
    const findings = (scan.findings || []).filter(f => f.affected_component === asset.host);
    const url = safeUrl(asset.url || asset.final_url || ((asset.ssl ? 'https://' : 'http://') + asset.host));
    return {asset, findings, url, command: command(url), captured: asset.observed_at || scan.observed_at || 'Not recorded (saved result)'};
  }
  function findingHtml(f) {
    const header = Object.keys(policies).find(h => (f.title || '').includes(h));
    const policy = policies[header];
    const kind = /x-powered-by/i.test(f.title || '') ? 'X-Powered-By' : (/server/i.test(f.title || '') ? 'Server' : (/cookie|session/i.test(f.title || '') ? 'Cookie' : null));
    const tutorial = policy ? policy[1] : ((kind && translations[kind]) ? translations[kind][0] : (f.remediation || 'Tinjau konfigurasi yang terdampak bersama pemilik aplikasi.'));
    const demo = header === 'Content-Security-Policy' ? `<details class="ar-payload"><summary>Pratinjau payload XSS (contoh lokal)</summary><p>Contoh ini hanya ditampilkan sebagai teks di dashboard. Tidak dikirim ke target dan tidak dijalankan.</p><pre>&lt;script&gt;alert('contoh XSS')&lt;/script&gt;</pre><p><strong>Gambaran mitigasi:</strong> kebijakan dengan <code>script-src 'self'</code> tanpa <code>'unsafe-inline'</code> semestinya memblokir skrip inline ini. CSP adalah lapisan tambahan; tetap lakukan output encoding sesuai konteks dan hindari memasukkan input pengguna ke HTML dengan API yang menjalankan markup.</p><p>Untuk teks HTML di PHP, encode nilai saat ditampilkan, misalnya <code>htmlspecialchars($input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')</code>. Sesuaikan encoding dengan konteks HTML, atribut, JavaScript, atau URL.</p><p>CSP membantu membatasi eksekusi skrip di browser. CSP tidak mencegah SQL injection dan tidak menggantikan validasi input atau output encoding.</p><p>Untuk pengujian, pemilik aplikasi perlu memakai salinan staging dan memeriksa pelanggaran CSP di Console atau endpoint laporan.</p></details>` : '';
    const sample = policy ? `<pre>${esc(header + ': ' + policy[0])}</pre><p>Contoh nilai awal. Sesuaikan daftar sumber dengan aplikasi dan uji lebih dulu di staging.</p>` : '';
    return `<article class="ar-finding"><h3>${esc(f.title || 'Temuan')}</h3><p class="ar-muted">${esc(f.severity || 'INFO')} · Observasi scanner · Dampak perlu divalidasi</p><p>${esc(f.evidence || f.description || 'Bukti pendukung tidak tercatat.')}</p><details open><summary>Tutorial mitigasi</summary><ol><li>Konfirmasi header pada respons yang terdampak. Tentukan apakah konfigurasi dikelola aplikasi, web server, reverse proxy, atau CDN.</li><li>${esc(tutorial)}</li><li>Cadangkan konfigurasi dan terapkan perubahan di staging.${sample}</li><li>Terapkan melalui proses review normal. Ulangi pemeriksaan respons, periksa header, lalu uji fungsi aplikasi terkait.</li><li>Jalankan pemeriksaan baru dan bandingkan bukti. Catat waktu verifikasi dan penanggung jawab. Jika ada gangguan, sesuaikan kebijakan sebelum penerapan ulang.</li></ol>${demo}</details></article>`;
  }
  function show(asset, scan) {
    const model = review(asset, scan);
    let dialog = document.getElementById('assetReviewDialog');
    if (!dialog) { dialog = document.createElement('dialog'); dialog.id = 'assetReviewDialog'; dialog.className = 'ar-dialog'; document.body.append(dialog); }
    dialog.innerHTML = `<header><div><p class="ar-eyebrow">KELOMPOK ASET / TINJAUAN PEMINDAIAN</p><h2>${esc(asset.host)}</h2></div><button type="button" data-close aria-label="Tutup tinjauan aset">Tutup ✕</button></header><p class="ar-muted">Diambil: ${esc(model.captured)} · ${asset.error ? 'TIDAK LENGKAP' : 'Observasi tercatat'}</p><nav aria-label="Bagian tinjauan"><button data-tab="evidence">Pratinjau bukti</button><button data-tab="poc">PoC / reproduksi</button><button data-tab="fix">Tutorial mitigasi (${model.findings.length})</button></nav><section data-panel="evidence"><h3>Bukti aset yang tercatat</h3><p>Ini pratinjau bukti pemindaian. Screenshot target tidak diambil.</p><dl><dt>Status HTTP</dt><dd>${esc(asset.status ?? 'Tidak diketahui')}</dd><dt>IP</dt><dd>${esc(asset.ip || 'Tidak dikumpulkan')}</dd><dt>Port yang dilaporkan</dt><dd>${esc(asset.ports || 'Tidak tercatat')}</dd><dt>Kedaluwarsa sertifikat TLS</dt><dd>${esc(asset.tls || 'Tidak dikumpulkan')}</dd></dl>${asset.error ? `<p class="ar-warning">${esc(asset.error)}</p>` : ''}<h3>Observasi header keamanan</h3><pre>${esc((asset.missing_headers || []).map(h => 'Dilaporkan tidak ada: ' + h).join('\n') || 'Tidak ada header hilang yang tercatat. Ini tidak membuktikan target aman.')}</pre><h3>Subset header yang direkam</h3><pre>${esc(asset.response_headers ? JSON.stringify(asset.response_headers, null, 2) : 'Header respons mentah tidak disimpan dalam hasil ini.')}</pre><p class="ar-warning">Cakupan: penemuan host, port terpilih, dan konfigurasi HTTP. Autentikasi, otorisasi, serta logika bisnis memerlukan pengujian terpisah.${(scan.coverage_gaps || []).length ? ' Celah cakupan: ' + esc(scan.coverage_gaps.join('; ')) : ''}</p></section><section data-panel="poc" hidden><h3>Reproduksi baca-saja · PowerShell</h3><p>Perintah ini disediakan untuk reproduksi manual dan tidak dijalankan oleh pratinjau. Perintah mengirim satu GET tanpa mengikuti redirect.</p><pre>${esc(model.command)}</pre><button data-copy>Salin perintah</button><p>Bandingkan status dan header aktual dengan observasi. Jika ada redirect, tinjau Location dan scope sebelum meminta alamat tujuan. Header yang tidak ada adalah bukti konfigurasi, bukan bukti eksploitasi.</p></section><section data-panel="fix" hidden>${model.findings.map(findingHtml).join('') || '<p>Tidak ada temuan untuk aset ini. Tinjau cakupan dan error sebelum menarik kesimpulan.</p>'}<p><a href="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer">Panduan header HTTP OWASP</a></p></section><footer><button data-export>Unduh JSON bukti</button></footer>`;
    dialog.querySelector('[data-close]').onclick = () => dialog.close();
    dialog.querySelectorAll('[data-tab]').forEach(b => { b.onclick = () => { dialog.querySelectorAll('[data-panel]').forEach(p => { p.hidden = p.dataset.panel !== b.dataset.tab; }); dialog.querySelectorAll('[data-tab]').forEach(t => t.setAttribute('aria-pressed', String(t === b))); }; });
    dialog.querySelector('[data-tab]').click();
    dialog.querySelector('[data-copy]').onclick = async e => { try { await navigator.clipboard.writeText(model.command); e.target.textContent = 'Copied'; } catch (_) { e.target.textContent = 'Select and copy the command above'; } };
    dialog.querySelector('[data-export]').onclick = () => { const href = URL.createObjectURL(new Blob([JSON.stringify(model, null, 2)], {type:'application/json'})); const a = document.createElement('a'); a.href = href; a.download = 'asset-evidence.json'; a.click(); setTimeout(() => URL.revokeObjectURL(href), 1000); };
    dialog.showModal();
  }
  root.AssetReview = {show, review, command, safeUrl, findingHtml};
  if (typeof module !== 'undefined') module.exports = root.AssetReview;
})(typeof window === 'undefined' ? globalThis : window);
