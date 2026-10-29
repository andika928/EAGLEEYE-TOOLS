# ReconGuard: one automatic scan pipeline

Dalfox and Nikto are integrated into the existing **Launch Calibrated Recon Pipeline** button. There is no separate tool panel, tool selector, checkbox, or report file chooser in ReconGuard.

The stage order is Scope Guard → Subfinder → Httpx → Calibrated Ffuf → Dalfox → Nikto → Evidence. Both new stages are scheduled automatically for the supplied target, using the existing scope/exclusions. Tool observations appear in the same Findings & Evidence list, counters, telemetry and existing Markdown export. Original HTTP scheme, port and path are retained for the external stages when explicitly supplied.

Run `python server.py` and open the printed localhost URL, then select ReconGuard in the sidebar. The server finds a free port starting at 8080. Restart an older server process to load backend changes; refreshing alone updates only frontend assets.

Native tools must be installed separately on the server. Discovery uses PATH or administrator-controlled RECONGUARD_DALFOX / RECONGUARD_NIKTO executable paths. Dalfox requires its documented v3 CLI. Nikto Perl scripts also require perl. Batch wrappers are not executed. Tool installation and live native scans have not been tested here.

Missing tools produce an unavailable stage. Nikto is skipped when configured regex exclusions cannot be enforced. Failed, timed out and incomplete source scans remain explicit; the pipeline reports COMPLETED_WITH_GAPS rather than treating missing coverage as clean. These constraints are automatic and require no tool selection.

Dalfox runs with one worker, one request/second, bounded payloads per parameter, same-origin URL matching, supplied exclusions, TLS verification, and process/scan-stage time limits. Nikto uses bounded discovery/configuration/information checks with a pause and time limits. No redirect-following or blind-callback flags are enabled by the adapters. The legacy rate/researcher fields do not override these fixed external-tool settings.

Reflection is informational. Scanner verification labels remain source claims requiring independent impact validation. A source message is not fabricated into a raw HTTP response or baseline measurement. Zero false positives cannot be guaranteed.

The existing ReconGuard JSON and Markdown output files include all stages and observations. External source files and process logs remain under rg_runs. Source captures can contain sensitive data; protect reports. The pre-existing dashboard is not comprehensively audited or hardened by this change.

Tests: `python -m unittest -v test_rg_tools_api test_unified_pipeline` (15 tests). JavaScript syntax was checked with Node. Pipeline tests mock network discovery and external executables; no public targets are scanned by those tests.

The old integration endpoints remain available for backward compatibility, but the dashboard no longer uses their separate launch/import workflow. rg-unified.js only adds installed-tool status to the existing scan control.


## Asset Group evidence review
Open Asset Groups and select Review on an asset. The panel provides recorded evidence, a manually runnable PowerShell GET command, per-finding mitigation tutorials, and a JSON download. Reviewing evidence does not contact the target. Legacy scans explicitly show unavailable timestamps and headers. New full scans retain a security-header allowlist (not cookies or credentials), capture time, and coverage gaps. Failed HTTP checks have unknown grades; third-party redirect responses are not attributed to the target. Port labels come from port scan results. This remains a bounded discovery/configuration scan, not a comprehensive penetration test.

Checks: `node test_asset_review.cjs` and `python -m unittest -q test_asset_review test_rg_tools_api test_unified_pipeline`. Tests use mocks and do not scan public targets.

## Separate SQLmap tool

Open Recon Tools → SQLmap evidence desk. Enter a full HTTP(S) URL containing one query parameter, the exact authorized hostname, and the parameter name. Confirm authorization and select Run SQLmap. The separate tool never runs through Run Tools or the automatic recon pipeline.

The adapter uses the official SQLmap checkout in bin/sqlmap; administrators can override it with RECONGUARD_SQLMAP pointing to sqlmap.py or a native executable. Shell wrappers and user-supplied command-line options are rejected. Current installation provenance is recorded in bin/sqlmap/INSTALL-SOURCE.txt.

Two successful, complete, identical baseline responses are required. Redirects, 4xx/5xx responses, TLS errors, dynamic bodies, and bodies over the 64-KiB baseline limit stop the check as inconclusive. This conservative gate intentionally reduces coverage on dynamic pages. SQLmap uses fresh sessions, GET parameters only, level/risk 1, boolean/error techniques, one worker, a one-second delay, and a 180-second process limit. No crawling, database dumps, OS actions or arbitrary options are exposed.

Results include the exact executed argument list, SQLmap's final injection summary, a bounded source log with SHA-256, baseline metadata, and mitigation guidance. Logs and reports are local files under sqlmap_runs; protect them as they may contain URLs and payloads. SQLmap claims are labeled SCANNER_REPORTED, never independently confirmed. Warnings, incomplete output, errors and limits remain INCONCLUSIVE. NO_DETECTION does not establish safety. Zero false positives is not guaranteed.

Validation: python -m unittest -q test_sqlmap_api test_asset_review test_rg_tools_api test_unified_pipeline (29 tests); node --check web/sqlmap.js. Tests use synthetic fixtures and mocked network calls. No public target assessment was performed to develop this integration.

### URL-only SQLmap workflow
The SQLmap form asks only for a URL and an authorization checkbox. Host scope is derived from that URL; up to 10 uniquely named query parameters are selected automatically. A URL without query parameters can perform a single-page, same-origin discovery pass for query links and GET forms, capped at five candidate endpoints; POST forms and off-origin links are skipped. The no-request preview shows the hostname, known parameter names, and the bounded automatic Boolean/error-based GET payload plan. SQLmap’s exact reported payload and reproduction details appear with the evidence after a run. Earlier single-parameter API callers remain compatible. Scanner reports are never independently confirmed, and zero false positives cannot be guaranteed.

## Manual HTTP security workbench

Open Recon Tools → Manual HTTP Security Workbench. Set a full HTTP(S) URL and confirm authorization. The origin and path become the scope: `https://example.com/admin/` permits that path and its children, not other paths or subdomains. A URL with a query string is accepted; the query remains in the Repeater URL while scope is enforced on the path. Use `/` to cover the origin. Enter one request, preview it, review the exact method/URL/headers/body size, then approve and send once. A changed request requires a new preview. Supported methods are GET, HEAD, OPTIONS, POST, PUT, PATCH, and DELETE. The panel also has a local URL/Base64 decoder and can compare the two most recent response previews in browser memory.

The server enforces scope and one-use, five-minute preview tokens separately from the browser UI. It pins a resolved address, verifies HTTPS certificates, refuses private/link-local/reserved addresses (loopback is allowed for local testing), caps request and response bodies at 64 KiB, uses a ten-second timeout, and does not follow redirects, crawl, fuzz, or retry. Host and transport headers are server-managed. The response view shows redacted cookie values, text body preview, SHA-256, and passive observations. These observations do not confirm vulnerabilities. In-memory history holds only method, URL, status, timing, and observations; it is reset on server restart or project change. Export omits credentials and response bodies, though URLs may still contain sensitive query values and should be handled carefully.

The Proxy panel starts a loopback HTTP forward proxy on the address displayed in the UI. Configure an external browser's HTTP proxy with that address. In-scope HTTP requests appear in history; Intercept can hold one for editing, Forward, or Drop, and times out after 30 seconds. HTTPS CONNECT is an opaque pass-through tunnel for origin-root scopes: history records only tunnel metadata, and Intercept cannot inspect or edit encrypted requests. No local CA certificate is installed. The Browser preview instead fetches one scoped GET with a fresh preview token and shows a read-only HTML snapshot without scripts, links, forms, or external assets; it is not a full browser.

Intruder supports Sniper and Battering ram with `{{1}}` through `{{4}}` markers in a URL, header value, or body. Enter up to 12 custom payload lines, preview the request plan, approve it, and run at most 24 serialized requests with a one-second gap. Results show status, time, body size, and SHA-256 for manual comparison. The tool does not claim a vulnerability from a response difference. The proxy and Intruder use the same server-enforced project scope as Repeater. All history and results are held in memory and reset when the project changes or the server restarts.

This is an original, bounded workbench inspired by Burp's proxy, HTTP history, intercept, Intruder, and browser workflows. It is not a copy of Burp Suite Professional; it does not offer TLS man-in-the-middle inspection, a fully interactive embedded browser, a crawler, extension API, or an automated vulnerability scanner. No public target was contacted during implementation or tests.

Validation: `python -m unittest -q test_web_workbench_api test_workbench_advanced test_dalfox_api test_sqlmap_api test_rg_tools_api` and `node --check web/workbench.js`. On locked-down Windows setups, point `TEMP` and `TMP` to a writable workspace directory before running the Python tests.
