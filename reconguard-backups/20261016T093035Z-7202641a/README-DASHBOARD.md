# ReconGuard dashboard: Dalfox and Nikto

This directory is a runnable copy of the supplied dashboard with the actual ReconGuard view extended. No public target was scanned during implementation.

```powershell
python server.py
python -m unittest -v test_rg_tools_api
```

Use the local URL printed by the server, then select **ReconGuard (Zero-FP)** in the sidebar. The server picks the next free port starting at 8080. Other copies of the original app may already occupy earlier ports.

## What changed

The original ReconGuard view now includes Dalfox/Nikto badges, separate enable checkboxes, installation status, native tool execution, JSON report inputs, an evidence review queue, rejected records and a separate Markdown tool-review export. The existing **Launch Calibrated Recon Pipeline** button retains the legacy Subfinder/Httpx/Ffuf behavior; use **Run selected tools** for the new adapters. The legacy rate/researcher controls do not configure the external tools. New native runs use fixed conservative arguments.

**Native Dalfox:** requires the documented v3 CLI and a server-side executable. Uses one worker, one concurrent target, one request/second, a scan-stage budget, limited payloads per parameter and a 120-second subprocess timeout. Same-origin URL matching and supplied regex exclusions are passed to Dalfox. TLS verification is enabled and no redirect/OOB flags are passed. Source-engine verification claims still need independent review.

**Native Nikto:** uses selected discovery/configuration/information/identification tuning categories, a pause between tests and bounded scan/process times. It cannot enforce the dashboard's regex path exclusions; native mode refuses these rather than silently ignoring them. Run only for an authorized whole origin. Otherwise import a separately obtained report. This is not full vulnerability coverage.

Install tools separately using official project releases. Detection uses PATH or administrator-controlled `RECONGUARD_DALFOX` / `RECONGUARD_NIKTO` environment variables containing executable paths. Nikto Perl scripts require `perl` in PATH. Batch wrappers (`.bat` / `.cmd`) are deliberately not launched. Restart the dashboard after installation or environment changes. Native execution was not tested here because the executables were unavailable.

**Import:** select the tool checkbox, choose a JSON report, then press **Import selected JSON reports**. Reports are limited to 1 MiB each and the server's existing overall 2 MiB request limit also applies. Dalfox accepts finding arrays, results/meta envelopes and finding-only JSONL. Nikto accepts host objects/arrays. Matching records are filtered by exact hostname scope and URL regex exclusions. Import filtering cannot retroactively enforce a scanner's network scope. Unknown/malformed formats are rejected.

Dalfox reflections remain informational. Dalfox V is preserved as an engine claim. Standard Nikto messages do not become raw HTTP evidence or an invented severity. Incomplete-scan metadata is displayed. No result is automatically marked independently confirmed. Zero findings does not establish safety.

## Persistence and verification

Tool imports/runs persist independently in `rg_integrations_results.json`. Native source files and process diagnostics remain under `rg_runs/`. Legacy pipeline reports remain in their existing files. Protect source exports and generated reports because URLs and response captures can contain sensitive data. The new export is not a universal secret-redaction engine.

New routes: GET `/api/reconguard/integrations/status`, GET `/api/reconguard/integrations/results`, POST `/api/reconguard/integrations/import`, POST `/api/reconguard/integrations/scan`. New routes require local Host headers; cross-origin browser requests are rejected. Native tools are launched with argument lists and `shell=False` after explicit scope checks. This is not a security audit or hardening of every pre-existing dashboard route or scanner.

Nine backend integration tests cover scope-before-execution, exclusions, missing tools, fixed command construction, timeout reporting, unavailable-state reporting and origin checks. The earlier standalone evidence engine has 22 passing tests. The dashboard UI was inspected in a browser. Browser upload testing stopped when permission for the Nikto upload to localhost was declined; no alternate upload mechanism was attempted. A full browser import and native scans remain unverified.

## Applying to the original directory

Only the files listed in `deployment-manifest.json` are changed/added. The deployment script verifies the original files have not changed since preparation, backs up overwritten files under `reconguard-backups`, then copies the reviewed files. Restart the original server afterward and refresh its page. The script requires write access to `C:\New folder (6)`.

Official references: [Dalfox CLI](https://github.com/hahwul/dalfox/blob/main/docs/content/reference/cli.md), [Dalfox report format](https://github.com/hahwul/dalfox/blob/main/docs/content/guide/output.md), [Nikto manual](https://github.com/sullo/nikto/blob/main/documentation/nikto.1), [Nikto JSON reporter](https://github.com/sullo/nikto/blob/main/program/plugins/nikto_report_json.plugin).
