/* Tool availability is part of the existing ReconGuard launch control. */
document.addEventListener('DOMContentLoaded', () => {
  const status = document.getElementById('rgStatusIndicator');
  if (!status) return;
  fetch('/api/reconguard/integrations/status').then(response => response.json()).then(data => {
    // Preserve the state of a scan started before availability finished loading.
    if (document.getElementById('btnLaunchReconGuard')?.disabled) return;
    if (status.textContent !== 'Ready to probe') return;
    status.textContent = 'One pipeline · ' + Object.entries(data.tools).map(([name, tool]) => `${name}: ${tool.available ? 'ready' : 'unavailable'}`).join(' · ');
  }).catch(() => {});
});
