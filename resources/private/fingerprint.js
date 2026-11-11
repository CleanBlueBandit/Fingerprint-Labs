(() => {
  const $ = (id) => document.getElementById(id);

  const warn = $('warn');
  const ok = $('ok');
  const optNetwork = $('opt-network');
  const optGeo = $('opt-geo');
  const start = $('start');
  const status = $('status');
  const out = $('out');

  warn.textContent = FINGERPRINT_WARNING;

  // Browsers can restore checkbox state on reload, so sync the button on load
  start.disabled = !ok.checked;
  ok.addEventListener('change', () => {
    start.disabled = !ok.checked;
  });

  start.addEventListener('click', async () => {
    start.disabled = true;
    ok.disabled = true;
    out.textContent = '';
    status.textContent = 'Running...';

    try {
      const result = await runFingerprint({
        consent: ok.checked,
        network: optNetwork.checked,
        geolocation: optGeo.checked,
        onProgress: (name) => {
          status.textContent = `Collecting: ${name}...`;
        }
      });
      out.textContent = JSON.stringify(result, null, 2);
      status.textContent = 'Done.';
    } catch (err) {
      status.textContent = `Error: ${err.message}`;
    } finally {
      ok.disabled = false;
      start.disabled = !ok.checked;
    }
  });
})();
