(() => {
  const $ = (id) => document.getElementById(id);

  const warn = $('warn');
  const ok = $('ok');
  const optNetwork = $('opt-network');
  const optGeo = $('opt-geo');
  const optScreens = $('opt-screens');
  const start = $('start');
  const save = $('save');
  const status = $('status');
  const out = $('out');

  warn.textContent = FINGERPRINT_WARNING;

  // Browsers can restore checkbox state on reload, so sync the button on load
  start.disabled = !ok.checked;
  ok.addEventListener('change', () => {
    start.disabled = !ok.checked;
  });

  // The latest result, kept so it can be saved to the account
  let lastResult = null;
  let saved = false;

  start.addEventListener('click', async () => {
    start.disabled = true;
    ok.disabled = true;
    out.textContent = '';
    status.textContent = 'Running...';
    lastResult = null;
    saved = false;
    save.hidden = true;

    try {
      const result = await runFingerprint({
        consent: ok.checked,
        network: optNetwork.checked,
        geolocation: optGeo.checked,
        screenDetails: optScreens.checked,
        onProgress: (name) => {
          status.textContent = `Collecting: ${name}...`;
        }
      });
      out.textContent = JSON.stringify(result, null, 2);
      status.textContent = 'Done.';
      lastResult = result;
      save.textContent = 'Save to my account';
      save.disabled = false;
      save.hidden = false;
    } catch (err) {
      status.textContent = `Error: ${err.message}`;
    } finally {
      ok.disabled = false;
      start.disabled = !ok.checked;
    }
  });

  save.addEventListener('click', async () => {
    if (!lastResult || saved) return;
    save.disabled = true;
    status.textContent = 'Saving...';

    try {
      const res = await fetch('/fingerprint/saved', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: lastResult })
      });

      if (res.status === 401) {
        window.location.href = '/login';
        return;
      }

      const body = await res.json().catch(() => null);
      if (!res.ok || !body?.ok) {
        throw new Error(body?.message || `HTTP ${res.status}`);
      }

      saved = true;
      save.textContent = 'Saved';
      const cmp = body.comparison;
      status.textContent = cmp && cmp.score !== null
        ? `Saved. ${cmp.score}% similar to your previous saved fingerprint (${cmp.verdict}). See "My saved fingerprints" for details.`
        : 'Saved to your account. See it under "My saved fingerprints".';
    } catch (err) {
      status.textContent = `Could not save: ${err.message}`;
      save.disabled = false;
    }
  });
})();


document.querySelectorAll("div").forEach(el => { 
  el.style.userSelect = 'auto';
})