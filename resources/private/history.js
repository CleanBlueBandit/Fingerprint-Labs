(() => {
  const list = document.getElementById('list');
  const status = document.getElementById('status');
  const more = document.getElementById('more');
  const latest = document.getElementById('latest');
  const latestBody = document.getElementById('latest-body');
  const compareBtn = document.getElementById('compare');
  const compareHint = document.getElementById('compare-hint');
  const comparePanel = document.getElementById('compare-panel');
  const compareBody = document.getElementById('compare-body');

  const HASHES = [
    ['combinedHash', 'Combined'],
    ['staticHash', 'Static'],
    ['configurationHash', 'Configuration'],
    ['behavioralHash', 'Behavioral']
  ];

  let nextCursor = null;
  let shown = 0;

  // Ids ticked for comparison, oldest tick first. Two at most.
  let selected = [];
  const boxes = new Map();

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  const pct = (n) => `${Math.round(n * 1000) / 10}%`;
  const when = (m) => `#${m.id} (${new Date(m.createdAt).toLocaleString()})`;

  function updateSelection() {
    for (const [id, box] of boxes) box.checked = selected.includes(id);
    compareBtn.disabled = selected.length !== 2;
    compareHint.textContent = selected.length === 2
      ? `Selected #${selected[0]} and #${selected[1]}.`
      : 'Tick two fingerprints below to compare them.';
  }

  // Draws one comparison result into `container`. Everything is set with textContent.
  function renderComparison(container, cmp) {
    container.replaceChildren();

    if (cmp.score === null) {
      container.append(el('p', 'muted', 'These two have no signals in common to compare.'));
      return;
    }

    container.append(
      el('p', 'cmp-score', `${cmp.score}% similar: ${cmp.verdict}`),
      el('p', 'muted', `${when(cmp.a)} vs ${when(cmp.b)}. ${pct(cmp.coverage)} of the total weight could be compared on both sides.`)
    );

    // Per-group scores
    const groupList = el('ul', 'cmp-groups');
    for (const g of Object.values(cmp.groups).sort((x, y) => y.weight - x.weight)) {
      groupList.append(el('li', '', `${g.label}: ${g.score}%`));
    }
    container.append(groupList);

    // What cost the most: weight times how much it differed
    const impact = (c) => c.weight * (1 - c.similarity);
    const differing = cmp.components
      .filter((c) => c.similarity !== null && c.similarity < 1)
      .sort((x, y) => impact(y) - impact(x));

    container.append(el('h3', '', differing.length ? 'What differs most' : 'Nothing differs'));
    if (differing.length) {
      const ul = el('ul', 'cmp-diff');
      for (const c of differing.slice(0, 10)) {
        const li = el('li');
        li.append(el('strong', '', c.label), ` (weight ${c.weight}): ${pct(c.similarity)} similar`);
        if (c.changed.length) li.append(el('div', 'cmp-changed', c.changed.join(', ')));
        ul.append(li);
      }
      container.append(ul);
    }

    // Every component, including the ones that could not be compared
    const details = el('details', 'cmp-all');
    details.append(el('summary', '', `All ${cmp.components.length} components`));
    const table = el('table', 'cmp-table');
    const head = el('tr');
    for (const h of ['Component', 'Weight', 'Similarity']) head.append(el('th', '', h));
    table.append(head);
    for (const c of cmp.components) {
      const row = el('tr', `cmp-${c.status}`);
      row.append(
        el('td', '', c.label),
        el('td', '', String(c.weight)),
        el('td', '', c.similarity === null ? 'not compared' : pct(c.similarity))
      );
      table.append(row);
    }
    details.append(table);
    container.append(details);
  }

  async function loadLatest() {
    try {
      const body = await api('/fingerprint/saved/compare/latest');
      latest.hidden = false;
      if (!body.comparison) {
        latestBody.replaceChildren(el('p', 'muted', 'Save at least two fingerprints to see how similar they are.'));
        return;
      }
      renderComparison(latestBody, body.comparison);
    } catch (err) {
      latest.hidden = true;
    }
  }

  compareBtn.addEventListener('click', async () => {
    if (selected.length !== 2) return;
    compareBtn.disabled = true;
    comparePanel.hidden = false;
    compareBody.replaceChildren(el('p', 'muted', 'Comparing...'));
    try {
      const [a, b] = selected;
      const body = await api(`/fingerprint/saved/compare?a=${a}&b=${b}`);
      renderComparison(compareBody, body.comparison);
    } catch (err) {
      compareBody.replaceChildren(el('p', 'message', `Could not compare: ${err.message}`));
    } finally {
      compareBtn.disabled = selected.length !== 2;
    }
  });

  // navigator.clipboard only exists in secure contexts (HTTPS or localhost), so fall back
  // to a hidden textarea for plain-HTTP deployments
  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }

    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try {
      if (!document.execCommand('copy')) throw new Error('copy command rejected');
    } finally {
      area.remove();
    }
  }

  // Briefly shows the outcome on the button that was clicked
  function flash(button, text) {
    const original = button.dataset.label || button.textContent;
    button.dataset.label = original;
    button.textContent = text;
    clearTimeout(button._t);
    button._t = setTimeout(() => { button.textContent = original; }, 1500);
  }

  async function api(path, options) {
    const res = await fetch(path, { cache: 'no-store', ...options });
    if (res.status === 401) {
      window.location.href = '/login';
      throw new Error('Not logged in');
    }
    const body = await res.json().catch(() => null);
    if (!res.ok || !body?.ok) throw new Error(body?.message || `HTTP ${res.status}`);
    return body;
  }

  function button(label, onClick, className) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = label;
    if (className) b.className = className;
    b.addEventListener('click', () => onClick(b));
    return b;
  }

  function renderItem(fp) {
    const li = document.createElement('li');
    li.className = 'hist-item';

    const head = document.createElement('div');
    head.className = 'hist-head';
    const date = document.createElement('span');
    date.className = 'hist-date';
    date.textContent = new Date(fp.createdAt).toLocaleString();
    const id = document.createElement('span');
    id.className = 'hist-id';
    id.textContent = `#${fp.id}`;
    const pick = el('label', 'hist-pick');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.addEventListener('change', () => {
      selected = selected.filter((x) => x !== fp.id);
      if (box.checked) selected.push(fp.id);
      if (selected.length > 2) selected.shift();
      updateSelection();
    });
    boxes.set(fp.id, box);
    pick.append(box, ' Compare');
    head.append(date, id, pick);

    const dl = document.createElement('dl');
    dl.className = 'hist-hashes';
    for (const [key, label] of HASHES) {
      const value = fp[key];
      if (!value) continue;
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = value;
      dl.append(dt, dd, button('Copy', async (b) => {
        try { await copyText(value); flash(b, 'Copied'); } catch { flash(b, 'Failed'); }
      }, 'secondary'));
    }

    // Full payload is fetched on demand: it can be several hundred KB
    let cached = null;
    const load = async () => {
      if (!cached) cached = (await api(`/fingerprint/saved/${fp.id}`)).fingerprint.data;
      return JSON.stringify(cached, null, 2);
    };

    const details = document.createElement('pre');
    details.className = 'hist-details';
    details.hidden = true;

    const actions = document.createElement('div');
    actions.className = 'hist-actions';
    actions.append(
      button('Copy full JSON', async (b) => {
        b.disabled = true;
        try { await copyText(await load()); flash(b, 'Copied'); } catch { flash(b, 'Failed'); }
        b.disabled = false;
      }, 'secondary'),
      button('View', async (b) => {
        if (!details.hidden) {
          details.hidden = true;
          b.textContent = 'View';
          return;
        }
        b.disabled = true;
        try {
          // textContent, never innerHTML: the payload comes from the browser
          details.textContent = await load();
          details.hidden = false;
          b.textContent = 'Hide';
        } catch (err) {
          flash(b, 'Failed');
        }
        b.disabled = false;
      }, 'secondary'),
      button('Delete', async (b) => {
        if (!confirm('Delete this saved fingerprint?')) return;
        b.disabled = true;
        try {
          await api(`/fingerprint/saved/${fp.id}`, { method: 'DELETE' });
          li.remove();
          boxes.delete(fp.id);
          selected = selected.filter((x) => x !== fp.id);
          updateSelection();
          loadLatest();
          shown -= 1;
          if (shown === 0 && !nextCursor) status.textContent = 'No saved fingerprints yet.';
        } catch (err) {
          b.disabled = false;
          flash(b, 'Failed');
        }
      }, 'secondary danger')
    );

    li.append(head, dl, actions, details);
    return li;
  }

  async function loadPage() {
    more.disabled = true;
    status.textContent = shown ? '' : 'Loading...';

    try {
      const query = nextCursor ? `?cursor=${nextCursor}` : '';
      const body = await api(`/fingerprint/saved${query}`);

      for (const fp of body.fingerprints) list.appendChild(renderItem(fp));
      shown += body.fingerprints.length;
      nextCursor = body.nextCursor;

      more.hidden = !nextCursor;
      status.textContent = shown ? '' : 'No saved fingerprints yet. Run a fingerprint and press "Save to my account".';
    } catch (err) {
      status.textContent = `Could not load saved fingerprints: ${err.message}`;
    } finally {
      more.disabled = false;
    }
  }

  more.addEventListener('click', loadPage);
  loadPage();
  loadLatest();
})();
