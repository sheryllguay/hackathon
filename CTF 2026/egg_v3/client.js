(function () {
  const $ = (id) => document.getElementById(id);
  const balEl = $('balance'), amtEl = $('withdraw-amount'), btn = $('withdraw-btn'),
        resetBtn = $('reset-btn'), resultEl = $('result'), logEl = $('log');
  const fmt = (n) => Number(n).toFixed(4);
  let claimed = false, everLogged = false;

  function log(text) {
    if (!everLogged) { logEl.innerHTML = ''; everLogged = true; }
    const p = document.createElement('p');
    p.style.margin = '.25rem 0';
    p.innerHTML = '<small>[' + new Date().toLocaleTimeString() + '] ' + text + '</small>';
    logEl.prepend(p);
  }

  function showFlag(flag) {
    if (claimed) return;
    claimed = true;
    resultEl.hidden = false;
    resultEl.innerHTML = '<mark>Risk-override settlement:</mark> <code>' + flag + '</code>';
    log('Settlement override triggered.');
    btn.textContent = 'Completed';
    btn.setAttribute('aria-busy', 'false');
    btn.disabled = true;
  }

  async function refresh() {
    try {
      const d = await (await fetch('/api/balance', { method: 'POST' })).json();
      if (typeof d.balance === 'number') balEl.textContent = fmt(d.balance);
      if (!claimed) {
        if (d.pending > 0) { btn.textContent = d.pending + ' pending…'; btn.setAttribute('aria-busy', 'true'); btn.disabled = true; }
        else { btn.textContent = 'Withdraw'; btn.setAttribute('aria-busy', 'false'); btn.disabled = false; }
      }
      const flag = d.flag || (d.lastTx && d.lastTx.settlement_override);
      if (flag) showFlag(flag);
    } catch (e) { /* transient */ }
  }

  btn.addEventListener('click', async () => {
    const amount = parseFloat(amtEl.value);
    resultEl.hidden = true;
    if (!Number.isFinite(amount) || amount <= 0) { resultEl.hidden = false; resultEl.innerHTML = '<small>Enter a valid amount.</small>'; return; }
    btn.setAttribute('aria-busy', 'true'); btn.disabled = true;
    try {
      const d = await (await fetch('/api/withdraw', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount }),
      })).json();
      if (d.status === 'pending') log('Submitted ' + fmt(amount) + ' BTC (' + d.pending + ' pending).');
      else if (d.error === 'insufficient_balance') { resultEl.hidden = false; resultEl.innerHTML = '<small>Insufficient balance.</small>'; }
      else if (d.error === 'invalid_amount') { resultEl.hidden = false; resultEl.innerHTML = '<small>Invalid amount.</small>'; }
      else if (d.error === 'rate_limited') { resultEl.hidden = false; resultEl.innerHTML = '<small>Too many requests — slow down.</small>'; }
    } catch (e) { resultEl.hidden = false; resultEl.innerHTML = '<small>Network error.</small>'; }
    refresh();
  });

  resetBtn.addEventListener('click', async () => {
    try {
      await fetch('/api/reset', { method: 'POST' });
      claimed = false; resultEl.hidden = true; btn.disabled = false; btn.textContent = 'Withdraw';
      log('Account reset.');
      refresh();
    } catch (e) { /* ignore */ }
  });

  refresh();
  setInterval(refresh, 1500);
})();
