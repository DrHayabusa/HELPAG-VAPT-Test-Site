/* Operator console client. Served only behind the range token. */
async function api(path, options) { return (await fetch(path, options)).json(); }

function esc(v) {
  return String(v).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderTeamSlot(state) {
  const slot = document.getElementById('team-slot');
  if (!slot) return;
  slot.innerHTML = state.team
    ? `team <b>${esc(state.team)}</b> &middot; ${state.earned}/${state.total_points} pts`
    : 'no team registered';
}

function renderBoard(state) {
  const board = document.getElementById('board');
  const categories = [...new Set(state.findings.map((f) => f.category))];
  board.innerHTML = categories.map((category) => {
    const cards = state.findings.filter((f) => f.category === category).map((f) => `
      <article class="card ${f.found ? 'found' : ''}">
        <div class="row">
          <span class="tag ${esc(f.difficulty)}">${esc(f.difficulty)}</span>
          ${f.found ? '<span class="tick">confirmed</span>' : ''}
          <span class="pts">${f.points}</span>
        </div>
        <h3>${esc(f.title)}</h3>
        <p>${esc(f.summary)}</p>
        <div class="entry"><b>Feature:</b> ${esc(f.feature)}</div>
        <div class="entry">${f.entrypoints.map((e) => `<code>${esc(e)}</code>`).join(' ')}</div>
        <div class="entry">${esc(f.owasp)} &middot; ${f.mitre.map((m) => esc(m[0])).join(', ')}</div>
        <div class="entry"><b>Proof:</b> ${esc(f.artifact)}</div>
        <details><summary>Hints</summary><ul>${
          f.hints.map((h) => `<li>${esc(h)}</li>`).join('')}</ul></details>
      </article>`).join('');
    return `<h2 class="cat">${esc(category)}</h2><div class="cards">${cards}</div>`;
  }).join('');

  const percent = state.total_points ? (state.earned / state.total_points) * 100 : 0;
  document.getElementById('progress-bar').style.width = `${percent}%`;
  document.getElementById('progress-meta').textContent = state.team
    ? `${state.found_count}/${state.finding_count} findings · ${state.earned}/${state.total_points} points`
    : 'Register a team to track progress.';
  renderTeamSlot(state);
}

async function refreshBoard() { renderBoard(await api('/range/api/findings')); }

function initConsole() {
  document.getElementById('team-btn').addEventListener('click', async () => {
    const result = await api('/range/api/team', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ team: document.getElementById('team-input').value.trim() }),
    });
    if (result.error) { alert(result.error); return; }
    refreshBoard();
  });

  document.getElementById('proof-btn').addEventListener('click', async () => {
    const input = document.getElementById('proof-input');
    const out = document.getElementById('proof-result');
    const result = await api('/range/api/submit', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: input.value }),
    });
    if (result.error) { out.className = 'result no'; out.textContent = result.error; return; }
    if (!result.correct) {
      out.className = 'result no';
      out.textContent = 'No finding matches that value.'; return;
    }
    out.className = result.duplicate ? 'result dup' : 'result ok';
    out.textContent = (result.first_to_find ? 'FIRST TO FIND — ' : '') + result.message;
    input.value = '';
    refreshBoard();
  });

  document.getElementById('proof-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('proof-btn').click();
  });

  refreshBoard();
}

async function refreshScoreboard() {
  const scores = await api('/range/api/scoreboard');
  document.getElementById('score-body').innerHTML = scores.teams.length
    ? scores.teams.map((t) => `<tr><td>${t.rank}</td><td>${esc(t.team)}</td>
        <td>${t.findings}</td><td>${t.points}</td>
        <td class="dim">${esc(t.last_find || '')}</td></tr>`).join('')
    : '<tr><td colspan="5" class="dim">Nothing confirmed yet.</td></tr>';

  const progress = await api('/range/api/progress');
  document.getElementById('progress-body').innerHTML = progress.progress
    .map((p) => `<tr><td>${esc(p.title)}</td><td class="dim">${esc(p.feature)}</td>
      <td>${p.points}</td><td>${p.teams_found}</td></tr>`).join('');
  renderTeamSlot(await api('/range/api/findings'));
}

function initScoreboard() { refreshScoreboard(); setInterval(refreshScoreboard, 10000); }
