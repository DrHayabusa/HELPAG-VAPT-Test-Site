/* HELP AG VAPT range - challenge board client. No secrets live here. */

async function api(path, options) {
  const response = await fetch(path, options);
  return response.json();
}

function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
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
  const categories = [...new Set(state.challenges.map((c) => c.category))];
  board.innerHTML = categories.map((category) => {
    const cards = state.challenges.filter((c) => c.category === category).map((c) => `
      <article class="card ${c.solved ? 'solved' : ''}">
        <div class="row">
          <span class="tag ${esc(c.difficulty)}">${esc(c.difficulty)}</span>
          ${c.solved ? '<span class="tick">solved</span>' : ''}
          <span class="pts">${c.points}</span>
        </div>
        <h3>${esc(c.title)}</h3>
        <p class="blurb">${esc(c.blurb)}</p>
        <div class="entry">${c.entrypoints.map((e) => `<code>${esc(e)}</code>`).join(' ')}</div>
        <div class="entry">${esc(c.owasp)}</div>
        <details><summary>Hints</summary><ul>${
          c.hints.map((h) => `<li>${esc(h)}</li>`).join('')}</ul></details>
      </article>`).join('');
    return `<h2 class="cat">${esc(category)}</h2><div class="cards">${cards}</div>`;
  }).join('');

  const percent = state.total_points ? (state.earned / state.total_points) * 100 : 0;
  document.getElementById('progress-bar').style.width = `${percent}%`;
  document.getElementById('progress-meta').textContent = state.team
    ? `${state.solved_count}/${state.challenge_count} challenges · ${state.earned}/${state.total_points} points`
    : 'Register a team to track progress.';
  renderTeamSlot(state);
}

async function refreshBoard() {
  renderBoard(await api('/api/ctf/challenges'));
}

function initBoard() {
  document.getElementById('team-btn').addEventListener('click', async () => {
    const team = document.getElementById('team-input').value.trim();
    const result = await api('/api/ctf/team', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ team }),
    });
    if (result.error) { alert(result.error); return; }
    refreshBoard();
  });

  document.getElementById('flag-btn').addEventListener('click', async () => {
    const input = document.getElementById('flag-input');
    const out = document.getElementById('flag-result');
    const result = await api('/api/ctf/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flag: input.value }),
    });
    if (result.error) { out.className = 'result no'; out.textContent = result.error; return; }
    if (!result.correct) { out.className = 'result no'; out.textContent = 'Incorrect flag.'; return; }
    out.className = result.duplicate ? 'result dup' : 'result ok';
    out.textContent = (result.first_blood ? 'FIRST BLOOD — ' : '') + result.message;
    input.value = '';
    refreshBoard();
  });

  document.getElementById('flag-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') document.getElementById('flag-btn').click();
  });

  refreshBoard();
}

async function refreshScoreboard() {
  const scores = await api('/api/ctf/scoreboard');
  const body = document.getElementById('score-body');
  body.innerHTML = scores.teams.length
    ? scores.teams.map((t) => `<tr><td>${t.rank}</td><td>${esc(t.team)}</td>
        <td>${t.solves}</td><td>${t.points}</td><td class="dim">${esc(t.last_solve || '')}</td></tr>`).join('')
    : '<tr><td colspan="5" class="dim">No captures yet.</td></tr>';

  const progress = await api('/api/ctf/progress');
  document.getElementById('progress-body').innerHTML = progress.progress
    .map((p) => `<tr><td>${esc(p.title)}</td><td class="dim">${esc(p.category)}</td>
      <td>${p.points}</td><td>${p.solves}</td></tr>`).join('');
  renderTeamSlot(await api('/api/ctf/challenges'));
}

function initScoreboard() {
  refreshScoreboard();
  setInterval(refreshScoreboard, 10000);
}

document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('board') && !document.getElementById('score-body')) {
    api('/api/ctf/challenges').then(renderTeamSlot);
  }
});
