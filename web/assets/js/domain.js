'use strict';

const params = new URLSearchParams(window.location.search);
const domain = params.get('d');

if (!domain) {
  window.location.href = 'intel-board.html';
}

function formatDateTime(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return isoStr;
  const yr = d.getUTCFullYear();
  const mo = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dy = String(d.getUTCDate()).padStart(2, '0');
  const hr = String(d.getUTCHours()).padStart(2, '0');
  const mn = String(d.getUTCMinutes()).padStart(2, '0');
  return yr + '-' + mo + '-' + dy + ' ' + hr + ':' + mn + ' UTC';
}

function showError(domainStr, msg) {
  const box = document.getElementById('error-box');
  const msgEl = document.getElementById('error-message');
  if (box) box.style.display = '';
  if (msgEl) msgEl.textContent = msg;
  document.title = 'harvester-importer — error';
}

function renderHeader(data) {
  const nameEl = document.getElementById('domain-name-display');
  if (nameEl) nameEl.textContent = data.domain || domain;

  const metaEl = document.getElementById('contributor-meta');
  if (metaEl) {
    const parts = [data.display_name, data.display_loc].filter(Boolean);
    metaEl.textContent = parts.join(' · ');
  }

  document.title = 'harvester-importer — ' + (data.domain || domain);
}

function renderStats(data) {
  const emailEl = document.getElementById('val-email-count');
  const hostEl = document.getElementById('val-host-count');
  const ipEl = document.getElementById('val-ip-count');
  const srcEl = document.getElementById('val-source-count');

  if (emailEl) emailEl.textContent = data.email_count ?? '—';
  if (hostEl) hostEl.textContent = data.host_count ?? '—';
  if (ipEl) ipEl.textContent = data.ip_count ?? '—';
  if (srcEl) srcEl.textContent = data.source_count ?? '—';
}

function renderQueriedAt(data) {
  const el = document.getElementById('queried-at');
  if (!el) return;
  const ts = data.last_refreshed || data.queried_at || '';
  el.textContent = ts ? formatDateTime(ts) : '—';
}

function renderList(data, key, listId) {
  const container = document.getElementById(listId);
  if (!container) return;

  const arr = data[key];
  if (!Array.isArray(arr) || arr.length === 0) {
    container.innerHTML = '<div class="entry"><span class="entry-name empty">—</span></div>';
    return;
  }

  arr.forEach(function (item) {
    const div = document.createElement('div');
    div.className = 'entry';
    const span = document.createElement('span');
    span.className = 'entry-name';
    span.textContent = String(item);
    div.appendChild(span);
    container.appendChild(div);
  });
}

document.addEventListener('DOMContentLoaded', async function () {
  if (!domain) return;

  try {
    const res = await fetch('data/domains/' + encodeURIComponent(domain) + '.json');
    if (!res.ok) throw new Error('HTTP ' + res.status + ' — no data found for ' + domain);
    const data = await res.json();

    renderHeader(data);
    renderStats(data);
    renderQueriedAt(data);
    renderList(data, 'emails', 'list-emails');
    renderList(data, 'hosts', 'list-hosts');
    renderList(data, 'ips', 'list-ips');
    renderList(data, 'sources', 'list-sources');
  } catch (err) {
    showError(domain, err.message || 'Failed to load data for ' + domain);
  }
});
