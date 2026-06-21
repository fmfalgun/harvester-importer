'use strict';

function buildCard(entry) {
  const card = document.createElement('div');
  card.className = 'domain-card';
  card.dataset.domain = entry.domain;
  card.addEventListener('click', function () {
    window.location.href = 'domain.html?d=' + encodeURIComponent(entry.domain);
  });

  const headerRow = document.createElement('div');
  headerRow.className = 'card-header-row';

  const domainSpan = document.createElement('span');
  domainSpan.className = 'card-domain';
  domainSpan.textContent = entry.domain;

  const dateStr = (entry.queried_at || entry.last_refreshed || '').slice(0, 10);
  const dateSpan = document.createElement('span');
  dateSpan.className = 'card-date';
  dateSpan.textContent = dateStr;

  headerRow.appendChild(domainSpan);
  headerRow.appendChild(dateSpan);

  const statsDiv = document.createElement('div');
  statsDiv.className = 'card-stats';

  const statDefs = [
    (entry.email_count ?? 0) + ' emails',
    (entry.host_count ?? 0) + ' hosts',
    (entry.ip_count ?? 0) + ' IPs',
    (entry.source_count ?? 0) + ' sources',
  ];
  statDefs.forEach(function (label) {
    const s = document.createElement('span');
    s.className = 'card-stat';
    s.textContent = label;
    statsDiv.appendChild(s);
  });

  const contributorDiv = document.createElement('div');
  contributorDiv.className = 'card-contributor';

  const nameSpan = document.createElement('span');
  nameSpan.className = 'card-name';
  nameSpan.textContent = entry.display_name ?? '';

  const locSpan = document.createElement('span');
  locSpan.textContent = entry.display_loc ?? '';

  contributorDiv.appendChild(nameSpan);
  contributorDiv.appendChild(locSpan);

  card.appendChild(headerRow);
  card.appendChild(statsDiv);
  card.appendChild(contributorDiv);

  return card;
}

function renderDomains(domains) {
  const list = document.getElementById('domain-list');
  if (!list) return;

  const sorted = domains.slice().sort(function (a, b) {
    const ea = a.email_count ?? 0;
    const eb = b.email_count ?? 0;
    if (eb !== ea) return eb - ea;
    return (a.domain || '').localeCompare(b.domain || '');
  });

  sorted.forEach(function (entry) {
    list.appendChild(buildCard(entry));
  });
}

function updateSearchCount() {
  const countEl = document.getElementById('search-count');
  if (!countEl) return;
  const cards = document.querySelectorAll('.domain-card');
  let visible = 0;
  cards.forEach(function (card) {
    if (card.style.display !== 'none') visible++;
  });
  countEl.textContent = visible + ' domain' + (visible === 1 ? '' : 's');
}

function applySearch(term) {
  const lower = term.toLowerCase();
  const cards = document.querySelectorAll('.domain-card');
  cards.forEach(function (card) {
    const d = (card.dataset.domain || '').toLowerCase();
    card.style.display = d.includes(lower) ? '' : 'none';
  });
  updateSearchCount();
}

function showError(msg) {
  const box = document.getElementById('error-box');
  const msgEl = document.getElementById('error-message');
  if (box) box.style.display = '';
  if (msgEl) msgEl.textContent = msg;
}

document.addEventListener('DOMContentLoaded', async function () {
  try {
    const res = await fetch('data/index.json');
    if (!res.ok) throw new Error('HTTP ' + res.status + ' fetching data/index.json');
    const data = await res.json();

    const statsEl = document.getElementById('ib-stats');
    if (statsEl) {
      statsEl.textContent =
        (data.total_domains ?? 0) + ' domains · ' + (data.total_scans ?? 0) + ' scans indexed';
    }

    if (Array.isArray(data.domains) && data.domains.length > 0) {
      renderDomains(data.domains);
    }

    updateSearchCount();

    const searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('keyup', function () {
        applySearch(searchInput.value);
      });
    }
  } catch (err) {
    showError(err.message || 'Failed to load index data.');
  }
});
