// AdGuard Shield Statusseite. Daten werden ausschließlich per textContent
// eingefügt, nie als HTML.
(function () {
  'use strict';

  var THEME_KEY = 'adguard-shield-theme';
  var INTERVAL = 5000;
  var root = document.documentElement;

  function storedTheme() {
    try { return localStorage.getItem(THEME_KEY); } catch (e) { return null; }
  }
  function storeTheme(v) {
    try { localStorage.setItem(THEME_KEY, v); } catch (e) { /* ohne Speicher */ }
  }
  var initial = storedTheme();
  if (initial === 'light' || initial === 'dark') {
    root.setAttribute('data-theme', initial);
  }
  function currentTheme() {
    var t = root.getAttribute('data-theme');
    if (t) { return t; }
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  var base = '/';
  var timer = null;
  var inflight = false;

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }

  function setText(id, v) {
    var e = $(id);
    if (e) { e.textContent = (v === undefined || v === null || v === '') ? '–' : String(v); }
  }

  function num(n) {
    return typeof n === 'number' ? n.toLocaleString('de-DE') : '–';
  }

  function time(v) {
    if (!v) { return '–'; }
    var d = new Date(v);
    return isNaN(d.getTime()) ? '–' : d.toLocaleTimeString('de-DE');
  }

  function dateTime(v) {
    if (!v) { return '–'; }
    var d = new Date(v);
    return isNaN(d.getTime()) ? '–' : d.toLocaleString('de-DE');
  }

  function duration(sec) {
    sec = Math.max(0, Math.floor(sec || 0));
    var d = Math.floor(sec / 86400);
    var h = Math.floor(sec % 86400 / 3600);
    var m = Math.floor(sec % 3600 / 60);
    var s = sec % 60;
    var hms = [h, m, s].map(function (x) { return x < 10 ? '0' + x : String(x); }).join(':');
    return d > 0 ? d + ' T ' + hms : hms;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  // cols: [{ get: fn(row) -> string|Node, cls: string }]
  function fillTable(id, rows, cols, emptyText) {
    var body = $(id);
    if (!body) { return; }
    clear(body);
    if (!rows || rows.length === 0) {
      var tr = el('tr');
      var td = el('td', 'empty', emptyText);
      td.colSpan = cols.length;
      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }
    rows.forEach(function (row) {
      var tr = el('tr');
      cols.forEach(function (c) {
        var td = el('td', c.cls || '');
        var v = c.get(row);
        if (v instanceof Node) { td.appendChild(v); } else { td.textContent = (v === undefined || v === null || v === '') ? '–' : String(v); }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
  }

  function countBar(count, limit) {
    var wrap = el('div', 'count');
    wrap.appendChild(el('span', '', count + '/' + limit));
    var bar = el('div', 'bar');
    var fill = el('i');
    var pct = limit > 0 ? Math.min(100, count / limit * 100) : 0;
    fill.style.width = pct.toFixed(1) + '%';
    if (count >= limit) { fill.className = 'over'; } else if (pct >= 80) { fill.className = 'hot'; }
    bar.appendChild(fill);
    wrap.appendChild(bar);
    return wrap;
  }

  function pill(text, kind) {
    return el('span', 'pill' + (kind ? ' ' + kind : ''), text);
  }

  function renderTiles(s) {
    var t = s.tiles || {};
    setText('t-active', num(t.active_bans));
    setText('t-permanent', num(t.permanent_bans));
    setText('t-today', num(t.bans_today));
    setText('t-week', num(t.bans_7_days));
    setText('t-offenses', num(t.offenses));
    setText('t-whitelist', num(t.whitelist_entries));
    var p = s.poll || {};
    setText('t-poll', p.last_success ? time(p.last_success) : 'noch kein Poll');
    var sub = $('t-poll-sub');
    if (p.last_error && (!p.last_success || new Date(p.last_error_at) > new Date(p.last_success))) {
      sub.className = 'sub bad';
      sub.textContent = 'Fehler ' + time(p.last_error_at) + ': ' + p.last_error;
    } else {
      sub.className = 'sub';
      sub.textContent = num(p.entries) + ' Einträge · alle ' + p.interval_seconds + ' s';
    }
  }

  function renderModules(mods) {
    var box = $('modules');
    clear(box);
    (mods || []).forEach(function (m) {
      var card = el('div', 'module');
      var head = el('div', 'head');
      head.appendChild(el('span', 'name', m.name));
      head.appendChild(pill(m.active ? 'aktiv' : 'inaktiv', m.active ? 'ok' : ''));
      card.appendChild(head);
      if (m.detail) { card.appendChild(el('div', 'detail', m.detail)); }
      if (m.last_run) {
        var ok = m.last_result === 'ok';
        card.appendChild(el('div', 'run' + (ok ? '' : ' bad'), 'Letzter Lauf ' + dateTime(m.last_run) + ': ' + (ok ? 'OK' : (m.last_result || 'Fehler'))));
      }
      box.appendChild(card);
    });
  }

  function renderLive(l) {
    l = l || {};
    setText('top-hint', '(' + l.window_seconds + ' s, Limit ' + l.limit + ')');
    fillTable('top', l.top, [
      { get: function (r) { return countBar(r.count, l.limit); } },
      { get: function (r) { return r.client; }, cls: 'mono wrap' },
      { get: function (r) { return r.domain; }, cls: 'wrap' },
      { get: function (r) { return r.protocol; }, cls: 'nowrap' }
    ], 'Keine Anfragen im aktuellen Zeitfenster.');

    $('sub-panel').hidden = !l.subdomain_enabled;
    setText('sub-hint', '(' + l.subdomain_window_seconds + ' s, Limit ' + l.subdomain_limit + ')');
    fillTable('subdomains', l.subdomains, [
      { get: function (r) { return countBar(r.count, l.subdomain_limit); } },
      { get: function (r) { return r.client; }, cls: 'mono wrap' },
      { get: function (r) { return r.domain; }, cls: 'wrap' },
      { get: function (r) { return r.protocol; }, cls: 'nowrap' }
    ], 'Keine Subdomain-Gruppen im aktuellen Zeitfenster.');

    setText('recent-hint', '(' + num(l.events_in_memory) + ' Ereignisse im Analysefenster)');
    fillTable('recent', l.recent, [
      { get: function (r) { return time(r.time); }, cls: 'nowrap' },
      { get: function (r) { return r.client; }, cls: 'mono wrap' },
      { get: function (r) { return r.protocol; }, cls: 'nowrap' },
      { get: function (r) { return r.domain; }, cls: 'wrap' }
    ], 'Noch keine Querylog-Einträge im Speicher.');
  }

  function renderBans(bans) {
    fillTable('bans', bans, [
      { get: function (b) { return b.ip; }, cls: 'mono wrap' },
      { get: function (b) { return b.source; } },
      { get: function (b) { return b.reason; } },
      { get: function (b) { return b.domain; }, cls: 'wrap' },
      { get: function (b) { return b.country; } },
      { get: function (b) { return b.permanent ? pill('permanent', 'bad') : dateTime(b.until); }, cls: 'nowrap' }
    ], 'Keine aktiven Sperren.');
  }

  function renderHistory(items) {
    fillTable('history', items, [
      { get: function (h) { return h.time; }, cls: 'nowrap' },
      { get: function (h) { return pill(h.action, h.action === 'BAN' ? 'bad' : (h.action === 'UNBAN' ? 'ok' : '')); } },
      { get: function (h) { return h.ip; }, cls: 'mono wrap' },
      { get: function (h) { return h.domain; }, cls: 'wrap' },
      { get: function (h) { return h.reason; } },
      { get: function (h) { return h.duration; }, cls: 'nowrap' }
    ], 'Keine Ereignisse.');
  }

  function renderLogs(lines) {
    var list = $('logs');
    clear(list);
    if (!lines || lines.length === 0) {
      list.appendChild(el('li', 'empty', 'Keine passenden Logeinträge.'));
      return;
    }
    lines.slice().reverse().forEach(function (line) {
      var cls = line.indexOf('[ERROR]') >= 0 ? 'bad' : (line.indexOf('[WARN]') >= 0 ? 'warn' : '');
      list.appendChild(el('li', cls, line));
    });
  }

  function render(s) {
    setText('version', s.version);
    setText('hostname', s.hostname);
    setText('uptime', duration(s.uptime_seconds));
    $('dryrun').hidden = !s.dry_run;
    renderTiles(s);
    renderModules(s.modules);
    renderLive(s.live);
    renderBans(s.bans);
    renderHistory(s.history);
    renderLogs(s.logs);
  }

  function showError(msg) {
    $('error').hidden = false;
    setText('error-detail', msg);
  }

  function schedule() {
    clearTimeout(timer);
    timer = null;
    if (!document.hidden) { timer = setTimeout(refresh, INTERVAL); }
  }

  function refresh() {
    if (inflight) { return; }
    inflight = true;
    fetch(base + 'api/status', { cache: 'no-store', credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) {
        if (r.status === 401) { throw new Error('Anmeldung abgelaufen – bitte Seite neu laden.'); }
        if (!r.ok) { throw new Error('HTTP ' + r.status); }
        return r.json();
      })
      .then(function (s) {
        render(s);
        $('error').hidden = true;
        setText('updated', new Date().toLocaleTimeString('de-DE'));
      })
      .catch(function (e) { showError(e && e.message ? e.message : 'Unbekannter Fehler'); })
      .then(function () { inflight = false; schedule(); });
  }

  function init() {
    base = document.body.getAttribute('data-base') || '/';
    var btn = $('theme');
    btn.addEventListener('click', function () {
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      storeTheme(next);
    });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden) { clearTimeout(timer); timer = null; } else { refresh(); }
    });
    refresh();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
