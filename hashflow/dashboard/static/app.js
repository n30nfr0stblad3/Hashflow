/* Hashflow Dashboard JS */
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

let chart;
let history = { total: [], yours: [], labels: [] };
let currentLogTab = 'contrib';
let ws = null;
let wsLogs = null;

function initChart() {
    const ctx = document.getElementById('hashChart').getContext('2d');
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total',
                    data: [],
                    borderColor: '#22d3ee',
                    backgroundColor: 'rgba(34,211,238,0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                    borderWidth: 2,
                },
                {
                    label: 'You',
                    data: [],
                    borderColor: '#34d399',
                    backgroundColor: 'rgba(52,211,153,0.05)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                    borderWidth: 1.5,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(0,0,0,0.8)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1,
                }
            },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: 'rgba(255,255,255,0.4)', maxTicksLimit: 6 } },
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: 'rgba(255,255,255,0.4)', callback: v => formatHash(v) } }
            }
        }
    });
}

function formatHash(h) {
    if (h >= 1e12) return (h/1e12).toFixed(2)+' TH/s';
    if (h >= 1e9) return (h/1e9).toFixed(2)+' GH/s';
    if (h >= 1e6) return (h/1e6).toFixed(2)+' MH/s';
    if (h >= 1e3) return (h/1e3).toFixed(2)+' kH/s';
    return h.toFixed(0)+' H/s';
}

function updateUI(data) {
    const isRunning = data.running;
    updateControlUI(isRunning);
    const dot = $('#status-dot');
    const text = $('#status-text');
    if (isRunning) {
        dot.className = 'w-2 h-2 rounded-full bg-emerald-400 shadow shadow-emerald-400/50';
        text.textContent = 'Mining • Active';
        text.className = 'text-sm text-emerald-300';
    } else {
        dot.className = 'w-2 h-2 rounded-full bg-yellow-400';
        text.textContent = 'Idle • Waiting';
        text.className = 'text-sm text-yellow-300';
    }

    const stats = data.stats || {};
    const contrib = stats.contrib || {};
    const total = stats.total || {};
    const threads = data.threads || {};

    $('#total-hash').textContent = total.current_formatted || '0 H/s';
    $('#total-avg').textContent = `Avg: ${total.average_formatted || '0 H/s'}`;
    $('#your-hash').textContent = contrib.current_formatted || '0 H/s';
    $('#your-threads').textContent = `${threads.contrib || 0} threads`;
    $('#accepted').textContent = (contrib.accepted || 0) + (stats.owner?.accepted || 0);
    $('#rejected').textContent = `${(contrib.rejected || 0) + (stats.owner?.rejected || 0)} rejected`;

    $('#sys-threads').textContent = `${threads.contrib || 0} + ${threads.owner || 0} / ${threads.total || 0}`;
    $('#sys-pool').textContent = (data.pool || '').split(':')[0] || '-';
    $('#sys-donation').textContent = data.donation ? (data.donation*100).toFixed(1)+'%' : '-';
    $('#sys-uptime').textContent = contrib.uptime_formatted || '-';
    
    const stealth = data.stealth || {};
    $('#sys-cpu-limit').textContent = stealth.cpu_limit ? stealth.cpu_limit+'%' : 'None';
    $('#sys-stealth').textContent = stealth.stealth_mode ? 'ON' : 'OFF';
    $('#sys-stealth').className = stealth.stealth_mode ? 'mono text-cyan-300' : 'mono';

    const thermal = data.thermal || {};
    if (thermal.temperature) {
        $('#sys-temp').textContent = thermal.temperature.toFixed(1)+'°C';
        $('#sys-temp').className = thermal.overheating ? 'mono text-red-400' : 'mono';
    } else {
        $('#sys-temp').textContent = '-';
    }

    // Chart update
    const now = new Date().toLocaleTimeString();
    history.labels.push(now);
    history.total.push(total.current || 0);
    history.yours.push(contrib.current || 0);
    if (history.labels.length > 30) {
        history.labels.shift();
        history.total.shift();
        history.yours.shift();
    }
    if (chart) {
        chart.data.labels = history.labels;
        chart.data.datasets[0].data = history.total;
        chart.data.datasets[1].data = history.yours;
        chart.update('none');
    }
}

async function fetchGroup() {
    try {
        const res = await fetch('/api/group');
        const data = await res.json();
        $('#group-size').textContent = `${data.total}/${data.max}`;
        $('#group-available').textContent = `${data.available} slots free`;

        const platformsDiv = $('#platforms');
        platformsDiv.innerHTML = '';
        for (const [plat, count] of Object.entries(data.platforms || {})) {
            const div = document.createElement('div');
            div.className = 'flex justify-between items-center text-sm bg-white/5 rounded-lg px-3 py-2';
            div.innerHTML = `<span class="text-white/70">${plat}</span><span class="mono font-bold">${count}</span>`;
            platformsDiv.appendChild(div);
        }

        const membersDiv = $('#members');
        membersDiv.innerHTML = '';
        if (!data.members || data.members.length === 0) {
            membersDiv.innerHTML = '<div class="text-sm text-white/40 text-center py-8">No miners yet</div>';
        } else {
            data.members.slice(-20).reverse().forEach(m => {
                const div = document.createElement('div');
                div.className = 'flex items-center gap-3 bg-white/[0.03] border border-white/5 rounded-xl px-3 py-2.5';
                div.innerHTML = `
                    <div class="w-8 h-8 rounded-full bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center text-xs font-bold">${(m.username||'?')[0].toUpperCase()}</div>
                    <div class="flex-1 min-w-0">
                        <div class="text-sm font-medium truncate">${m.username}</div>
                        <div class="text-xs text-white/40 mono truncate">${m.device_id} • ${ (m.platform||'').split('-')[0] }</div>
                    </div>
                    <div class="w-2 h-2 rounded-full bg-emerald-400"></div>
                `;
                membersDiv.appendChild(div);
            });
        }
    } catch (e) {
        console.error('group fetch failed', e);
    }
}

async function fetchLogs() {
    try {
        const res = await fetch(`/api/logs?label=${currentLogTab}&limit=100`);
        const data = await res.json();
        const logs = data.logs[currentLogTab] || [];
        const logsDiv = $('#logs');
        logsDiv.innerHTML = logs.map(l => {
            let cls = 'text-white/60';
            if (l.toLowerCase().includes('accepted')) cls = 'text-emerald-300';
            if (l.toLowerCase().includes('rejected')) cls = 'text-red-300';
            if (l.toLowerCase().includes('error')) cls = 'text-red-400';
            if (l.toLowerCase().includes('speed') || l.toLowerCase().includes('h/s')) cls = 'text-cyan-300';
            return `<div class="${cls}">${escapeHtml(l)}</div>`;
        }).join('');
        logsDiv.scrollTop = logsDiv.scrollHeight;
    } catch (e) {
        console.error('logs fetch failed', e);
    }
}

function escapeHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${location.host}/ws`;

    try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => {
            console.log('WS connected');
        };
        ws.onmessage = (ev) => {
            try {
                const data = JSON.parse(ev.data);
                updateUI(data);
            } catch (e) {}
        };
        ws.onclose = () => {
            console.log('WS closed, retry in 3s');
            setTimeout(connectWebSocket, 3000);
            // Fallback polling
            startPolling();
        };
        ws.onerror = () => {
            ws.close();
        };
    } catch (e) {
        startPolling();
    }
}

let pollingInterval = null;
function startPolling() {
    if (pollingInterval) return;
    pollingInterval = setInterval(async () => {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            updateUI(data);
        } catch (e) {}
    }, 3000);
}

function initLogTabs() {
    $$('.log-tab').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.log-tab').forEach(b => {
                b.className = 'log-tab px-3 py-1 rounded-full text-xs bg-white/5';
            });
            btn.className = 'log-tab px-3 py-1 rounded-full text-xs bg-cyan-500/20 text-cyan-300';
            currentLogTab = btn.dataset.log;
            fetchLogs();
        });
    });
}

// ---------- Control deck (Normie Mode) ----------
const btnStart = () => document.getElementById('btn-start');
const btnStop = () => document.getElementById('btn-stop');

function updateControlUI(running) {
    const s = btnStart(), t = btnStop();
    if (!s || !t) return;
    if (running) { s.classList.add('hidden'); t.classList.remove('hidden'); }
    else { s.classList.remove('hidden'); t.classList.add('hidden'); }
}

async function loadSettings() {
    try {
        const res = await fetch('/api/settings');
        const s = await res.json();
        const u = document.getElementById('in-user');
        const w = document.getElementById('in-wallet');
        const c = document.getElementById('in-cpu');
        if (u && s.username) u.value = s.username;
        if (c && s.limit_cpu) { c.value = s.limit_cpu; }
        const cv = document.getElementById('cpu-val');
        if (cv && s.limit_cpu) cv.textContent = Math.round(s.limit_cpu) + '%';
        const hint = document.getElementById('setup-hint');
        if (hint) hint.classList.toggle('hidden', !!s.has_wallet);
        if (w && s.has_wallet) w.placeholder = 'Wallet saved ✓';
    } catch (e) {}
}

async function saveSettings() {
    try {
        return await fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                wallet: document.getElementById('in-wallet').value.trim(),
                username: document.getElementById('in-user').value.trim(),
                limit_cpu: parseFloat(document.getElementById('in-cpu').value),
            })
        }).then(r => r.json());
    } catch (e) { return {}; }
}

async function startMining() {
    const s = btnStart(); if (s) s.disabled = true;
    await saveSettings();
    let res = {ok: false, error: 'network'};
    try {
        res = await fetch('/api/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                wallet: document.getElementById('in-wallet').value.trim(),
                username: document.getElementById('in-user').value.trim() || 'miner',
                limit_cpu: parseFloat(document.getElementById('in-cpu').value),
                stealth: true,
            })
        }).then(r => r.json());
    } catch (e) {}
    if (!res.ok) {
        if (res.error === 'xmrig_not_found') {
            alert('xmrig is not installed yet.\nOpen Terminal in this folder and run:\n\n    hashflow install');
        } else if (res.error === 'wallet_missing') {
            alert('Please enter your Monero wallet address first.');
        } else {
            alert('Could not start mining: ' + (res.error || 'unknown'));
        }
    }
    if (s) s.disabled = false;
}

async function stopMining() {
    try { await fetch('/api/stop', {method: 'POST'}); } catch (e) {}
}

async function loadPrice() {
    try {
        const p = await (await fetch('/api/price')).json();
        const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
        set('xmr-price', `XMR: ₱${(p.xmr_php||0).toLocaleString(undefined,{maximumFractionDigits:2})} (${p.offline ? 'offline est.' : 'live'})`);
        set('earn-xmr', `${(p.xmr_day_est||0).toFixed(6)} XMR/day`);
        set('earn-php', `₱${(p.php_day_est||0).toFixed(2)}/day`);
    } catch (e) {}
}

async function loadPdax() {
    try {
        const g = await (await fetch('/api/pdax')).json();
        const ol = document.getElementById('pdax-steps');
        if (ol && g.steps) ol.innerHTML = g.steps.map(s => `<li>${s.replace(/^\d+\.\s*/, '')}</li>`).join('');
    } catch (e) {}
}

// Init
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    initLogTabs();
    connectWebSocket();
    fetchGroup();
    fetchLogs();
    setInterval(fetchGroup, 10000);
    setInterval(fetchLogs, 3000);

    // Control deck
    const s = btnStart(), t = btnStop();
    if (s) s.addEventListener('click', startMining);
    if (t) t.addEventListener('click', stopMining);
    const cpu = document.getElementById('in-cpu');
    if (cpu) cpu.addEventListener('input', e => {
        const cv = document.getElementById('cpu-val');
        if (cv) cv.textContent = e.target.value + '%';
    });
    loadSettings();
    loadPrice();
    loadPdax();
    setInterval(loadPrice, 60000);
});
