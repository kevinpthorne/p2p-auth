let adminToken = sessionStorage.getItem('p2p_auth_token') || '';
let eventSource = null;

function authHeaders() {
    const h = { 'Content-Type': 'application/json' };
    if (adminToken) {
        h['Authorization'] = 'Bearer ' + adminToken;
    }
    return h;
}

async function apiFetch(path, opts = {}) {
    opts.headers = Object.assign(authHeaders(), opts.headers || {});
    const res = await fetch(path, opts);
    if (res.status === 401) {
        document.getElementById('login-overlay').classList.remove('hidden');
        throw new Error('Unauthorized');
    }
    return res;
}

function shortHex(str, len = 14) {
    if (!str) return '-';
    return str.length > len ? str.slice(0, len) + '…' : str;
}

async function refreshAll() {
    try {
        const [statusRes, pendingRes, psksRes, nodesRes] = await Promise.all([
            apiFetch('/api/admin/status'),
            apiFetch('/api/admin/adopt/pending'),
            apiFetch('/api/admin/psks'),
            apiFetch('/api/admin/nodes')
        ]);
        const status = await statusRes.json();
        const pending = await pendingRes.json();
        const psks = await psksRes.json();
        const nodes = await nodesRes.json();

        document.getElementById('login-overlay').classList.add('hidden');
        document.getElementById('epoch-id-val').textContent = status.epoch_id;
        document.getElementById('merkle-root-val').textContent = shortHex(status.merkle_root, 18);
        document.getElementById('merkle-root-val').title = status.merkle_root || '';
        document.getElementById('active-count-val').textContent = status.active_nodes_count;
        document.getElementById('swarm-peers-val').textContent = status.swarm_peers_count;
        document.getElementById('ca-key-id-val').textContent = status.ca_key_id || '-';
        document.getElementById('pending-badge').textContent = pending.length;
        document.getElementById('active-nodes-badge').textContent = status.active_nodes_count;

        renderPending(pending);
        renderPSKs(psks);
        renderNodes(nodes);
    } catch (e) {
        // Handled by 401 overlay if unauthenticated
    }
}

function renderPending(list) {
    const tbody = document.getElementById('pending-table-body');
    if (!list || list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No pending node adoptions</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    list.forEach(item => {
        const tr = document.createElement('tr');
        const manifestStr = item.requested_manifest_text || '{{PEER_ID}}|10.200.0.1/24';
        tr.innerHTML = `
            <td>
                <div><strong>${item.subject_id || 'unnamed'}</strong></div>
                <div class="mono hint" title="${item.peer_id}">${shortHex(item.peer_id, 20)}</div>
            </td>
            <td class="mono">${item.namespace}</td>
            <td><span class="badge badge-tier">${item.keystore_tier || 'Filesystem'}</span></td>
            <td class="mono">${shortHex(manifestStr, 28)}</td>
            <td>
                <button class="btn btn-success btn-sm approve-row-btn">Approve & Sign</button>
                <button class="btn btn-danger btn-sm reject-row-btn">Reject</button>
            </td>
        `;
        tr.querySelector('.approve-row-btn').addEventListener('click', () => openApproveModal(item));
        tr.querySelector('.reject-row-btn').addEventListener('click', () => rejectNode(item.peer_id));
        tbody.appendChild(tr);
    });
}

function renderPSKs(list) {
    const tbody = document.getElementById('psks-table-body');
    if (!list || list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No PSKs registered</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    list.forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="mono">${p.psk_id}</td>
            <td class="mono">${p.namespace}</td>
            <td><span class="badge badge-tier">${p.mode}</span></td>
            <td>${p.used_count} / ${p.max_uses}</td>
            <td>
                ${p.revoked ? '<span class="badge badge-revoked">REVOKED</span>' : '<button class="btn btn-danger btn-sm revoke-psk-btn">Revoke</button>'}
            </td>
        `;
        const btn = tr.querySelector('.revoke-psk-btn');
        if (btn) {
            btn.addEventListener('click', async () => {
                await apiFetch('/api/admin/psks/' + encodeURIComponent(p.psk_id), { method: 'DELETE' });
                await refreshAll();
            });
        }
        tbody.appendChild(tr);
    });
}

function renderNodes(list) {
    const filterNS = document.getElementById('filter-namespace').value.trim().toLowerCase();
    const tbody = document.getElementById('nodes-table-body');
    const filtered = (list || []).filter(n => !filterNS || (n.namespace || '').toLowerCase().includes(filterNS));
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty-row">No enrolled credentials</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    filtered.forEach(n => {
        const tr = document.createElement('tr');
        tr.dataset.serial = n.serial;
        tr.dataset.peerId = n.peer_id;
        tr.innerHTML = `
            <td class="mono">#${n.serial}</td>
            <td>
                <div><strong>${n.subject_id || '-'}</strong></div>
                <div class="mono hint" title="${n.peer_id}">${shortHex(n.peer_id, 20)}</div>
            </td>
            <td class="mono">${n.namespace}</td>
            <td class="mono">${n.leaf_index}</td>
            <td class="mono" title="${n.claims_commitment_hex}">${shortHex(n.claims_commitment_hex, 16)}</td>
            <td class="mono">${shortHex(n.manifest_text, 28)}</td>
            <td class="node-status-cell">
                <span class="badge ${n.revoked ? 'badge-revoked' : 'badge-active'}">${n.revoked ? 'REVOKED' : 'ACTIVE'}</span>
            </td>
            <td>
                ${n.revoked ? '-' : '<button class="btn btn-danger btn-sm revoke-node-btn">Revoke</button>'}
            </td>
        `;
        const revokeBtn = tr.querySelector('.revoke-node-btn');
        if (revokeBtn) {
            revokeBtn.addEventListener('click', () => revokeNode(n.serial, n.peer_id));
        }
        tbody.appendChild(tr);
    });
}

function openApproveModal(item) {
    document.getElementById('approve-peer-id').value = item.peer_id;
    document.getElementById('approve-peer-display').value = item.peer_id;
    document.getElementById('approve-namespace').value = item.namespace || 'default';
    document.getElementById('approve-domain-context').value = item.domain_context || 'p2p-auth:manifest:v1';
    document.getElementById('approve-manifest').value = item.requested_manifest_text || `{"peer":"${item.peer_id}"}`;
    document.getElementById('approve-modal').classList.remove('hidden');
}

async function rejectNode(peerId) {
    await apiFetch('/api/admin/adopt/reject', {
        method: 'POST',
        body: JSON.stringify({ peer_id: peerId })
    });
    await refreshAll();
}

async function revokeNode(serial, peerId) {
    await apiFetch('/api/admin/revoke', {
        method: 'POST',
        body: JSON.stringify({ serial: serial, peer_id: peerId })
    });
    await refreshAll();
}

function connectSSE() {
    if (eventSource) {
        eventSource.close();
    }
    const url = '/api/admin/events?token=' + encodeURIComponent(adminToken);
    eventSource = new EventSource(url);
    eventSource.onmessage = (e) => {
        const logEl = document.getElementById('events-log');
        const line = document.createElement('div');
        line.textContent = `[${new Date().toISOString()}] ${e.data}`;
        logEl.prepend(line);
        refreshAll();
    };
}

document.addEventListener('DOMContentLoaded', () => {
    // Tab switching
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById('view-' + btn.dataset.tab).classList.add('active');
        });
    });

    // Login form
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const tok = document.getElementById('admin-token-input').value.trim();
        const res = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: tok })
        });
        if (!res.ok) {
            document.getElementById('login-error').classList.remove('hidden');
            return;
        }
        adminToken = tok;
        sessionStorage.setItem('p2p_auth_token', tok);
        document.getElementById('login-error').classList.add('hidden');
        document.getElementById('login-overlay').classList.add('hidden');
        connectSSE();
        await refreshAll();
    });

    // PSK create form
    document.getElementById('psk-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            namespace: document.getElementById('psk-namespace').value.trim(),
            mode: document.getElementById('psk-mode').value,
            domain_context: document.getElementById('psk-domain-context').value.trim(),
            max_uses: parseInt(document.getElementById('psk-max-uses').value, 10) || 1,
            ttl_hours: parseInt(document.getElementById('psk-ttl-hours').value, 10) || 24,
            manifest_template: document.getElementById('psk-template').value,
            require_hardware_tier: document.getElementById('psk-require-hw').checked
        };
        const res = await apiFetch('/api/admin/psks', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.token) {
            document.getElementById('generated-psk-val').textContent = data.token;
            document.getElementById('generated-psk-box').classList.remove('hidden');
        }
        await refreshAll();
    });

    // Approve modal
    document.getElementById('approve-cancel-btn').addEventListener('click', () => {
        document.getElementById('approve-modal').classList.add('hidden');
    });
    document.getElementById('approve-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            peer_id: document.getElementById('approve-peer-id').value,
            namespace: document.getElementById('approve-namespace').value.trim(),
            domain_context: document.getElementById('approve-domain-context').value.trim(),
            manifest_payload: document.getElementById('approve-manifest').value
        };
        await apiFetch('/api/admin/adopt/approve', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        document.getElementById('approve-modal').classList.add('hidden');
        await refreshAll();
    });

    // Manual Enroll modal
    document.getElementById('open-enroll-modal-btn').addEventListener('click', () => {
        document.getElementById('enroll-modal').classList.remove('hidden');
    });
    document.getElementById('enroll-cancel-btn').addEventListener('click', () => {
        document.getElementById('enroll-modal').classList.add('hidden');
    });
    document.getElementById('enroll-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const payload = {
            peer_id: document.getElementById('enroll-peer-id').value.trim(),
            subject_id: document.getElementById('enroll-subject-id').value.trim(),
            namespace: document.getElementById('enroll-namespace').value.trim(),
            domain_context: document.getElementById('enroll-domain-context').value.trim(),
            manifest_payload: document.getElementById('enroll-manifest').value
        };
        await apiFetch('/api/admin/nodes/enroll', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        document.getElementById('enroll-modal').classList.add('hidden');
        await refreshAll();
    });

    // Rotate Epoch
    document.getElementById('rotate-epoch-btn').addEventListener('click', async () => {
        await apiFetch('/api/admin/epoch/rotate', { method: 'POST' });
        await refreshAll();
    });

    // Filter namespace
    document.getElementById('filter-namespace').addEventListener('input', () => {
        refreshAll();
    });

    refreshAll().then(() => {
        if (adminToken) connectSSE();
    });
});
