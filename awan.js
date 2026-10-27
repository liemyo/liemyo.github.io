// Awan — cadangan cloud untuk data browser di liemyo.github.io (Rumah 3D, RAB, MMORPG, btcusdt, launcher, dll.).
// Semua situs di liemyo.github.io berbagi satu localStorage, jadi satu cadangan memuat data semuanya.
// Disimpan di Backblaze B2 (penyimpanan bersama pantau/klip-worker, situs 'cadangan', per akun) lewat Supabase Edge Function
// simpan; login = akun Amatu (nama + PIN, sama dengan Planner). Isi dienkripsi di browser (AES-GCM, kunci dari PIN), jadi
// server tidak bisa membacanya. Cadangan otomatis sekali sehari bila ada perubahan; 14 cadangan terakhir disimpan.
(() => {
  if (window.__awan) return; window.__awan = true;
  // Tombol ☁ hanya tampil bila <script … data-tombol="1"> (halaman utama) atau ?awan di alamat; di situs lain cadangan berjalan diam-diam.
  const TOMBOL = document.currentScript?.dataset.tombol === '1';
  const B2 = 'https://bbptcxpzzvgpxqylkrmw.supabase.co/functions/v1/simpan', KEEP = 14, DAY = 864e5;
  const L = { get: k => { try { return localStorage.getItem('awan.' + k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem('awan.' + k, v); } catch {} }, del: k => { try { localStorage.removeItem('awan.' + k); } catch {} } };
  const enc = new TextEncoder(), dec = new TextDecoder();
  let sess = null; try { sess = JSON.parse(L.get('sess') || 'null'); } catch {}

  async function b2(path, init = {}, s = sess) {
    const r = await fetch(B2 + path, { ...init, cache: 'no-store', headers: { 'x-site': 'cadangan', 'x-token': s.name + '\n' + s.pin, ...(init.headers || {}) } });
    const j = await r.json().catch(() => null);
    if (!r.ok) { const e = new Error(r.status === 401 ? 'Nama / PIN salah, atau akun belum punya PIN (atur PIN di Planner).' : r.status === 413 ? 'Kuota cadangan penuh.' : 'Server: ' + (j?.error || r.status)); e.status = r.status; throw e; }
    return j;
  }
  const post = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const sha = async b => [...new Uint8Array(await crypto.subtle.digest('SHA-256', b))].map(x => x.toString(16).padStart(2, '0')).join('');
  const key = s => crypto.subtle.importKey('raw', enc.encode(s.pin), 'PBKDF2', false, ['deriveKey']).then(k => crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode('awan-v1|' + s.name), iterations: 200000 }, k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']));
  const pipe = (bytes, t) => new Response(new Blob([bytes]).stream().pipeThrough(t)).arrayBuffer();

  function snapshot() { // semua localStorage kecuali milik Awan sendiri
    const o = {};
    for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k && !k.startsWith('awan.')) o[k] = localStorage.getItem(k); }
    return o;
  }
  async function pack(data, s) { // 'AWN1' + iv(12) + AES-GCM(gzip(json))
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await key(s), await pipe(enc.encode(JSON.stringify(data)), new CompressionStream('gzip')));
    return new Blob([enc.encode('AWN1'), iv, ct], { type: 'application/octet-stream' });
  }
  async function unpack(buf, s) {
    const u = new Uint8Array(buf);
    if (dec.decode(u.subarray(0, 4)) !== 'AWN1') throw new Error('Berkas cadangan tidak dikenal.');
    let pt; try { pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.subarray(4, 16) }, await key(s), u.subarray(16)); }
    catch { throw new Error('Tidak bisa dibuka — PIN berbeda dengan saat dicadangkan.'); }
    return JSON.parse(dec.decode(await pipe(pt, new DecompressionStream('gzip'))));
  }

  const stamp = d => d.toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 13); // 20261027-1530 (UTC)
  const when = p => { const m = p.match(/liemyo-(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)$/); return m ? new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5])) : null; };
  async function list() { return (await b2('/list')).files.filter(f => when(f.path)).sort((a, b) => b.path.localeCompare(a.path)); }

  async function backup(manual) {
    if (!sess) throw new Error('Belum masuk.');
    const data = snapshot(), json = JSON.stringify(data), h = await sha(enc.encode(json));
    if (!manual && h === L.get('hash')) { L.set('last', String(Date.now())); return { same: true }; }
    const me = await b2('/me'), blob = await pack(data, sess), path = me.prefix + 'liemyo-' + stamp(new Date());
    if (blob.size <= 8388608) await b2('/o/' + path, { method: 'PUT', body: blob, headers: { 'Content-Type': 'application/octet-stream' } }).catch(e => { if (e.status !== 409) throw e; });
    else {
      const m = await b2('/mp/start', post({ path, size: blob.size, mime: 'application/octet-stream' })), n = Math.ceil(blob.size / m.part);
      for (let i = 0; i < n; i++) await b2(`/mp/part?id=${encodeURIComponent(m.id)}&n=${i + 1}`, { method: 'PUT', body: blob.slice(i * m.part, (i + 1) * m.part) });
      await b2('/mp/done', post({ id: m.id }));
    }
    L.set('hash', h); L.set('last', String(Date.now()));
    const old = (await list()).slice(KEEP).map(f => f.path);
    if (old.length) await b2('/del', post({ paths: old })).catch(() => {});
    return { size: blob.size, keys: Object.keys(data).length };
  }
  async function restore(path) {
    const url = (await b2('/sign', post({ paths: [path] })))[path], r = url && await fetch(url);
    if (!r?.ok) throw new Error('Cadangan tidak bisa diunduh.');
    const data = await unpack(await r.arrayBuffer(), sess);
    for (const [k, v] of Object.entries(data)) try { localStorage.setItem(k, v); } catch {}
    L.set('hash', await sha(enc.encode(JSON.stringify(snapshot()))));
    return Object.keys(data).length;
  }

  // ---------- tampilan ----------
  const css = `#awan-b{position:fixed;left:10px;bottom:10px;z-index:2147483000;width:34px;height:34px;border-radius:50%;border:1px solid rgba(127,127,127,.35);
    background:rgba(30,34,40,.72);color:#fff;font:16px/1 system-ui;cursor:pointer;opacity:.55;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
    #awan-b:hover,#awan-b.on{opacity:1}#awan-b i{position:absolute;right:-1px;top:-1px;width:9px;height:9px;border-radius:50%;background:#e5484d}
    #awan-p{position:fixed;left:10px;bottom:52px;z-index:2147483001;width:min(320px,calc(100vw - 20px));max-height:70vh;overflow:auto;box-sizing:border-box;padding:14px;border-radius:14px;
    background:#1d2127;color:#e9edf2;font:13px/1.45 system-ui,-apple-system,sans-serif;box-shadow:0 10px 40px rgba(0,0,0,.45);border:1px solid #333a44}
    #awan-p h3{margin:0 0 6px;font-size:15px}#awan-p p{margin:6px 0;color:#aab3bf}#awan-p input,#awan-p select{width:100%;box-sizing:border-box;margin:4px 0;padding:8px;border-radius:8px;border:1px solid #3a424e;background:#12151a;color:#fff;font:inherit}
    #awan-p button{margin:4px 4px 0 0;padding:7px 11px;border-radius:8px;border:0;background:#2f6fde;color:#fff;font:inherit;cursor:pointer}#awan-p button.g{background:#38404c}#awan-p button:disabled{opacity:.5}
    #awan-p .m{min-height:18px;color:#8fd19e}#awan-p .e{color:#ff8a8a}`;
  const st = document.createElement('style'); st.textContent = css;
  const btn = document.createElement('button'); btn.id = 'awan-b'; btn.type = 'button'; btn.title = 'Cadangan cloud (Awan)'; btn.textContent = '☁';
  const pan = document.createElement('div'); pan.id = 'awan-p'; pan.hidden = true;
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmt = d => d.toLocaleString('id-ID', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  const msg = (t, err) => { const m = pan.querySelector('.m'); if (m) { m.textContent = t; m.classList.toggle('e', !!err); } };
  const dot = () => { btn.querySelector('i')?.remove(); if (sess && Date.now() - Number(L.get('last') || 0) > 3 * DAY) btn.append(document.createElement('i')); };

  async function draw() {
    if (!sess) {
      pan.innerHTML = `<h3>☁ Cadangan cloud</h3><p>Simpan data situs-situs liemyo.github.io (Rumah 3D, RAB, game, dll.) ke cloud, terenkripsi. Masuk dengan akun Amatu (sama dengan Planner, wajib ber-PIN).</p>
        <form><input name="n" placeholder="Nama pengguna" autocomplete="username" autocapitalize="none" required><input name="p" type="password" inputmode="numeric" placeholder="PIN" autocomplete="current-password" required>
        <button>Masuk</button><button type="button" class="g" data-x="hide">Sembunyikan ☁</button></form><div class="m"></div>`;
      pan.querySelector('form').onsubmit = async ev => {
        ev.preventDefault(); const f = ev.target, s = { name: f.n.value.trim().toLowerCase(), pin: f.p.value };
        try { msg('Memeriksa…'); await b2('/me', {}, s); sess = s; L.set('sess', JSON.stringify(s)); draw(); auto(true); } catch (e) { msg(e.message, true); }
      };
      return;
    }
    pan.innerHTML = `<h3>☁ Cadangan cloud</h3><p>Akun <b>${esc(sess.name)}</b> · terakhir ${L.get('last') ? fmt(new Date(+L.get('last'))) : 'belum pernah'}</p>
      <button data-x="now">Cadangkan sekarang</button><p style="margin-top:12px">Pulihkan (menimpa data di browser ini):</p><select disabled><option>Memuat daftar…</option></select>
      <button class="g" data-x="restore" disabled>Pulihkan</button><p class="u"></p><button class="g" data-x="out">Keluar</button><button class="g" data-x="hide">Sembunyikan ☁</button><div class="m"></div>`;
    try {
      const [fs, u] = await Promise.all([list(), b2('/usage')]), sel = pan.querySelector('select');
      sel.innerHTML = fs.length ? fs.map(f => `<option value="${esc(f.path)}">${fmt(when(f.path))} · ${(f.size / 1024).toFixed(0)} KB</option>`).join('') : '<option>Belum ada cadangan</option>';
      sel.disabled = !fs.length; pan.querySelector('[data-x=restore]').disabled = !fs.length;
      pan.querySelector('.u').textContent = `Kuota bersama: ${(u.used / 1048576).toFixed(1)} MB / ${(u.quota / 1073741824).toFixed(1)} GB`;
    } catch (e) { msg(e.message, true); }
  }
  pan.addEventListener('click', async ev => {
    const x = ev.target.dataset?.x; if (!x) return;
    if (x === 'hide') { L.set('hide', '1'); btn.remove(); pan.remove(); return; }
    if (x === 'out') { sess = null; ['sess', 'hash', 'last'].forEach(L.del); draw(); dot(); return; }
    ev.target.disabled = true;
    try {
      if (x === 'now') { msg('Mencadangkan…'); const r = await backup(true); msg(`Tersimpan (${r.keys} data, ${(r.size / 1024).toFixed(0)} KB).`); await draw(); msg('Tersimpan ✓'); }
      if (x === 'restore') {
        const p = pan.querySelector('select').value;
        if (!confirm('Pulihkan cadangan ini? Data di browser ini akan ditimpa.')) return;
        msg('Memulihkan…'); const n = await restore(p); msg(`${n} data dipulihkan. Memuat ulang…`); setTimeout(() => location.reload(), 900);
      }
    } catch (e) { msg(e.message, true); } finally { ev.target.disabled = false; dot(); }
  });
  btn.onclick = () => { pan.hidden = !pan.hidden; btn.classList.toggle('on', !pan.hidden); if (!pan.hidden) draw(); };

  async function auto(now) { // sekali sehari, hanya bila ada perubahan
    if (!sess || (!now && Date.now() - Number(L.get('last') || 0) < DAY)) return;
    try { await backup(false); } catch (e) { if (e.status === 401) { sess = null; L.del('sess'); } console.warn('Awan:', e.message); } finally { dot(); }
  }
  window.Awan = { backup, restore, list, unpack, pack, snapshot, get sess() { return sess; } }; // dipakai juga untuk uji

  const show = () => {
    // ?awan memunculkan tombol (juga yang pernah disembunyikan)
    const ask = new URLSearchParams(location.search).has('awan');
    if (ask) L.del('hide');
    document.head.append(st);
    if (ask || (TOMBOL && !L.get('hide'))) document.body.append(btn, pan);
    dot(); setTimeout(() => auto(false), 8000);
  };
  document.readyState === 'loading' ? document.addEventListener('DOMContentLoaded', show) : show();
})();
