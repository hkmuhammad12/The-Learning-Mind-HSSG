// Admin panel: full control of the public Welfare Foundation page (page details + text/picture sections).
(function () {
  const $ = (id) => document.getElementById(id);
  const MAX = 5 * 1024 * 1024, OK = ['jpg', 'jpeg', 'png', 'webp', 'gif'];

  async function request(url, method, body) {
    const opts = { method };
    if (body instanceof FormData) opts.body = body;
    else if (body) { opts.body = JSON.stringify(body); opts.headers = { 'Content-Type': 'application/json' }; }
    const res = await fetch(url, opts);
    let data = {}; try { data = await res.json(); } catch (e) {}
    if (!res.ok) throw new Error(res.status === 401 || res.status === 403 ? 'Your session has expired. Please log in again.' : (data.error || 'Something went wrong.'));
    return data;
  }
  const bad = (f) => {
    if (!f) return null;
    if (!OK.includes(f.name.split('.').pop().toLowerCase())) return 'Please choose a JPG, PNG, WEBP or GIF image.';
    if (f.size > MAX) return 'The image must be 5 MB or smaller.';
    return null;
  };
  const prev = (box, src) => { box.innerHTML = src ? `<img src="${escapeHtml(src)}" alt="">` : 'No photo'; };
  const busy = (btn, on, txt) => { if (!btn.dataset.l) btn.dataset.l = btn.textContent; btn.disabled = on; btn.textContent = on ? txt : btn.dataset.l; };

  // ---------- page details ----------
  let cover = null;
  async function loadPage() {
    try {
      const d = await (await fetch('/api/content/welfare')).json();
      const p = d.page || {};
      $('wfPTitle').value = p.title || ''; $('wfPSub').value = p.subtitle || ''; $('wfPIntro').value = p.intro || '';
      cover = p.cover_path || null; prev($('wfPPreview'), cover);
      $('wfPRemoveWrap').style.display = cover ? 'flex' : 'none'; $('wfPRemove').checked = false;
      renderSections(d.sections || []);
    } catch (e) { TLM.error('Could not load the Welfare Foundation page.'); }
  }
  $('wfPPhoto').addEventListener('change', () => {
    const f = $('wfPPhoto').files[0], m = bad(f);
    if (m) { TLM.error(m); $('wfPPhoto').value = ''; prev($('wfPPreview'), cover); return; }
    if (f) prev($('wfPPreview'), URL.createObjectURL(f));
  });
  $('wfPageForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData();
    fd.append('title', $('wfPTitle').value); fd.append('subtitle', $('wfPSub').value); fd.append('intro', $('wfPIntro').value);
    if ($('wfPPhoto').files[0]) fd.append('photo', $('wfPPhoto').files[0]);
    if ($('wfPRemove').checked) fd.append('remove_photo', '1');
    busy($('wfPSave'), true, 'Saving…');
    try { await request('/api/admin/content/welfare', 'PUT', fd); TLM.success('The Welfare Foundation page was updated.', 'Saved'); $('wfPPhoto').value = ''; loadPage(); }
    catch (err) { TLM.error(err.message); } finally { busy($('wfPSave'), false); }
  });

  // ---------- sections ----------
  let sections = [], editPhoto = null;
  function renderSections(list) {
    sections = list;
    const box = $('wfSList');
    if (!list.length) { box.innerHTML = '<div class="empty-note" style="grid-column:1/-1">No sections yet. Add the first one above.</div>'; return; }
    box.innerHTML = list.map(s => `
      <div class="admin-card">
        ${s.photo_path ? `<img class="ac-img" src="${escapeHtml(s.photo_path)}" alt="" loading="lazy">` : ''}
        <div class="ac-body"><b>${escapeHtml(s.heading)}</b><small>${escapeHtml((s.body || '').slice(0, 110))}${(s.body || '').length > 110 ? '…' : ''}</small>
          <div class="ac-actions"><button class="rowbtn" data-edit="${s.id}">Edit</button><button class="rowbtn danger" data-del="${s.id}">Delete</button></div></div>
      </div>`).join('');
  }
  function resetForm() {
    $('wfSForm').reset(); $('wfSId').value = ''; editPhoto = null; prev($('wfSPreview'), null);
    $('wfSRemoveWrap').style.display = 'none'; $('wfSBanner').classList.remove('show');
    $('wfSFormTitle').textContent = 'Add a section (text + picture)'; $('wfSSave').textContent = 'Add section'; $('wfSSave').dataset.l = 'Add section';
    $('wfSCancel').style.display = 'none';
  }
  $('wfSPhoto').addEventListener('change', () => {
    const f = $('wfSPhoto').files[0], m = bad(f);
    if (m) { TLM.error(m); $('wfSPhoto').value = ''; prev($('wfSPreview'), editPhoto); return; }
    if (f) prev($('wfSPreview'), URL.createObjectURL(f));
  });
  $('wfSCancel').addEventListener('click', resetForm);
  $('wfSForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = $('wfSId').value, fd = new FormData();
    fd.append('heading', $('wfSHeading').value); fd.append('body', $('wfSBody').value); fd.append('sort_order', $('wfSOrder').value);
    if ($('wfSPhoto').files[0]) fd.append('photo', $('wfSPhoto').files[0]);
    if ($('wfSRemove').checked) fd.append('remove_photo', '1');
    busy($('wfSSave'), true, 'Saving…');
    try {
      await request('/api/admin/content/welfare/sections' + (id ? '/' + id : ''), id ? 'PUT' : 'POST', fd);
      TLM.success(id ? 'The section was updated.' : 'The section was added.', 'Saved');
      resetForm(); loadPage();
    } catch (err) { TLM.error(err.message); } finally { busy($('wfSSave'), false); }
  });
  $('wfSList').addEventListener('click', async (e) => {
    const ed = e.target.closest('[data-edit]'), del = e.target.closest('[data-del]');
    if (ed) {
      const s = sections.find(x => x.id === Number(ed.dataset.edit)); if (!s) return;
      $('wfSId').value = s.id; $('wfSHeading').value = s.heading; $('wfSBody').value = s.body || ''; $('wfSOrder').value = s.sort_order;
      editPhoto = s.photo_path || null; prev($('wfSPreview'), editPhoto);
      $('wfSRemoveWrap').style.display = editPhoto ? 'flex' : 'none'; $('wfSRemove').checked = false;
      $('wfSBanner').textContent = 'Editing: ' + s.heading; $('wfSBanner').classList.add('show');
      $('wfSFormTitle').textContent = 'Edit section'; $('wfSSave').textContent = 'Save changes'; $('wfSSave').dataset.l = 'Save changes';
      $('wfSCancel').style.display = ''; $('wfSForm').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    if (del) {
      const s = sections.find(x => x.id === Number(del.dataset.del)); if (!s) return;
      if (!confirm('Delete the section "' + s.heading + '"? This cannot be undone.')) return;
      try { await request('/api/admin/content/welfare/sections/' + s.id, 'DELETE'); TLM.success('The section was deleted.', 'Deleted'); loadPage(); }
      catch (err) { TLM.error(err.message); }
    }
  });

  loadPage();
})();
