/* ============================================================
   Hospital Laboratory Management System - Frontend JS
   ============================================================ */

/* ---------------- security helpers ---------------- */
function csrfHeaders(extra) {
  var h = { 'X-CSRF-Token': window.CSRF_TOKEN || '', 'Content-Type': 'application/json' };
  return Object.assign(h, extra || {});
}

function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function openModal(id) {
  var content = document.getElementById(id);
  if (!content) return;
  document.getElementById('modalBox').innerHTML = content.innerHTML;
  document.getElementById('modalBackdrop').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  document.getElementById('modalBackdrop').classList.remove('open');
  document.body.style.overflow = '';
}

document.getElementById('modalBackdrop').addEventListener('click', function (e) {
  if (e.target === this) closeModal();
});

document.addEventListener('click', function (e) {
  var drop = document.getElementById('userDrop');
  if (drop && drop.classList.contains('open') && !e.target.closest('.user-menu')) {
    drop.classList.remove('open');
  }
});

document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') closeModal();
});

/* ---------------- Toasts ---------------- */
function showToast(message, type) {
  var wrap = document.getElementById('toastWrap');
  var icons = { success: '&#10004;', error: '&#10060;', info: '&#8505;' };
  var el = document.createElement('div');
  el.className = 'toast ' + (type || 'info');
  el.innerHTML =
    '<span class="t-ico">' + (icons[type] || icons.info) + '</span>' +
    '<span class="t-msg">' + message + '</span>' +
    '<button class="t-close" onclick="this.parentElement.remove()">&#10005;</button>';
  wrap.appendChild(el);
  setTimeout(function () {
    el.classList.add('leaving');
    setTimeout(function () { el.remove(); }, 220);
  }, 3200);
}

/* ---------------- Delete record ---------------- */
function deleteRecord(table, recordId) {
  if (!confirm('Delete record ' + recordId + '? This cannot be undone.')) return;
  fetch('/api/delete/' + table + '/' + encodeURIComponent(recordId), {
    method: 'POST',
    headers: csrfHeaders()
  })
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d.ok) {
        showToast('Record ' + recordId + ' deleted', 'success');
        setTimeout(function () { location.reload(); }, 600);
      } else {
        showToast(d.error || 'Delete failed', 'error');
      }
    })
    .catch(function () { showToast('Network error', 'error'); });
}

/* ---------------- Global search ---------------- */
function globalSearch(value) {
  var q = value.trim().toLowerCase();
  document.querySelectorAll('.table-wrap tbody tr').forEach(function (tr) {
    var text = tr.textContent.toLowerCase();
    tr.style.display = q && text.indexOf(q) === -1 ? 'none' : '';
  });
  var emptyRows = document.querySelectorAll('.table-wrap tbody tr');
  var anyVisible = false;
  emptyRows.forEach(function (tr) {
    if (tr.style.display !== 'none' && tr.querySelector('td')) anyVisible = true;
  });
}

/* ---------------- Auto-dismiss flash messages ---------------- */
setTimeout(function () {
  document.querySelectorAll('.flash').forEach(function (el) {
    el.style.transition = 'opacity .5s';
    el.style.opacity = '0';
    setTimeout(function () { el.remove(); }, 500);
  });
}, 4500);

/* ============================================================
   Test / Profile Picker
   ============================================================ */

function pickerRoot(el) {
  return el.closest('[data-picker]');
}

function onPickChange(cb) {
  var card = cb.closest('.pick-card');
  card.classList.toggle('checked', cb.checked);
  if (!cb.checked) uncheckContainingProfiles(cb);
  syncPicker(pickerRoot(cb));
}

function onProfileChange(cb) {
  var card = cb.closest('.pick-card');
  card.classList.toggle('checked', cb.checked);
  var root = pickerRoot(cb);
  if (cb.checked) {
    var members = (card.dataset.members || '').split(',').filter(Boolean);
    members.forEach(function (tid) {
      var member = root.querySelector('.test-cb[value="' + tid + '"]');
      if (member) {
        member.checked = true;
        member.closest('.pick-card').classList.add('checked');
      }
    });
  }
  syncPicker(root);
}

function uncheckContainingProfiles(cb) {
  var root = pickerRoot(cb);
  root.querySelectorAll('.profile-cb:checked').forEach(function (pcb) {
    var pcard = pcb.closest('.pick-card');
    var members = (pcard.dataset.members || '').split(',').filter(Boolean);
    if (members.indexOf(cb.value) !== -1) {
      pcb.checked = false;
      pcard.classList.remove('checked');
    }
  });
}

function syncPicker(root) {
  if (!root) return;
  var tests = root.querySelectorAll('.test-cb');
  var count = 0, total = 0;
  tests.forEach(function (cb) {
    if (cb.checked) { count++; total += parseFloat(cb.dataset.price || 0); }
  });
  root.querySelector('.picker-hidden').innerHTML =
    Array.prototype.slice.call(root.querySelectorAll('.test-cb:checked'))
      .map(function (cb) { return '<input type="hidden" name="test_ids" value="' + cb.value + '">'; })
      .join('') +
    Array.prototype.slice.call(root.querySelectorAll('.profile-cb:checked'))
      .map(function (cb) { return '<input type="hidden" name="profile_ids" value="' + cb.value + '">'; })
      .join('');
  var sum = root.querySelector('.pick-summary');
  var tot = root.querySelector('.pick-total');
  if (sum) sum.textContent = count + ' test' + (count === 1 ? '' : 's') + ' selected';
  if (tot) tot.innerHTML = 'Total: &#8377;' + total.toLocaleString('en-IN');
}

function filterPicker(input) {
  var root = pickerRoot(input);
  var q = input.value.trim().toLowerCase();
  root.querySelectorAll('.pick-card').forEach(function (card) {
    card.style.display = (q && card.textContent.toLowerCase().indexOf(q) === -1) ? 'none' : '';
  });
  root.querySelectorAll('.picker-section').forEach(function (sec) {
    var any = Array.prototype.some.call(sec.querySelectorAll('.pick-card'), function (c) { return c.style.display !== 'none'; });
    sec.style.display = any ? '' : 'none';
  });
}

function syncPickerSubmit(event) {
  document.querySelectorAll('[data-picker]').forEach(syncPicker);
  return true;
}

function initPicker() {
  document.querySelectorAll('[data-picker]').forEach(syncPicker);
}
