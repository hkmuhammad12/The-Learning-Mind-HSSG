// Safely create (or repair) the intended admin account WITHOUT duplicates.
//   ADMIN_USERNAME=hkmuhammad ADMIN_PASSWORD='...' npm run ensure-admin
// - Username lookup is case-insensitive, so "HKMuhammad" and "hkmuhammad" are the same account.
// - If the account is missing        -> it is created.
// - If it exists and is inactive      -> it is re-activated.
// - If it exists and password differs -> the password is changed ONLY when ADMIN_RESET_PASSWORD=1.
// - Never touches any other user, and never deletes anything.
// Set ADMIN_FORCE_CHANGE=0 to skip the "choose a new password" step on first login.
const bcrypt = require('bcryptjs');

function ensureAdmin(db, env = process.env, log = console.log) {
  const username = (env.ADMIN_USERNAME || '').trim();
  const password = env.ADMIN_PASSWORD || '';
  if (!username || !password) return { skipped: true };
  if (password.length < 8) { log('[admin] ADMIN_PASSWORD must be at least 8 characters - skipped.'); return { skipped: true }; }

  const fullName = (env.ADMIN_FULL_NAME || 'Principal / Admin').trim();
  const mustChange = env.ADMIN_FORCE_CHANGE === '0' ? 0 : 1;
  const row = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username);

  if (!row) {
    db.prepare(`INSERT INTO users (username, password_hash, role, full_name, is_active, must_change_password)
                VALUES (?, ?, 'admin', ?, 1, ?)`).run(username, bcrypt.hashSync(password, 10), fullName, mustChange);
    log(`[admin] Created admin account "${username}".`);
    return { created: true };
  }
  if (row.role !== 'admin') {
    log(`[admin] "${username}" exists but is a ${row.role}, not an admin. Left unchanged.`);
    return { conflict: true };
  }
  const changes = [];
  if (!row.is_active) { db.prepare(`UPDATE users SET is_active = 1, updated_at = datetime('now') WHERE id = ?`).run(row.id); changes.push('re-activated'); }
  if (env.ADMIN_RESET_PASSWORD === '1' && !bcrypt.compareSync(password, row.password_hash)) {
    db.prepare(`UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(bcrypt.hashSync(password, 10), mustChange, row.id);
    changes.push('password reset');
  }
  log(changes.length ? `[admin] "${username}": ${changes.join(', ')}.` : `[admin] "${username}" already exists - nothing changed.`);
  return { updated: changes };
}

module.exports = ensureAdmin;

if (require.main === module) {
  try { process.loadEnvFile(); } catch (_) {}
  const db = require('../db');
  if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
    console.error('Set ADMIN_USERNAME and ADMIN_PASSWORD first (see .env.example).');
    process.exit(1);
  }
  ensureAdmin(db);
  process.exit(0);
}
