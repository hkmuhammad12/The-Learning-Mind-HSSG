const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// DATA_DIR lets a host keep the database on a persistent disk (e.g. /var/data).
const DATA_DIR = process.env.DATA_DIR || __dirname;
fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'school.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Run schema on every boot - all statements use CREATE TABLE IF NOT EXISTS,
// so this is safe to re-run and never touches existing data.
const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');
db.exec(schema);

module.exports = db;
