const mysql = require('mysql2/promise');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
function databaseConfig(env = process.env) {
  const database = env.DB_NAME || 'atbm_internal';
  if (!/^[a-zA-Z0-9_]{1,64}$/.test(database)) throw new Error('DB_NAME chỉ được chứa chữ, số và dấu gạch dưới.');
  return { host: env.DB_HOST || '127.0.0.1', port: Number(env.DB_PORT || 3307),
    user: env.DB_USER || 'root', password: env.DB_PASSWORD || '', database,
    charset: 'utf8mb4', timezone: 'Z', connectTimeout: 5000, connectionLimit: 5,
    supportBigNumbers: true, bigNumberStrings: false, multipleStatements: false };
}
class Store {
  constructor(connection, transactional = false) { this.connection = connection; this.transactional = transactional; }
  static async open(config, { createDatabase = false, initialize = true } = {}) {
    if (createDatabase) {
      const admin = await mysql.createConnection({ ...config, database: undefined });
      try { await admin.query(`CREATE DATABASE IF NOT EXISTS \`${config.database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`); }
      finally { await admin.end(); }
    }
    const pool = mysql.createPool(config), store = new Store(pool);
    try {
      if (!initialize) {
        await store.get("SELECT value FROM settings WHERE name='audit_head'");
        return store;
      }
      const schema = fs.readFileSync(path.join(__dirname, 'database/schema.sql'), 'utf8');
      for (const statement of schema.split(/;\s*(?:\r?\n|$)/).map(s => s.trim()).filter(Boolean)) await pool.query(statement);
      // Nâng cấp database cũ: loại bỏ cấu hình xác thực hai bước đã ngừng sử dụng.
      for (const [table, columns] of Object.entries({ users: ['mfa_secret', 'mfa_step'], sessions: ['pending_mfa'] })) {
        const existing = (await store.all('SHOW COLUMNS FROM ' + table)).map(column => column.Field);
        for (const column of columns) if (existing.includes(column)) await pool.query(`ALTER TABLE ${table} DROP COLUMN ${column}`);
      }
      for (const [name, event] of [['audit_no_update', 'UPDATE'], ['audit_no_delete', 'DELETE']]) {
        const exists = await store.get('SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=? AND TRIGGER_NAME=?', config.database, name);
        if (!exists) await pool.query(`CREATE TRIGGER ${name} BEFORE ${event} ON audit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit is append-only'`);
      }
      return store;
    } catch (error) { await pool.end(); throw error; }
  }
  async get(sql, ...args) { return (await this.all(sql, ...args))[0]; }
  async all(sql, ...args) { return (await this.connection.execute(sql, args))[0]; }
  async run(sql, ...args) { return (await this.connection.execute(sql, args))[0]; }
  async transaction(fn) {
    if (this.transactional) return fn(this);
    const conn = await this.connection.getConnection();
    try {
      await conn.beginTransaction();
      const result = await fn(new Store(conn, true));
      await conn.commit(); return result;
    } catch (error) { await conn.rollback(); throw error; }
    finally { conn.release(); }
  }
  async audit(actor, action, documentId = null, result = 'ok', ip = '') {
    return this.transaction(async tx => {
      const previous = (await tx.get("SELECT value FROM settings WHERE name='audit_head' FOR UPDATE")).value;
      const entry = [new Date().toISOString(), actor || 'anonymous', action, documentId, result, ip, previous];
      const hash = crypto.createHash('sha256').update(JSON.stringify(entry)).digest('hex');
      await tx.run('INSERT INTO audit(time,actor,action,document_id,result,ip,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)', ...entry, hash);
      await tx.run("UPDATE settings SET value=? WHERE name='audit_head'", hash);
    });
  }
  async verifyAudit() {
    let previous = '';
    for (const row of await this.all('SELECT * FROM audit ORDER BY seq')) {
      const hash = crypto.createHash('sha256').update(JSON.stringify([
        row.time, row.actor, row.action, row.document_id, row.result, row.ip, row.prev_hash
      ])).digest('hex');
      if (row.prev_hash !== previous || row.hash !== hash) return false;
      previous = row.hash;
    }
    return previous === (await this.get("SELECT value FROM settings WHERE name='audit_head'")).value;
  }
  async close() { await this.connection.end(); }
}
module.exports = { Store, databaseConfig };
