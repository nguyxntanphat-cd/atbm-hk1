-- MySQL 8 / MariaDB 10.4 (XAMPP), utf8mb4 giữ đầy đủ tiếng Việt.
CREATE TABLE IF NOT EXISTS settings (
  name VARCHAR(64) PRIMARY KEY, value TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS users (
  username VARCHAR(64) COLLATE utf8mb4_bin PRIMARY KEY,
  name VARCHAR(100) NOT NULL, role ENUM('employee','boss','admin') NOT NULL,
  salt CHAR(32) NOT NULL, hash CHAR(128) NOT NULL, enabled TINYINT NOT NULL DEFAULT 1,
  must_change TINYINT NOT NULL DEFAULT 0, quota BIGINT UNSIGNED NOT NULL DEFAULT 104857600,
  created_at VARCHAR(24) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS key_records (
  key_id CHAR(64) PRIMARY KEY, username VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
  directory VARCHAR(255) NOT NULL UNIQUE, active TINYINT NOT NULL DEFAULT 1,
  active_owner VARCHAR(64) COLLATE utf8mb4_bin GENERATED ALWAYS AS (IF(active=1,username,NULL)) STORED,
  created_at VARCHAR(24) NOT NULL, UNIQUE KEY active_key(active_owner),
  FOREIGN KEY (username) REFERENCES users(username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS documents (
  id VARCHAR(40) PRIMARY KEY, sender_username VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
  recipient_username VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
  sender VARCHAR(100) NOT NULL, title VARCHAR(200) NOT NULL, category VARCHAR(100) NOT NULL,
  filename VARCHAR(255) NOT NULL, size BIGINT UNSIGNED NOT NULL, stored_bytes BIGINT UNSIGNED NOT NULL,
  key_id CHAR(64) NOT NULL, version INT NOT NULL, time VARCHAR(24) NOT NULL,
  opened_at VARCHAR(24), revoked_at VARCHAR(24), expires_at VARCHAR(24), previous_id VARCHAR(40),
  scan_status VARCHAR(32) NOT NULL DEFAULT 'not-scanned', sha256 CHAR(64) NOT NULL,
  INDEX inbox(recipient_username,time), INDEX outbox(sender_username,time),
  FOREIGN KEY (recipient_username) REFERENCES users(username),
  FOREIGN KEY (key_id) REFERENCES key_records(key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS sessions (
  token_hash CHAR(64) PRIMARY KEY, username VARCHAR(64) COLLATE utf8mb4_bin NOT NULL,
  expires_at BIGINT NOT NULL,
  INDEX session_expiry(expires_at), FOREIGN KEY (username) REFERENCES users(username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE TABLE IF NOT EXISTS audit (
  seq BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, time VARCHAR(24) NOT NULL,
  actor VARCHAR(64) NOT NULL, action VARCHAR(64) NOT NULL, document_id VARCHAR(40),
  result VARCHAR(32) NOT NULL, ip VARCHAR(64) NOT NULL, prev_hash VARCHAR(64) NOT NULL,
  hash CHAR(64) NOT NULL, INDEX audit_time(time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
INSERT IGNORE INTO settings(name,value) VALUES('audit_head','');
