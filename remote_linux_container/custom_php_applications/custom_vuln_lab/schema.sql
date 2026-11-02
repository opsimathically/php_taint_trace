CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'user'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS accounts (
  user_id INT PRIMARY KEY,
  balance DECIMAL(12,2) NOT NULL DEFAULT 0,
  CONSTRAINT fk_accounts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  owner_user_id INT NOT NULL,
  item_name VARCHAR(255) NOT NULL,
  total_amount DECIMAL(12,2) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'new',
  CONSTRAINT fk_orders_user FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS comments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL DEFAULT 0,
  body TEXT NOT NULL,
  created_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS transfer_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  from_user_id INT NOT NULL,
  to_user_id INT NOT NULL,
  amount DECIMAL(12,2) NOT NULL,
  created_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO users (id, username, password, email, role) VALUES
  (1, 'alice', 'synthetic-lab-alice-only', 'alice@example.test', 'user'),
  (2, 'bob', 'synthetic-lab-bob-only', 'bob@example.test', 'user'),
  (3, 'admin', 'synthetic-lab-admin-only', 'admin@example.test', 'admin');

INSERT IGNORE INTO accounts (user_id, balance) VALUES
  (1, 1000.00),
  (2, 750.00),
  (3, 5000.00);

INSERT IGNORE INTO orders (id, owner_user_id, item_name, total_amount, status) VALUES
  (1, 1, 'Alice Order Alpha', 99.99, 'paid'),
  (2, 2, 'Bob Order Beta', 42.50, 'pending'),
  (3, 3, 'Admin Order Gamma', 250.00, 'shipped');

INSERT IGNORE INTO comments (id, user_id, body, created_at) VALUES
  (1, 1, 'Welcome to custom_vuln_lab comments.', NOW()),
  (2, 2, 'Stored XSS test surface is active.', NOW());
