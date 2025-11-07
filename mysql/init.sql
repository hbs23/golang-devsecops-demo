CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL,
  password VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  number VARCHAR(32) NOT NULL,
  balance DOUBLE NOT NULL DEFAULT 0, -- float/double for money (intentionally bad)
  INDEX(user_id)
);

CREATE TABLE IF NOT EXISTS transactions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  from_account_id INT NOT NULL,
  to_account_id INT NOT NULL,
  amount DOUBLE NOT NULL,
  created_at DATETIME NOT NULL
);

INSERT INTO users (username, password) VALUES ('admin','password123'),('alice','alice123'),('bob','bob123');
INSERT INTO accounts (user_id, number, balance) VALUES (1,'100-001',1000000.00),(2,'100-002',500000.00),(3,'100-003',750000.00);
