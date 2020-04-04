CREATE DATABASE vulnspring;
USE vulnspring;
CREATE TABLE users (username VARCHAR(20), password VARCHAR(20), name VARCHAR(50), accountnumber VARCHAR(20), balance FLOAT);
INSERT INTO users values("bob", "secretPassword", "Bob", "12345678", 2232.45);
INSERT INTO users values("alice", "aliceAlice", "Alice", "12345679", 9412.45);

