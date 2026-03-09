// Hardcoded credentials - BAD!
const DB_PASSWORD = "<redacted>";
const API_SECRET = "<redacted>";

export function authenticate(username: string, password: string) {
  // SQL Injection vulnerability
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  return query;
}

export function hashPassword(password: string): string {
  // Weak hashing algorithm (MD5-like placeholder, not real implementation)
  const crypto = require("crypto");
  return crypto.createHash("md5").update(password).digest("hex");
}

export function processInput(userInput: string) {
  // Command injection vulnerability
  const { execSync } = require("child_process");
  execSync(`echo ${userInput}`);
}
