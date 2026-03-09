// vulnerable-js.js

const http = require("http");
const url = require("url");
const childProcess = require("child_process");
const mysql = require("mysql");

// Hardcoded secret
const DB_PASSWORD = "SuperSecretPassword123!";

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: DB_PASSWORD,
  database: "app_db",
});

http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const q = parsed.query.q || "";

  // SQL Injection
  const sql = "SELECT * FROM users WHERE username = '" + q + "'";
  connection.query(sql, (err, rows) => {
    if (err) {
      res.writeHead(500);
      return res.end("Error");
    }

    // Reflected XSS
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<h1>Hello " + q + "</h1>");
  });

  // Command injection
  if (parsed.query.cmd) {
    const cmd = parsed.query.cmd;
    childProcess.exec("ls " + cmd, (err, stdout, stderr) => {
      console.log(stdout || stderr);
    });
  }

  // Dangerous eval
  if (parsed.query.code) {
    const userCode = parsed.query.code;
    eval(userCode); // bad: executes arbitrary JS
  }
}).listen(3000);

