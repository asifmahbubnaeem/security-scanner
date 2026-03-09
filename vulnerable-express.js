// vulnerable-express.js

const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());

// Hardcoded JWT secret
const SECRET = "hardcoded-jwt-secret";

app.post("/login", (req, res) => {
  const { username } = req.body;

  // No password check, weak auth
  const token = jwt.sign({ username, admin: req.body.admin }, SECRET, {
    expiresIn: "7d",
  });

  res.json({ token });
});

app.get("/admin", (req, res) => {
  const token = req.query.token;

  // No signature verification error handling / algorithm check
  const decoded = jwt.verify(token, SECRET);

  if (decoded.admin) {
    res.send("Welcome admin");
  } else {
    res.status(403).send("Forbidden");
  }
});

app.listen(4000);

