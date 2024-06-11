const express = require("express");
const uuid = require("uuid")
const path = require("path");
const cors = require("cors")
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");

const app = express();
app.use(cors())

const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');

const dbPath = path.join(__dirname, "bd.db");

const Port=process.env.PORT || 3103

let db = null;

app.use(express.json());

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(Port, () => {
      console.log(`Server Running at http://localhost:${Port}/`);
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};
initializeDBAndServer();

app.get('/', async (req, res) => {
  res.send("Bindassdeal Assignment Backend")
});


app.post("/api/user/", async (request, response) => {
    try {
      const { username, password } = request.body;
  
      if (!username || !password) {
        return response.status(400).json({ error: "Missing required fields." });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10); 
  
      const insertUserQuery = `
        INSERT INTO users (id, username, password)
        VALUES (?, ?, ?)
      `;
  
      const userId = uuid.v4();
  
      await db.run(insertUserQuery, [userId, username, hashedPassword]);
  
      const token = jwt.sign({ id: userId, username }, "secret-key", {
        expiresIn: "1h",
      });
  
      response.status(201).json({
        token,
      });
    } catch (error) {
      console.error("Error adding user:", error.message);
      response.status(500).json({ error: "Internal Server Error" });
    }
  });


  app.post("/api/signin/", async (request, response) => {
    try {
      const { username, password } = request.body;
  
      if (!username || !password) {
        return response.status(400).json({ error: "Missing required fields." });
      }
  
      const selectUserQuery = `
        SELECT id, username, password
        FROM users
        WHERE username = ?
      `;
  
      const user = await db.get(selectUserQuery, [username]);
  
      if (!user) {
        return response.status(401).json({ error: "Invalid username or password." });
      }
  
      const passwordMatch = await bcrypt.compare(password, user.password);
  
      if (!passwordMatch) {
        return response.status(401).json({ error: "Invalid username or password." });
      }
  
      const token = jwt.sign({ id: user.id, username: user.username }, "secret-key", {
        expiresIn: "1h",
      });
  
      response.status(200).json({
        token,
      });
    } catch (error) {
      console.error("Error signing in:", error.message);
      response.status(500).json({ error: "Internal Server Error" });
    }
  });