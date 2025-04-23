require("dotenv").config();
const http = require("http");
const { neon } = require("@neondatabase/serverless");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');

const sql = neon(process.env.DATABASE_URL);
const saltRounds = 10;

async function parseJSONBody(req) {
  return new Promise((resolve) => {
    let body = [];
    req.on("data", (chunk) => body.push(chunk));
    req.on("end", () => resolve(JSON.parse(Buffer.concat(body).toString())));
  });
}

const requestHandler = async (req, res) => {
  try {
    // Set CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.url === "/api/signup" && req.method === "POST") {
      const { email, password } = await parseJSONBody(req);
      
      if (!email || !password) {
        res.writeHead(400, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Missing required fields" }));
      }

      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const userId = uuidv4();
      
      await sql`
        INSERT INTO users (id, email, password_hash)
        VALUES (${userId}, ${email}, ${hashedPassword})
      `;

      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "User created successfully" }));
    }
    else if (req.url === "/api/login" && req.method === "POST") {
      const { email, password } = await parseJSONBody(req);
      
      const [user] = await sql`
        SELECT * FROM users WHERE email = ${email}
      `;

      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Invalid credentials" }));
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      
      const JWT_SECRET = process.env.JWT_SECRET || 'your_secure_secret_here';
      
      // Add this in login handler after successful authentication
      const token = jwt.sign(
        { userId: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.end(JSON.stringify({ 
        message: "Login successful",
        token: token 
      }));
      
      // Add middleware to verify JWT
      function verifyToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
          return res.writeHead(401).end(JSON.stringify({ error: "Unauthorized" }));
        }
      
        jwt.verify(token, JWT_SECRET, (err, user) => {
          if (err) return res.writeHead(403).end(JSON.stringify({ error: "Invalid token" }));
          req.user = user;
          next();
        });
      }
      
      // Update CORS headers to allow Authorization
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }
    else {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Endpoint not found" }));
    }
  } catch (error) {
    console.error(error);
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Internal server error" }));
  }
};

// Add database initialization function
async function initializeDatabase() {
  // Create users table
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
  
  // Create index separately
  await sql`
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
  `;
}

// Modify server startup
http.createServer(requestHandler).listen(3000, async () => {
  await initializeDatabase();
  console.log("Server running at http://localhost:3000");
});