const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // use promise-based mysql2

const app = express();
const PORT = 8080;

app.use(cors());
app.use(express.json());

// Create MySQL connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'testdb',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

app.get('/api/data', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM users');

    // Optional: simulate a delay before responding
    setTimeout(() => {
      console.log("Data fetched from the database");
      res.json({ message: "Data fetched from MySQL", data: rows });
    }, 1000);
  } catch (err) {
    console.error("Error fetching data from DB:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

module.exports = app;
