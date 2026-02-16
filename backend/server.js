const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./db");

const app = express();

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
    res.send("Server Running");
});

// REGISTER ROUTE
app.post("/register", async (req, res) => {
    const { name, email, password, role } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)";

        db.query(sql, [name, email, hashedPassword, role || "user"], (err, result) => {
            if (err) {
                return res.status(400).json({ message: "User already exists" });
            }
            res.json({ message: "User registered successfully" });
        });

    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

// LOGIN ROUTE
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    const sql = "SELECT * FROM users WHERE email = ?";

    db.query(sql, [email], async (err, result) => {
        if (err || result.length === 0) {
            return res.status(400).json({ message: "Invalid Email or Password" });
        }

        const user = result[0];

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: "Invalid Email or Password" });
        }

        res.json({
            message: "Login Successful",
            role: user.role,
            name: user.name
        });
    });
});

app.listen(5000, () => {
    console.log("Server running on port 5000");
});
