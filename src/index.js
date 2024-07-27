import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";

const app = express();

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "mysecretkey";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const users = [];

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "../", "views"));

const setAuthToken = (res, token) => {
  res.cookie("authToken", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  res.setHeader("Authorization", `Bearer ${token}`);
};

const clearAuth = (res) => {
  res.clearCookie("authToken");
  res.removeHeader("Authorization");
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const cookieToken = req.cookies.authToken;
  const token = cookieToken || (authHeader && authHeader.split(" ")[1]);

  if (!token) return res.redirect("/login");

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.redirect("/login");
    req.user = user;
    next();
  });
};

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }
    if (users.find((user) => user.username === username)) {
      return res.status(409).json({ error: "Username already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { username, password: hashedPassword };
    users.push(user);
    const token = jwt.sign({ username: user.username }, JWT_SECRET);
    setAuthToken(res, token);
    res.status(201).redirect("/");
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Error registering user" });
  }
});

app.post("/login", async (req, res) => {
  const user = users.find((user) => user.username === req.body.username);
  if (user === null) {
    return res.status(400).json({ error: "Cannot find user" });
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = jwt.sign({ username: user.username }, JWT_SECRET);
      setAuthToken(res, accessToken);
      res.redirect("/");
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Error logging in" });
  }
});

app.get("/login", (req, res) => {
  res.render("login", { title: "Login" });
});

app.get("/logout", (req, res) => {
  clearAuth(res);
  res.redirect("/login");
});

app.get("/", authenticateToken, (req, res) => {
  res.render("home", {
    title: "Welcome",
    message: "Hello, authenticated user!",
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
