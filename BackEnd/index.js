require("dotenv").config(); // ✅ Load environment variables first
require("./passport");

const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const authModel = require("./Models/Model");
const bcrypt = require("bcrypt");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const TodoRoutes = require("./Routes/TodoRoutes");
const NoteRoutes = require("./Routes/NoteRoutes");
const TaskRoutes = require("./Routes/TaskRoutes");

const PORT = 8080;
const MONGO_URL = process.env.MONGO_URL;
const FRONTEND_DOMAIN = process.env.FRONTEND_DOMAIN;

// ✅ MongoDB Connection
mongoose.connect(MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch((err) => console.error("MongoDB connection error:", err));

const app = express();

app.use([
  cors({
    origin: FRONTEND_DOMAIN,
    credentials: true,
    methods: ["GET", "PUT", "PATCH", "POST", "DELETE"],
  }),
  express.json(),
  express.urlencoded({ extended: true }),
]);

// ✅ MongoDB Session Store
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    store: MongoStore.create({
      mongoUrl: MONGO_URL,
      collectionName: "sessions",
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// ✅ Passport middleware
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.json("Hello from backend!");
});

// ✅ Registration route
app.post("/register", async (req, res) => {
  const { userName, email, password } = req.body;
  try {
    const user = await authModel.findOne({ email });
    if (user) return res.json("Already Registered");

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new authModel({ userName, email, password: hashedPassword });
    const savedUser = await newUser.save();
    res.json(savedUser);
  } catch (err) {
    res.status(400).send(err);
  }
});

// ✅ Local Login
app.post(
  "/login",
  passport.authenticate("local", { failureRedirect: FRONTEND_DOMAIN }),
  (req, res) => {
    res.json({ success: "Successfully logged in" });
  }
);

// ✅ Logout
app.get("/logout", (req, res) => {
  req.logOut((err) => {
    if (err) return res.send(err);
    res.json({ success: "Logged out" });
  });
});

// ✅ Google OAuth
app.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: FRONTEND_DOMAIN,
    successRedirect: `${FRONTEND_DOMAIN}/Home`,
  })
);

// ✅ Facebook OAuth
app.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));
app.get(
  "/facebook/callback",
  passport.authenticate("facebook", {
    failureRedirect: FRONTEND_DOMAIN,
    successRedirect: `${FRONTEND_DOMAIN}/Home`,
  })
);

// ✅ Get User
app.get("/getUser", (req, res) => {
  if (req.user) res.json(req.user);
  else res.status(401).json({ error: "Not authenticated" });
});

// ✅ Forgot password
app.post("/forgotpass", async (req, res) => {
  const { email } = req.body;
  const user = await authModel.findOne({ email });
  if (!user) return res.send({ Status: "Enter a valid email" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: "1d" });
  const resetURL = `${FRONTEND_DOMAIN}/ResetPass/${user._id}/${token}`;

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "jhonmoorthi85131@gmail.com",
      pass: "klxb xvje ygnr qvbo",
    },
  });

  const mailOptions = {
    from: "jhonmoorthi85131@gmail.com",
    to: email,
    subject: "Forgot password for Task Manager",
    text: resetURL,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) return res.send({ Status: error });
    res.send({ Status: "success" });
  });
});

// ✅ Reset Password
app.post("/resetPassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { newPassword } = req.body;

  jwt.verify(token, process.env.JWT_SECRET_KEY, async (err) => {
    if (err) return res.send({ Status: "Try again after a few minutes" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await authModel.findByIdAndUpdate(id, { password: hashedPassword });
    res.send({ Status: "success" });
  });
});

// ✅ Protected Routes
const authenticator = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Login Required" });
  }
  next();
};

app.use("/todo", authenticator, TodoRoutes);
app.use("/note", authenticator, NoteRoutes);
app.use("/task", authenticator, TaskRoutes);

// ✅ Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
