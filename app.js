const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs"); // or bcrypt, depending on your installation
const cors = require("cors");

// Initialize Express app
const app = express();
app.use(cors());
app.use(express.json()); // To parse JSON bodies

// MongoDB connection URI
const uri = "mongodb://localhost:27017/jahanzaib"; // Replace with your MongoDB URI
mongoose.connect(uri)
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit the process if MongoDB connection fails
  });

// Define the User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

// Create User model
const User = mongoose.model("User", userSchema);

// Utility function for error handling
const handleError = (res, message, status = 500) => {
  console.error(message);
  res.status(status).json({ error: message });
};

// Sign-Up Route
app.post("/signup", async (req, res) => {
  const { username, password, email } = req.body;

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) return handleError(res, "Username or email already exists", 400);

    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ username, password: hashedPassword, email }).save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    handleError(res, 'Sign-up error');
  }
});
app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return handleError(res, "User not found", 404);

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return handleError(res, "Incorrect password", 400);

    // Exclude the password from the response
    const { password: _, ...userDetails } = user.toObject();

    res.json({
      message: "Sign-in successful",
      user: userDetails
    });
  } catch (err) {
    handleError(res, 'Sign-in error: ' + err.message);
  }
});

// Update Password Route
app.post("/update-password", async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) return handleError(res, "User not found", 400);

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return handleError(res, "Incorrect old password", 400);

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    handleError(res, 'Password update error');
  }
});

// Get User Route
app.get("/user", async (req, res) => {
  const { username, email } = req.query;

  try {
    if (!username && !email) return handleError(res, "Username or email required", 400);

    const query = username ? { username } : { email };
    const user = await User.findOne(query);
    if (!user) return handleError(res, "User not found", 404);

    res.json(user);
  } catch (err) {
    handleError(res, 'User retrieval error');
  }
});

// Start the server
app.listen(5000, () => {
  console.log("Server is running on port 5000");
});
