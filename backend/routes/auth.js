const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Register user
router.post('/register', async (req, res) => {
    const { username, email, password, profilePic } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: "All fields are required." });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPass = await bcrypt.hash(password, salt);
        const user = new User({ username, email, password: hashedPass, profilePic });

        await user.save();
        res.status(200).json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error." });
    }
});

// Login user
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required." });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        const validated = await bcrypt.compare(password, user.password);
        if (!validated) {
            return res.status(401).json({ message: "Invalid email or password." });
        }

        const accessToken = jwt.sign({ id: user._id }, process.env.TOKEN_SECRET, { expiresIn: "15d" });
        const { password: pwd, ...others } = user._doc;
        res.status(200).json({ ...others, accessToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error." });
    }
});

// Logout user
router.get("/logout", (req, res) => {
    res.clearCookie('accessToken', { path: "/" });
    res.status(200).json({ message: "User logged out!" });
});

module.exports = router;
