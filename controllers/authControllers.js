const dotenv = require('dotenv');
dotenv.config();

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const USER = require('../model/userModel')
const SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET;

const sessions = new Map();
function generateAccessToken(data) {
    return jwt.sign(data, SECRET, { expiresIn: '1m' });
};

const Register = async (req, res) => {
    try {
        const { name, email, password, role = "Customer" } = req.body;
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(password, salt);

        const existingUser = await USER.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        const user = new USER({
            name,
            email,
            password: hashedPassword,
            role
        });

        const savedUser = await user.save();
        res.status(200).json({ savedUser, message: "User registered successfully" });
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
};

const Login = async (req, res) => {
    const { email, password } = req.body;
    const user = await USER.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: "User not found" });
    }
    try {
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Incorrect Password' });
        }
    } catch (err) {
        res.status(400).json({ message: err.message });
    }

    const userInfo = {
        image: user.image,
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
    };
    const token_data = { user: userInfo };

    const refresh_token = jwt.sign(token_data, REFRESH_SECRET);
    sessions.set(refresh_token, user._id);

    const token = generateAccessToken(token_data);

    return res.json({ token, refresh_token, user: userInfo });
};

const Token = async (req, res) => {
    const refresh_token = req.body.token;
    if (!refresh_token) return res.status(400).json({ message: "Refresh token missing!" });

    if (!sessions.has(refresh_token)) {
        return res.status(401).json({ message: "Invalid refresh token!" });
    }

    jwt.verify(refresh_token, REFRESH_SECRET, function (err, token_data) {
        if (err) {
            console.error("JWT verification error:", err);
            return res.status(403).json({ message: "Forbidden", error: err.message });
        }

        const newToken = generateAccessToken({ user: token_data.user });
        return res.json({ token: newToken });
    });
};


const Logout = async (req, res) => {
    const refreshToken = req.body.token;
    if (!sessions.has(refreshToken)) {
        return res.status(200).json({ message: "No op" });
    }
    sessions.delete(refreshToken);
    return res.status(204).json({ message: "Logged out" });
};

module.exports = {
    Register,
    Login,
    Token,
    Logout,
}