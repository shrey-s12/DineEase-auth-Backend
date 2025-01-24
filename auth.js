const dotenv = require('dotenv');
dotenv.config();

const express = require('express');
const cors = require('cors');
require('../config/connection');
const AuthRoutes = require('./routes/authRouter');

const AUTH_PORT = process.env.AUTH_PORT; // 5001
const app = express();

app.use(express.json());
app.use(cors());

app.use("/auth", AuthRoutes);

app.listen(AUTH_PORT, () => {
    console.log(`Auth Server running on port ${AUTH_PORT}`);
});