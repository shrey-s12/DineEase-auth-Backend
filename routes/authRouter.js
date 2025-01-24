const express = require('express');
const router = express.Router();
const { Register, Login, Token, Logout } = require('../controllers/authControllers');

router.post("/register", Register);
router.post("/login", Login);
router.post("/token", Token);
router.post("/logout", Logout);

module.exports = router;