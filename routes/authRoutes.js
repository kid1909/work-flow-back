const express = require('express');
const router = express.Router();

const { authenticateUser } = require("../middleware/authentication");

const {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
} = require("../controllers/authController");

router.post("/register", register);
router.post("/login", login);
router.post("/verify-email", verifyEmail);
router.delete("/logout", authenticateUser, logout);
router
  .post("/forgot-password", forgotPassword)
  .post("/reset-password", resetPassword);
  
  
module.exports = router;
