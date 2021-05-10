const express = require("express");
const router = express.Router();

const uid2 = require("uid2");
const SHA256 = require("crypto-js/sha256");
const encBase64 = require("crypto-js/enc-base64");

// MODELS IMPORT
const User = require("../models/User");

// SIGN UP
router.post("/user/sign-up", async (req, res) => {
  console.log(req.fields);
  try {
    const user = await User.findOne({ email: req.fields.email });

    if (!user) {
      if (req.fields.email && req.fields.username && req.fields.password) {
        const salt = uid2(64);
        const hash = SHA256(req.fields.password + salt).toString(encBase64);
        const token = uid2(64);

        const newUser = new User({
          email: req.fields.email,

          username: req.fields.username,

          token: token,
          hash: hash,
          salt: salt,
        });
        const returnUser = (({ email, username, token, hash, salt, _id }) => ({
          email,
          username,
          token,
          _id,
        }))(newUser);
        await newUser.save();
        res.status(200).json(returnUser);
      } else {
        res.status(404).json({ error: "Missing parameters" });
      }
    } else {
      res.json({ message: "Email already exists" });
    }
  } catch (error) {
    res.json({ message: error.message });
  }
});

// LOG IN
router.post("/user/log-in", async (req, res) => {
  try {
    console.log(req.fields);
    const user = await User.findOne({ email: req.fields.email });
    if (user) {
      if (
        SHA256(req.fields.password + user.salt).toString(encBase64) ===
        user.hash
      ) {
        res.json({
          _id: user._id,
          token: user.token,
          username: user.username,
        });
      } else {
        res.status(401).json({ error: "Unauthorized" });
      }
    } else {
      res.json({ message: "User not found" });
    }
  } catch (error) {
    res.json({ message: error.message });
  }
});

module.exports = router;
