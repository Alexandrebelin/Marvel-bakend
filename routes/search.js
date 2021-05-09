const express = require("express");
const router = express.Router();
const axios = require("axios");

router.get("/search-characters", async (req, res) => {
  try {
    const name = req.query.name;
    const limit = req.query.limit || 100;
    const skip = req.query.skip;

    const response = await axios.get(
      `https://lereacteur-marvel-api.herokuapp.com/characters?apiKey=${process.env.API_KEY}&limit=${limit}&skip=${skip}&name=${name}`
    );

    res.json(response.data);
  } catch (error) {
    console.log("char search error", error.message);
    res.status(400).json({ message: error.message });
  }
});

router.get("/search-comics", async (req, res) => {
  try {
    const title = req.query.title;
    const limit = req.query.limit || 100;
    const skip = req.query.skip;

    const response = await axios.get(
      `https://lereacteur-marvel-api.herokuapp.com/comics?apiKey=${process.env.API_KEY}&limit=${limit}&skip=${skip}&title=${title}`
    );

    res.json(response.data);
  } catch (error) {
    console.log("comics search error", error.message);
    res.status(400).json({ message: error.message });
  }
});

module.exports = router;
