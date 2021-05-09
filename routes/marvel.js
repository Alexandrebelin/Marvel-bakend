const express = require("express");
const router = express.Router();
const axios = require("axios");

router.get("/characters", async (req, res) => {
  try {
    const skip = req.query.skip;
    const limit = req.query.limit || 100;

    const response = await axios.get(
      `https://lereacteur-marvel-api.herokuapp.com/characters?apiKey=${process.env.API_KEY}&limit=${limit}&skip=${skip}`
    );
    res.json(response.data);
  } catch (error) {
    console.log("characters error", error.message);
    res.status(400).json({ message: error.message });
  }
});

router.get("/comics", async (req, res) => {
  try {
    const skip = req.query.skip;
    const limit = req.query.limit || 100;

    const response = await axios.get(
      `https://lereacteur-marvel-api.herokuapp.com/comics?apiKey=${process.env.API_KEY}&limit=${limit}&skip=${skip}`
    );
    res.json(response.data);
  } catch (error) {
    console.log("comics error", error.message);
    res.status(400).json({ message: error.message });
  }
});

router.get("/comics/:characterId", async (req, res) => {
  try {
    const characterId = req.params.characterId;

    const response = await axios.get(
      `https://lereacteur-marvel-api.herokuapp.com/comics/${characterId}?apiKey=${process.env.API_KEY}`
    );
    res.json(response.data);
  } catch (error) {
    console.log("characterId/comics", error.message);
    res.status(400).json({ message: error.message });
  }
});

router.post("/favorites", async (req, res) => {
  const fav = req.fields.fav;

  let favTab = [[], []];
  try {
    for (let i = 0; i < fav.length; i++) {
      if (i === 0) {
        for (let j = 0; j < fav[i].length; j++) {
          const response = await axios.get(
            `https://lereacteur-marvel-api.herokuapp.com/character/${fav[i][j]}?apiKey=${process.env.API_KEY}`
          );

          favTab[0].push(response.data);
        }
      } else {
        for (let j = 0; j < fav[i].length; j++) {
          const response = await axios.get(
            `https://lereacteur-marvel-api.herokuapp.com/comic/${fav[i][j]}?apiKey=${process.env.API_KEY}`
          );

          favTab[1].push(response.data);
        }
      }
    }
    res.json(favTab);
  } catch (error) {
    console.log("error in favorites", error.response.data);
    console.log("favorites", error.message);
  }
});

module.exports = router;
