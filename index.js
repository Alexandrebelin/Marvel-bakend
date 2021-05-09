const express = require("express");
const mongoose = require("mongoose");
const formidableMiddleware = require("express-formidable");
var cors = require("cors");

const app = express();
require("dotenv").config();

app.use(formidableMiddleware());
app.use(cors());

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

const marvelRoutes = require("./routes/marvel");
const userRoutes = require("./routes/user");
const searchRoutes = require("./routes/search");
app.use(marvelRoutes);
app.use(userRoutes);
app.use(searchRoutes);

app.get("/", (req, res) => {
  res.json({ message: "Welcome on Marvel API" });
});

app.all("*", (req, res) => {
  res.json({ message: "this page does not exist" });
});

app.listen(process.env.PORT, () =>
  console.log(`Server started on port ${process.env.PORT}`)
);
