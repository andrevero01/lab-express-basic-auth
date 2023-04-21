const { Router } = require("express");
const router = new Router();

const bcryptjs = require("bcryptjs");
const saltRounds = 10;

const User = require("../models/User.model");

//Render sign up form

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

//Get form data
router.post("/signup", (req, res, next) => {
  const { username, password } = req.body;
  if (username === "" || password === "") {
    res.status(400).render("auth/signup", {
      errormessage:
        "All fields are mandatory. Please provide your username and password.",
    });
    return;
  }
  User.findOne({ username }).then((existingUser) => {
    if (existingUser) {
      res.status(400).render("auth/signup", {
        errormessage:
          "This username already exists. Please provide a new username.",
      });
      return;
    }
  });

  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({ username, passwordHash: hashedPassword });
    })
    .then(() => {
      res.render("index");
    })
    .catch((error) => next(error));
});

module.exports = router;
