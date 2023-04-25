const { Router } = require("express");
const router = new Router();

const bcryptjs = require("bcryptjs");
const mongoose = require("mongoose");
const saltRounds = 10;

const User = require("../models/User.model");

const { userLoggedIn, userLoggedOut } = require("../middleware/route-guard.js");

//LOGIN
//Get login form
router.get("/login", userLoggedOut, (req, res, next) => {
  res.render("auth/login");
});

//Process form data

router.post("/login", userLoggedOut, (req, res, next) => {
  const { username, password } = req.body;
  if (username === "" || password === "") {
    res.status(400).render("auth/login", {
      errormessage:
        "All fields are mandatory. Please provide your username and password.",
    });
    return;
  }
  User.findOne({ username })
    .then((dbUser) => {
      if (!dbUser) {
        res.render("auth/login", {
          errormessage: "Username is not registered. Try with other username.",
        });
        return;
      }
      const samePassword = bcryptjs.compareSync(password, dbUser.passwordHash);
      console.log("SamePassword", samePassword);
      if (!samePassword) {
        res.render("auth/login", { errormessage: "Incorrect password." });
        return;
      }

      req.session.currentUser = dbUser;
      res.redirect("/main");
    })
    .catch((error) => next(error));
});

//USER PROFILE
router.get("/main", userLoggedIn, (req, res) => {
  res.render("users/main", { userInSession: req.session.currentUser });
});

//SIGNUP

//Get sign up form
router.get("/signup", userLoggedOut, (req, res, next) => {
  res.render("auth/signup");
});

//Get form data
router.post("/signup", userLoggedOut, (req, res, next) => {
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
      res.redirect("/userProfile");
    })
    .catch((error) => next(error));
});

//Show private page
router.get("/private", userLoggedIn, (req, res, next) => {
  res.render("users/private");
});

//LOGOUT
router.get("/auth/logout", userLoggedIn, (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

module.exports = router;
