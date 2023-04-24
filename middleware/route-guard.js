//User is logged in
const userLoggedIn = (req, res, next) => {
  if (req.session.currentUser) {
    next();
  } else {
    res.redirect("/login");
  }
};

const userLoggedOut = (req, res, next) => {
  if (!req.session.currentUser) {
    next();
  } else {
    res.redirect("/main");
  }
};

module.exports = { userLoggedIn, userLoggedOut };
