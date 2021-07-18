const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const ejsMate = require("ejs-mate");
require("dotenv").config();
const session = require("express-session");
const flash = require("connect-flash");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const User = require("./models/user");
const catchAsync = require("./utils/catchAsync");
const ExpressError = require("./utils/ExpressError");
const Joi = require("joi");
const { currentUser } = require("./LoginMiddleware");
const dbUrl = process.env.DB_URL;
const MongoStore = require("connect-mongo");
const helmet = require("helmet");

const app = express();

mongoose.connect(dbUrl, {
  useNewUrlParser: true,
  useCreateIndex: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", () => {
  console.log("Database connected");
});

app.engine("ejs", ejsMate);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

//To get data form form
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const secret = process.env.SECRET || "badsecret";

const store = MongoStore.create({
  mongoUrl: dbUrl,
  secret,
  touchAfter: 24 * 60 * 60,
});

store.on("error", function (e) {
  console.log("SESSION STORE ERROR", e);
});

const sessionConfig = {
  store,
  secret,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
};

app.use(session(sessionConfig));
app.use(flash());
app.use(helmet({ contentSecurityPolicy: false }));

app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(User.authenticate()));

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.use((req, res, next) => {
  console.log(req.session);
  res.locals.currentUser = req.user;
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  next();
});

app.get("/", (req, res) => {
  res.render("./home.ejs");
});

app.get("/login", (req, res) => {
  res.render("./users/login.ejs");
});

app.get("/register", (req, res) => {
  res.render("./users/register.ejs");
  const { username = "unknown" } = req.query;
  req.session.username = username;
});

app.post(
  "/register",
  catchAsync(async (req, res, next) => {
    try {
      const schemaUser = Joi.object({
        email: Joi.string()
          .email({ minDomainSegments: 2, tlds: { allow: ["com", "net"] } })
          .required()
          .messages({
            "string.email": "Please fill a valid email address",
          })
          .trim(),
        username: Joi.string()
          .min(5)
          .max(25)
          .required()
          .messages({
            "string.min": "Username: minimum 5 character required",
            "string.max": "Username: maximum 25 characters allowed",
          })
          .trim(),
        password: Joi.string()
          .min(8)
          .max(32)
          .regex(RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{8,})"))
          .required()
          .messages({
            "string.min": "Password: minimum 8 character required",
            "string.max": "Password: maximum 32 characters allowed",
            "string.pattern.base":
              "Password must contain atleast one Upper and Lower case letter with one Number",
          }),
        password_confirmation: Joi.any()
          .equal(Joi.ref("password"))
          .required()
          .label("Confirm password")
          .messages({ "any.only": "Password does not match" }),
      });
      const { error } = schemaUser.validate(req.body);
      console.log(req.body);
      if (error) {
        const msg = error.details.map((el) => el.message).join(",");
        throw new ExpressError(msg, 400);
      }
      //Pulling stuff out of req.body
      const { email, username, password } = req.body;
      //creating a new user object
      const user = new User({ email, username });
      //Storing hashed password on our new user
      const registeredUser = await User.register(user, password);
      //req.login = automatically login the newly registered user
      req.login(registeredUser, (err) => {
        if (err) {
          return next(err);
        }
        req.flash("success", "Welcome");
        res.redirect("/gallery");
      });
    } catch (e) {
      req.flash("error", e.message);
      res.redirect("/register");
    }
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    failureFlash: true,
    failureRedirect: "/login",
  }),
  (req, res) => {
    req.flash("success", "Welcome to Gallery Timeless!");
    res.redirect("/gallery");
  }
);

app.get("/logout", (req, res) => {
  req.logout();
  req.flash("success", "Goodbye!");
  res.redirect("/login");
});

app.get("/gallery", currentUser, (req, res) => {
  res.render("./gallery.ejs", {
    title: "Gallery",
  });
});

app.all("*", (req, res, next) => {
  next(new ExpressError("Page Not Found", 404));
});

app.use((err, req, res, next) => {
  const { statusCode = 500 } = err;
  if (!err.message) err.message = "Oh No, Something Went Wrong!";
  res.status(statusCode).render("error", { err });
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`LISTENING ON PORT ${port}`);
});

// Script:
// "deploy": "nodemon app.js"
