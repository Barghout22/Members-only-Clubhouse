/////// app.js
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const Schema = mongoose.Schema;
const asyncHandler = require("express-async-handler");
const { body, validationResult } = require("express-validator");
require("dotenv").config();

const port=process.env.PORT||3000;
const mongoDb = process.env.MONGODB_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    firstname: { type: String, required: true },
    lastname: { type: String, required: true },
    username: { type: String, required: true },
    password: { type: String, required: true },
    membership_status: { type: String, required: true },
  })
);
const Post = mongoose.model(
  "Post",
  new Schema({
    title: { type: String, required: true },
    post_body: { type: String, required: true },
    timepstamp: { type: Date, required: true },
    postingUser: { type: Schema.Types.ObjectId, ref: "User", required: true },
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");
app.use(express.static(__dirname + "/public"));

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user);
        } else {
          // passwords do not match!
          return done(null, false, { message: "Incorrect password" });
        }
      });
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", async (req, res) => {
  const posts = await Post.find()
    .sort({ timepstamp: -1 })
    .populate("postingUser")
    .exec();
  res.render("index", { user: req.user, posts: posts });
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.post("/sign-up", [
  body("firstname", "first name must not be empty")
    .trim()
    .isLength({ min: 1 })
    .escape(),
  body("lastname", "last name must not be empty")
    .trim()
    .isLength({ min: 1 })
    .escape(),
  body("username", "username must not be empty")
    .trim()
    .isLength({ min: 1 })
    .escape(),
  body("password", "password must not be empty")
    .trim()
    .isLength({ min: 1 })
    .escape(),
  asyncHandler(async (req, res, next) => {
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        console.log(err);
        return;
      } else {
        const user = new User({
          firstname: req.body.firstname,
          lastname: req.body.lastname,
          username: req.body.username,
          password: hashedPassword,
          membership_status: "regular",
        });
        const result = await user.save();
        res.redirect("/");
      }
    });
  }),
]);
app.get("/log-in", (req, res) => res.render("log-in-form"));
app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);
app.get("/log-out", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});
app.post("/new-post", [
  body("title", "title must not be empty").trim().isLength({ min: 1 }).escape(),
  body("post_body", "post body must not be empty")
    .trim()
    .isLength({ min: 1 })
    .escape(),
  asyncHandler(async (req, res, next) => {
    const post = new Post({
      title: req.body.title,
      post_body: req.body.postText,
      timepstamp: Date.now(),
      postingUser: req.user,
    });
    const result = await post.save();
    res.redirect("/");
  }),
]);
app.get("/upgrade-status", (req, res) =>
  res.render("upgrade-status-form", { message: "" })
);
app.post("/upgrade-status", async (req, res) => {
  if (req.body.adminPwd === process.env.UPGRADE_PASS) {
    await User.findByIdAndUpdate(
      req.user._id,
      {
        membership_status: "admin",
      },
      {}
    );
    res.render("upgrade-status-form", {
      message: "congratulations! you have been promoted to admin!",
    });
  } else {
    res.render("upgrade-status-form", { message: "wrong password" });
  }
});

app.listen(port,"0.0.0.0", () => console.log("app listening on port 3000!"));
