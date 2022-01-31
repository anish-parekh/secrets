require('dotenv').config();        //must be the first line of the code if we wish to use environment variables
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const InstagramStrategy = require('passport-instagram').Strategy;
const findOrCreate = require("mongoose-findorcreate");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// const md5 = require("md5");           // for encryption using hashing

const app = express();

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  instagramId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"       // this line of code is added because of deprication of google+ services and this is another alternative url for retrieving the data of a user instead from the google+ services
  },
  function(accessToken, refreshToken, profile, cb) {     //accesstoken allows us to get data of the user
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.META_CLIENT_ID,
    clientSecret: process.env.META_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new InstagramStrategy({
    clientID: process.env.INSTAGRAM_CLIENT_ID,
    clientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/instagram/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ instagramId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));


app.get("/",function(req,res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  }
);

app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ["profile"] })
);

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get('/auth/instagram',
  passport.authenticate('instagram', { scope: ["profile"] })
);

app.get('/auth/instagram/secrets',
  passport.authenticate('instagram', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });


app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  if(req.isAuthenticated())
  {
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
      if(err)
      {
        console.log(err);
      }
      else
      {
        res.render("secrets",{usersWithSecrets: foundUsers});
      }
    });
    // res.render("secrets");
  }
  else
  {
    res.redirect("/login");
  }
});

app.get("/submit",function(req,res){
  if(req.isAuthenticated())
  {
    res.render("submit");
  }
  else
  {
    res.redirect("/login");
  }
});

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;

  // console.log(req.user);

  User.findById(req.user.id, function(err,foundUser){
    if(err)
    {
      console.log(err);
    }
    else
    {
      if(foundUser)
      {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

app.post("/register",function(req,res){

  User.register({username: req.body.username},req.body.password, function(err,user){
    if(err)
    {
      console.log(err);
      res.redirect("/register");
    }
    else
    {
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //
  //   newUser.save(function(err){
  //     if(err)
  //     {
  //       console.log(err);
  //     }
  //     else
  //     {
  //       res.render("secrets");          // there is no get route for the secrets page as the user could only access it once he/she is registered
  //     }
  //   });
// });

});


app.post("/login",function(req,res){

  const newUser = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(newUser,function(err){
    if(err)
    {
      console.log(err);
    }
    else
    {
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email: username},function(err,foundUser){
  //   if(err)
  //   {
  //     console.log(err);
  //   }
  //   else
  //   {
  //     bcrypt.compare(password, foundUser.password, function(err, result) {
  //       if(result === true)
  //       {
  //         res.render("secrets");
  //       }
  //     });
  //   }
  // });
});

app.listen(process.env.PORT || 3000,function(){
  console.log("Server successfully started on port 3000.");
});
