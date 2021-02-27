require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const app = express();

app.use(session({
   secret: process.env.SESSION_SECRET,
   resave: false,
   saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://admin:admin@cluster0.j3ghf.mongodb.net/users?retryWrites=true&w=majority", {
   useNewUrlParser: true,
   useUnifiedTopology: true,
   useCreateIndex: true
});

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
   extended: true
}));

app.use(express.static("public")); //folder public 

const SecretSchema = new mongoose.Schema({
   secret: String,
});

const UserSchema = new mongoose.Schema({
   username: String,
   password: String,
   googleId: String,
   secret: [SecretSchema]
});

UserSchema.plugin(passportLocalMongoose);
UserSchema.plugin(findOrCreate);

const User = new mongoose.model("user", UserSchema);
const Secret = new mongoose.model("secret", SecretSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
   done(null, user);
});

passport.deserializeUser(function(user, done) {
   done(null, user);
});

passport.use(new GoogleStrategy({
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_KEY,
      callbackURL: "http://secrets-webapp.herokuapp.com/auth/google/callback"
   },
   function(accessToken, refreshToken, profile, cb) {
      // console.log(profile);
      User.findOrCreate({
         googleId: profile.id
      }, function(err, user) {
         return cb(err, user);
      });
   }
));


app.get(("/"), (req, res) => {
   res.render("home");
});

app.get('/auth/google',
   passport.authenticate('google', {
      scope: ['profile']
   }));

app.get('/auth/google/callback',
   passport.authenticate('google', {
      failureRedirect: '/login'
   }),
   function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
   });




app.route("/login")
   .get((req, res) => {
      res.render("login");
   })
   .post((req, res) => {
      const user = new User({
         username: req.body.username,
         password: req.body.password
      })
      req.login(user, err => {
         if (!err) {
            passport.authenticate("local")(req, res, function() {
               res.redirect("/secrets")
            })
         } else console.log(err);
      })
   });

app.route("/register")
   .get((req, res) => {
      res.render("register");
   })
   .post(function(req, res) {
      User.register({
         username: req.body.username
      }, req.body.password, function(err, user) {
         if (!err) {
            passport.authenticate("local")(req, res, function() {
               res.redirect("/secrets");
            });
         } else {
            console.log(err);
            res.redirect("/register");
         }
      })
   });

app.get("/secrets", function(req, res) {
   if (req.isAuthenticated()) {
      // console.log(req.user);
      User.findById(req.user._id, function(err, result) {
         if (!err) {
            if (result) {
               console.log(result);
               try {
                  res.render("secrets", {
                     secret: result.secret[result.secret.length - 1].secret
                  });
               } catch (err){
                  console.log(err);
                  res.render("secrets",{
                     secret: ""
                  });
               }
            } else res.render("secrets",{
               secret: ""
            });
         } else {
            console.log(err);
            res.redirect("/login");
         }
      });
   } else res.redirect("/login");
})

app.route("/submit")
   .get((req, res) => {
      res.render("submit");
   })
   .post((req, res) => {
      // console.log(req.user._id, req.user.id);
      const secret = new Secret({
         secret: req.body.secret
      });
      try {
         User.findById(req.user._id, function(err, result) {
            if (!err) {
               if (result) {
                  result.secret.push(secret);
                  console.log(result.secret);
                  result.save(function() {
                     res.redirect("/secrets")
                  });
               } else console.log("ni ma użytkownika który chce dodać sekret");
            } else console.log(err);
         })
      } catch (err) {
         console.log(err);
         res.redirect("/secrets")
      }
   });

app.get("/logout", (req, res) => {
   req.logout();
   res.redirect("/");
});



app.listen(process.env.PORT || 2137, () => {
   console.log("Serwer is running on port 2137");
});