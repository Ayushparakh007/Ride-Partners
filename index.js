import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3005;
const saltRounds = 10;

app.use(
    session({
      secret: "TOPSECRETWORD",
      resave: false,
      saveUninitialized: true,
    //   cookie:{
    //     maxAge: 1000*60*60*24,
    //   },
      
    })
  );

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "TaxiService",
    password: "Ayush@7921",
    port: 5432,
});
db.connect();

app.get("/", (req, res) => {
    res.render("signup.ejs");
});

app.get("/sign", (req, res) => {
    res.render("sign.ejs");
});
app.get("/pay", (req, res) => {
  res.render("pay.ejs");
});

app.get("/signup", (req, res) => {
    res.render("signup.ejs");
});

app.get("/index", (req, res) => {
    res.render("index.ejs");
});

app.get("/index5", (req, res) => {
    res.render("index5.ejs");
});

app.get("/logout", (req, res) => {
    res.redirect("sign");
});





app.get("/profile", (req, res) => {
    // console.log(req.user);
    if (req.isAuthenticated()) {
      res.render("profile.ejs",{
        name: req.user.name1,
        email: req.user.email,
        phone_number: req.user.phone_number,
        gender: req.user.gender,
        your_date_column: req.user.your_date_column
      }
    );
    } else {
      res.redirect("/sign");
    }
  });
  app.get("/sign", async (req, res) => {
    console.log(req.user);
  
    ////////////////UPDATED GET SECRETS ROUTE/////////////////
    if (req.isAuthenticated()) {
      try {
        const result = await db.query(
          `SELECT secret FROM users WHERE email = $1`,
          [req.user.email]
        );
        console.log(result);
        const secret = result.rows[0].secret;
        if (secret) {
          res.render("profile.ejs", {   name: name1,
            email: email,
            phone_number: phone_number,
            gender: gender,
            your_date_column: your_date_column, });
        } else {
          res.render("profile.ejs");
        }
      } catch (err) {
        console.log(err);
      }
    } else {
      res.redirect("/sign");
    }
  });
  


  

  app.post(
    "/sign",
    passport.authenticate("local", {
      successRedirect: "/profile",
      failureRedirect: "/sign",
    })
  );

app.post("/signup", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
    const name1 = req.body.givenName;
    const phone_number = req.body.contactNumber;
    const gender = req.body.gender;
    const your_date_column = req.body.yob;

    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  
        if (checkResult.rows.length > 0) {
            res.send("Email already exists. Try logging in.");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    await db.query(
                        "INSERT INTO users (email, password,name1,phone_number,gender,your_date_column) VALUES ($1, $2,$3,$4,$5,$6)",
                        [email, hash,name1,phone_number,gender,your_date_column]
                    );
                    res.render("profile.ejs", {
                        name: name1,
                        email: email,
                        phone_number: phone_number,
                        gender: gender,
                        your_date_column: your_date_column,
                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});


    passport.use(
        new Strategy(async function verify(username, password, cb) {
          try {
            const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
              username,
            ]);
            if (result.rows.length > 0) {
              const user = result.rows[0];
              const storedHashedPassword = user.password;
              bcrypt.compare(password, storedHashedPassword, (err, valid) => {
                if (err) {
                  //Error with password check
                  console.error("Error comparing passwords:", err);
                  return cb(err);
                } else {
                  if (valid) {
                    //Passed password check
                    return cb(null, user);
                  } else {
                    //Did not pass password check
                    return cb(null, false);
                  }
                }
              });
            } else {
              return cb("User not found");
            }
          } catch (err) {
            console.log(err);
          }
        })
      );



  


passport.serializeUser((user, cb) => {
    cb(null, user);
  });
  passport.deserializeUser((user, cb) => {
    cb(null, user);
  });

  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });

