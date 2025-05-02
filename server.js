const express = require('express');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const db = require("better-sqlite3")("app.db");  
db.pragma("journal_mode = WAL");

const createTable = db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
  )
  `).run();
const app = express();
app.set('view engine', 'ejs');  
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

  app.use(function(req, res, next) {
    res.locals.errors = [];

    try {
      const decoded = jwt.verify(req.cookies.sApp, process.env.JWTSECRET);
      req.user = decoded;
    } catch (err) {
      // Ignore errors
    }
    next();
  });
app.get('/', (req, res) => {
  res.render("homepage");
});
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/register", (req, res) => {
  const errors = [];
  if(typeof req.body.username !== "string") req.body.username = "";
  if(typeof req.body.password !== "string") req.body.password = "";
  req.body.username = req.body.username.trim();
  if(!req.body.username) errors.push("No username specified");
  if(req.body.username && req.body.username.length <3) errors.push("Username is too short");
  if(req.body.username && req.body.username.length > 10) errors.push("Username is too long");
  if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers");

  if(!req.body.password) errors.push("No password specified");
  if(req.body.password && req.body.password.length < 6) errors.push("password is too short");
  if(req.body.password && req.body.password.length > 10) errors.push("password is too long");

  if (errors.length){
    return res.render("homepage", {
      errors: errors
    });
  }
  const salt=bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password,salt)
  const statement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
  const result=statement.run(req.body.username, req.body.password); 

  const lookStatement = db.prepare("SELECT * fROM users WHERE ROWID =  ?")
  const Ouruser=lookStatement.get(result.lastInsertRowID); 

  const token=jwt.sign({exp: Math.floor(Date.now()/1000+60*60*24), userid: Ouruser.id, username: user.username},process.env.JWTSECRET)

  res.cookie("sApp",token,{
    httpOnly:true,
    secure: true,
    sameSite:strictObject,
    maxAge:1000*60*60*24
  })

  res.send("Thanks for signing up!");
})
app.listen(3000, () => {
  console.log('app listening on port 3000!')
});