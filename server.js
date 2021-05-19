const express = require('express');
const app = express();
const { pool } = require('./dbConfig');
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");

const initializePassport = require("./passportConfig");
const initialize = require('./passportConfig');

initializePassport(passport);

const PORT = process.env.PORT || 4000;

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: false}));

app.use(session({
    secret: 'secret',

    resave: false,
    
    saveUninitialized: false
}));

app.use(passport.initialize());

app.use(passport.session());

app.use(flash());

app.get('/', (req,res) => {
    res.render("index");
});

app.get("/users/register", checkAuthenticated, (req, res)=> {
    res.render("register");
});

app.get("/users/login", checkAuthenticated, (req, res) => {
    res.render("login");
});

app.get("/users/dashboard", checkNonAuthenticated, (req, res)=> {
    res.render("dashboard", { user: req.user.name });
});

app.get('/users/logout', (req, res) => {
    req.logOut();
    req.flash('success_msg', "You have logged out");
    res.redirect("/users/login");
});

app.post("/users/register", async (req,res)=> {
    let {name, email, password, password2, phone} = req.body;

    console.log({
        name, email, password, password2, phone
    });

    let errors = [];

    if(!name || !email || !password || !password2 || !phone){
        errors.push({message: "Please enter all fields"});
    }

    if(password.length < 6){
        errors.push({message: "Password should be at least 6 characters"});
    }

    if(password != password2){
        errors.push({message: "Passwords do not match"});
    }

    if(errors.length > 0){
        res.render("register", {errors});
    }else{
        // Form validation has passed
        let hashedPassword = await bcrypt.hash(password,10);
        console.log(hashedPassword);

        pool.query(
            `SELECT * FROM clients WHERE email = $1`,
            [email],
            (err, results) => {
                if(err){
                    throw err;
                }
                console.log(results.rows);

                if(results.rows.length > 0){
                    errors.push({message: "Email already registered"});
                    res.render("register", { errors });
                }else{
                    // That means email doesn't exist in the database
                    pool.query(
                        `INSERT INTO clients (name, email, password, "phoneNumber")
                        VALUES($1, $2, $3, $4)
                        RETURNING id, password`, [name, email, hashedPassword, phone], 
                        (err, results) => {
                            if(err){
                                throw err;
                            }
                            console.log(results.rows);
                            req.flash("success_msg", "You are now registered. Please log in");
                            res.redirect("/users/login");
                        }
                    );
                }
            }
        )
    }
});

app.post("/users/login", passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
}));

function checkAuthenticated(req, res, next) {
    if(req.isAuthenticated()){
        return res.redirect("/users/dashboard");
    }

    next();
}

function checkNonAuthenticated(req, res, next) {
    if(req.isAuthenticated()){
        return next();
    }
    
    res.redirect("/users/login");
}

app.listen(PORT, ()=>{
    console.log(`Server running on port ${PORT}`);
});

