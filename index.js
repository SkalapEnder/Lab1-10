const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const flash = require('connect-flash');
const crypto = require('crypto');
const path = require('path');
const authMiddleware = require('./authMiddleware');
const LocalStrategy = require("passport-local");
const bcrypt = require("bcryptjs");
const User = require("./models/User");
const authRouter = require('./routes/authRouter');
const uploadRouter = require('./routes/uploadRouter');
const app = express();
const PORT = 3000;

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Session middleware
app.use(session({
    secret: 'ff63d7fe7d4cb794a5b97a0708e560b9c015fb59a4a0e85dbf1d11a47f14ed32',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(cookieParser());
app.use((req, res, next) => {
    res.locals.isLoggedIn = req.session.isLoggedIn || false;
    res.locals.username = req.session.username || 'Guest';
    res.locals.userId = req.session.userId;
    next();
});



passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email });
        if (user === null) return done(null, false, { message: 'Invalid email or password' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return done(null, false, { message: 'Invalid email or password' });

        return done(null, user);
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findOne({_id: id});
        done(null, user);
    } catch (err) {
        done(err);
    }
});


const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
};

app.get('/', (req, res) => res.render('index'))
app.get('/test', isAuthenticated,  async (req, res) => res.render('tasks/test'))

app.use('/', authRouter)
app.use('/', uploadRouter)

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

function convertData(timestamp) {
    const date = new Date(Date.parse(timestamp));

    const time = date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });

    const day = date.getDate();
    const month = date.toLocaleString('en-GB', { month: 'long' });
    const year = date.getFullYear();

    return `${time} ${day} ${month}, ${year}`;
}

function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}


app.locals.convertData = convertData;
app.locals.capitalizeFirstLetter = capitalizeFirstLetter;

