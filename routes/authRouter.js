const express = require('express');
const User = require('../models/User');
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MailerSend, EmailParams, Sender, Recipient } = require("mailersend");
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const authMiddleware = require('../authMiddleware');

const passport = require('passport');
const LocalStrategy = require('passport-local');

require('dotenv').config();
const router = express.Router();

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Auth: Connected to MongoDB Atlas'))
    .catch((err) => console.error('Error connecting to MongoDB Atlas:', err));


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
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});


const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
};

router.get('/api/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ username: user.username, email: user.email });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

router.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email });
    if (!user) {
        return res.status(401).json({ message: 'Invalid email' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid password' });
    }

    // Generate JWT
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

const mailerSend = new MailerSend({ apiKey: process.env.API_KEY, });

const sendEmail = async (to, subject, html) => {
    try {
        const senderEmail = process.env.SENDER_EMAIL;
        const senderName = process.env.SENDER_NAME || "Mailersend Trial";

        const sender = new Sender(senderEmail, senderName);
        const recipients = [new Recipient(to, "Guest")];

        const emailParams = new EmailParams()
            .setFrom(sender)
            .setTo(recipients)
            .setReplyTo(sender)
            .setSubject(subject)
            .setHtml(html)
            .setText(html.replace(/<[^>]*>/g, "")); // Convert HTML to plain text

        const response = await mailerSend.email.send(emailParams);
        return response.statusCode >= 200 && response.statusCode < 300;
    } catch (error) {
        console.error("❌ Error sending email:" + error);
        return false;
    }
};

// REGISTER part
router.get('/register', (req, res) => res.render('auth/registration'));

router.post('/register',
    [
    body('email').isEmail().withMessage('Invalid email address'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
        .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
        .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
        .matches(/[0-9]/).withMessage('Password must contain a number')
        .matches(/[@$!%*?&]/).withMessage('Password must contain a special character')
],
    async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errorMessage: errors.array()[0]['msg'] });
    }

    const { username, email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.status(400).json({ errorMessage: 'User already exists' });
        }

        const newUser = new User({
            username: username,
            email: email,
            password: password,
            created_at: new Date(),
            updated_at: new Date(),
        });

        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        return res.status(500).send({errorMessage:'Error registering user: ' + err.message});
    }
});

// LOGIN part
router.get('/login', (req, res) => res.render('auth/login'));

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email: email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ errorMessage: 'Invalid credentials' });
        }

        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.isLoggedIn = true;

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict'
        });

        res.redirect('/');
    } catch (err) {
        console.log(err)
        res.status(500).json({ errorMessage: 'Error logging in:' + err });
    }
});

// USER part
router.get('/profile', authMiddleware, isAuthenticated, async (req, res) => {
    const user = await getUser(req.session.userId);
    if (user === null) {
        return res.render('templates/error', {errorMessage: 'User not found'});
    }
    return res.render('profile/profile', {user});
});

router.get('/password-reset', (req, res) => res.render('reset/reset_password'));

router.post('/password-reset', [
    body('email').isEmail().withMessage('Invalid email address')
],
    async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errorMessage: errors.array()[0]['msg'] });
    }

    const email = req.body.email;

    if (email === undefined) return res.status(400).json({ errorMessage: "Email is required" });

    const user = await User.findOne({ email: email });
    if (user === null) return res.status(400).json({ errorMessage: "No account with that email exists." });

    // Generate a secure token
    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetToken = resetToken;
    user.tokenExpiry = Date.now() + 3600000;
    await user.save();


    const resetLink = `${process.env.BASE_URL}/password-reset/${resetToken}`;

    // Email template
    const emailHtml = `
        <h3>Password Reset Request</h3>
        <p>You requested to reset your password. Click the link below:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>If you didn't request this, ignore this email.</p>
    `;

    const response = await sendEmail(email, "Password Reset Request", emailHtml);
    if(!response) return res.status(500).json({errorMessage: 'Error sending message to email'});
    res.status(200).json({message: 'The request sent to your email.'});
});

router.get('/password-reset/:token', async (req, res) => {
    const user = await User.findOne({
        resetToken: req.params.token,
        tokenExpiry: { $gt: Date.now() }
    });

    if (user === null) {
        return res.render('templates/error', { errorMessage: 'Link are not actual!'});
    }

    res.render('reset/reset_password_form', { token: req.params.token});
});

router.post('/password-reset/:token', [
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain a lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain a number')
    .matches(/[@$!%*?&]/).withMessage('Password must contain a special character')
],
    async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errorMessage: errors.array()[0]['msg'] });
    }

    const { password } = req.body;
    const user = await User.findOne({
        resetToken: req.params.token,
        tokenExpiry: { $gt: Date.now() }
    });

    if (user === null) return res.status(400).json({ errorMessage: "Token is invalid or expired." });

    user.password = password;
    user.resetToken = undefined;
    user.tokenExpiry = undefined;
    await user.save();
    res.redirect('/reset-success')
});

router.get('/reset-success', (req, res) => res.render('reset/reset_password_success'))

// LOG OUT part
router.get('/logout', authMiddleware, isAuthenticated, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            res.render('templates/error', {errorMessage: 'Error logging out'});
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

router.get('/delete-account', authMiddleware, isAuthenticated, async (req, res) => {
    const userId = req.session.userId;

    try {
        const deletedUser = await User.findByIdAndDelete(userId);
        if (deletedUser === null) {
            return res.render('templates/error', {errorMessage: 'User not found or not deleted'});
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        req.session.destroy();
        res.redirect('/');
    } catch (err) {
        return res.render('templates/error', {errorMessage: err});
    }
});

// Helpers
async function getUser(id){
    const user = await User.findById(id);
    if (user === null) return null;
    return user;
}
module.exports = router;
