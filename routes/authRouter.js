const express = require('express');
const User = require('../models/User');
const mongoose = require("mongoose");
const bcrypt = require('bcryptjs');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const { MailerSend, EmailParams, Sender, Recipient } = require("mailersend");
const LocalStrategy = require('passport-local');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
require('dotenv').config();
const router = express.Router();

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Auth: Connected to MongoDB Atlas'))
    .catch((err) => console.error('Error connecting to MongoDB Atlas:', err));

const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
};

const authMiddleware = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ errorMessage: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ errorMessage: 'Unauthorized: Invalid token' });
        }
        req.user = decoded; // Store user info in request object
        next();
    });
};

const mailerSend = new MailerSend({
    apiKey: process.env.API_KEY,
});

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

passport.serializeUser((user, done) => done(null, user.user_id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findOne({user_id: id});
        done(null, user);
    } catch (err) {
        done(err);
    }
});

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

        const userId = await getNextFreeUserId();
        if (isNaN(userId)) {
            return res.status(500).json({ errorMessage: 'Failed to generate a valid user_id' });
        }
        const newUser = new User({
            user_id: userId,
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

        res.session.userId = user.user_id;
        res.session.username = user.username;
        res.session.isLoggedIn = true;

        const token = jwt.sign({ userId: user.user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

        res.redirect('/');
    } catch (err) {
        res.status(500).json({ errorMessage: 'Error logging in' });
    }
});

// UPDATE part
router.get('/update', authMiddleware, async (req, res) => {
    const user = await getUser(req.session.userId);
    if (user === null) {
        return res.render('templates/error', {errorMessage: 'User not found'});
    }
    res.render('profile/update', {user});
})

router.post('/update', authMiddleware, async (req, res) => {
    const { user_id, username, email } = req.body;

    try {
        const updateData = {
            username: username,
            email: email,
            updatedAt: new Date(),
        };

        const updatedUser = await User.findOneAndUpdate(
            {user_id: user_id},
            {$set: updateData}
        );
        if (updatedUser === null) {
            return res.status(500).send({errorMessage: 'Error updating user'});
        }
        req.session.username = username;
        res.redirect('/profile');
    } catch (err) {
        return res.status(500).send({errorMessage: 'Error updating user'});
    }
});

// USER part
router.get('/profile', authMiddleware, async (req, res) => {
    const user = await getUser(req.session.userId);
    if (user === null) {
        return res.render('templates/error', {errorMessage: 'User not found'});
    }
    return res.render('profile/profile', {user});
});

// Protected Profile Route
router.get('/api/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) return res.status(404).json({ errorMessage: 'User not found' });

        res.json(user);
    } catch (err) {
        res.status(500).json({ errorMessage: 'Error retrieving profile' });
    }
});

router.get('/password', authMiddleware, async (req, res) => res.render('profile/password'))

router.post('/password', authMiddleware, [
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

    const { oldPassword, password } = req.body;

    try {
        // Fetch user from database
        const user = await getUser(req.session.userId);
        if (user === null) {
            return res.status(404).send({ errorMessage: 'User not found' });
        }

        if (!await bcrypt.compare(oldPassword, user.password)) {
            return res.status(401).send({ errorMessage: 'Invalid old password' });
        }

        // Hash and save new password
        user.password = password;
        await user.save();
        res.redirect('/profile')
    } catch (err){
        return res.status(500).send({errorMessage:'Error creating new password: ', err});
    }
})

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
router.get('/logout', authMiddleware, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            res.render('templates/error', {errorMessage: 'Error logging out'});
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

router.get('/delete-account', authMiddleware, async (req, res) => {
    const userId = req.session.userId;

    try {
        const deletedUser = await User.findOneAndDelete({ user_id: userId });
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
    const user = await User.findOne({ user_id: id });
    if (user === null) return null;
    return user;
}

async function getNextFreeUserId() {
    try {
        const lastUser = await User.findOne().sort({ user_id: -1 });
        return lastUser ? lastUser.user_id + 1 : 0;
    } catch (err) {
        throw new Error('Failed to retrieve next free user ID');
    }
}

module.exports = router;
