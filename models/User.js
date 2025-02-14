const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true},
    password: { type: String, required: true},
    email: { type: String, required: true, unique: true },
    resetToken: { type: String },
    tokenExpiry: { type: Date },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
}, { timestamps: true });

userSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

userSchema.methods.comparePassword = async function (password) {
    password = await bcrypt.hash(password, 10);
    return bcrypt.compare(password, this.password);
};

const User = mongoose.model('user_list', userSchema);
module.exports = User;

