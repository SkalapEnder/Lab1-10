const multer = require('multer')
const path = require('path');
const crypto = require('crypto');
const fs = require("fs");
const express = require("express");
const authMiddleware = require("../authMiddleware");
const router = express.Router();

// Lab Work 2 Part
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const MAX_FILE_SIZE = 1024 * 1024;

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const randomName = crypto.randomBytes(16).toString("hex") + ext;
        cb(null, randomName);
    },
});

// File filter function (only .jpg and .png allowed)
const fileFilter = (req, file, cb) => {
    const allowedTypes = [".jpg", ".png"];
    const ext = path.extname(file.originalname).toLowerCase();

    if (allowedTypes.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error("Only .jpg and .png files are allowed!"), false);
    }
};

const allowedMimeTypes = ["image/jpeg", "image/png"];

const upload = multer({
    storage,
    fileFilter,
}).array("file", 5); // Allow multiple file uploads (max 5)

const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
};

router.get("/uploader", authMiddleware, (req, res) => {
    fs.readdir(uploadDir, (err, files) => {
        if (err) {
            return res.render("tasks/upload", { files: [], message: null, errorMessage: "Error loading images." });
        }
        res.render("tasks/upload", { files, message: null, errorMessage: null });
    });
});

router.post("/upload", (req, res) => {
    upload(req, res, (err) => {
        if (err) {
            return res.render("tasks/upload", { files: [], errorMessage: err.message, message: null });
        }

        if (!req.files || req.files.length === 0) {
            return res.render("tasks/upload", { files: [], errorMessage: "No files were uploaded.", message: null });
        }

        for (const file of req.files) {
            if (file.size > MAX_FILE_SIZE) {
                fs.unlinkSync(file.path);
                return res.render("tasks/upload", { files: [], errorMessage: `File "${file.originalname}" exceeds 1MB limit.`, message: null });
            }
        }


        fs.readdir(uploadDir, (err, files) => {
            if (err) {
                return res.render("tasks/upload", { files: [], errorMessage: "Error loading images.", message: null });
            }
            res.render("tasks/upload", { files, message: "Files uploaded successfully!", errorMessage: null });
        });
    });
});

router.post("/delete", (req, res) => {
    const filename = req.body.filename;
    const filePath = path.join(uploadDir, filename);

    if (fs.existsSync(filePath)) {
        fs.unlink(filePath, (err) => {
            if (err) {
                return res.render("tasks/upload", { files: [], errorMessage: "Error deleting file.", message: null });
            }

            fs.readdir(uploadDir, (err, files) => {
                res.render("tasks/upload", { files, message: "File deleted successfully!", errorMessage: null });
            });
        });
    } else {
        res.render("tasks/upload", { files: [], errorMessage: "File not found.", message: null });
    }
});


router.get("/files/:filename", (req, res) => {
    const filePath = path.join(uploadDir, req.params.filename);

    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.render("templates/error", { errorMessage: "File not found." });
    }
});

router.post("/delete-all", (req, res) => {
    fs.readdir(uploadDir, (err, files) => {
        if (err) {
            return res.render("tasks/upload", { files: [], errorMessage: "Error loading images.", message: null });
        }

        if (files.length === 0) {
            return res.render("tasks/upload", { files: [], errorMessage: "No images to delete.", message: null });
        }

        files.forEach((file) => {
            const filePath = path.join(uploadDir, file);
            fs.unlinkSync(filePath);
        });

        res.render("tasks/upload", { files: [], message: "All images deleted successfully!", errorMessage: null });
    });
});

module.exports = router;