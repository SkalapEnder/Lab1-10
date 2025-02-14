const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({error: '401: Token is missing'});
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({error: '401: No token provided: ' + err});
        }
        req.user = decoded;
        next();
    });
};

module.exports = authMiddleware;