const admin = require('./server');

const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from "Bearer <token>"

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken; // Attach decoded user info to request
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Unauthorized: Invalid token' });
  }
};

module.exports = verifyToken;