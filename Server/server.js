const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit')


const app = express();
app.use(cors()); 
app.use(express.json());




// firebase
const admin = require('firebase-admin');
const verifyToken = require('./authMiddleware');
const serviceAccount = require('./adminsdk/edsa-451812-firebase-adminsdk-fbsvc-c6fafe7dc2.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
module.exports = admin;

const auth = admin.auth();
const jwt = require("jsonwebtoken"); // For generating tokens
const db = admin.firestore();

// const loginLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 3, // Max 5 login attempts
//   standardHeaders: true, // Return rate limit info in headers
//   legacyHeaders: false,  // Disable `X-RateLimit-*` headers
//   handler: (req, res) => {
//     res.status(429).json({
//       success: false,
//       message: "Too many login attempts. Try again later.",
//     });
//   },
// });

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// 🔹 Backend Login Route - Verify Firebase Token & Issue Backend JWT
app.post('/login', async (req, res) => {
  const { idToken } = req.body;

  try {
    // Verify Firebase Token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { uid, email } = decodedToken;

    console.log('Verified Firebase UID:', uid);

    // Generate Backend JWT (Valid for 24h)
    const backendToken = jwt.sign({ uid, email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ success: true, token: backendToken });
  } catch (error) {
    console.error('Error verifying Firebase token:', error);
    res.status(401).json({ success: false, message: 'Invalid authentication token' });
  }
});

// 🔹 Protected Route Example
app.get('/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from "Bearer <token>"
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ success: true, message: 'Authenticated', user: decoded });
  } catch (err) {
    res.status(403).json({ message: 'Invalid token' });
  }
});



app.post('/register', async (req,res) => {
  const {FName, LName, email, org, pass, confirmPass} = req.body;

  try{

    if(pass != confirmPass){
      return res.status(400).json({error:'Password must be similar!'})
    }

  //   const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

  // if (!strongPasswordRegex.test(pass)) {
  //   return res.status(400).json({ 
  //     error: "Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character." 
  //   });
  // }


    const userRecord = await admin.auth().createUser({
      email,
      password: pass
    })


    
  const userData = {
    firstName: FName,
    lastName: LName,
    userName:'',
    email: email,
    organization: org,
    uid: userRecord.uid, // Store the UID in Firestore
  };

  await db.collection('users').doc(userRecord.uid).set(userData);
    




    await admin.auth().setCustomUserClaims(userRecord.uid, {role: 'student'})

    res.status(201).json({message: 'User Registered Successfully as a Student', uid: userRecord.uid});

  }catch(err){
    res.status(400).json({error: err.message})
  }
})

app.post('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});


app.get('/test', (req,res) => {
    res.json({hi: 'HERLLO THERE!', age:35})
})

const PORT = 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
