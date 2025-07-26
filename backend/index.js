import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { comparePassword } from './utils/hashPassword.js';
import bcrypt from 'bcrypt';

import Feedback from './models/Feedback.js';
import Admin from './admins/Admin.js';

dotenv.config();
const app = express();

app.use(cors({
  origin: [
    "http://localhost:5173",
    "https://student-management-hackathon-u6vj.vercel.app"
  ]
}));

app.use(express.json());


// JWT middleware
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: 'Access denied' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes
app.post('/feedback', async (req, res) => {
  const { name, email, course, rating, comments } = req.body;
  try {
    const feedback = new Feedback({ name, email, course, rating, comments, createdAt: new Date() });
    await feedback.save();
    res.status(201).json({ message: 'Feedback submitted' });
  } catch (err) {
    res.status(500).json({ message: 'Error saving feedback' });
  }
});

app.get('/feedbacks', authMiddleware, async (req, res) => {
  const feedbacks = await Feedback.find().sort({ createdAt: -1 });
  res.json(feedbacks);
});

app.post('/admin/create', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const admin = new Admin({ username, password: hashed });
  await admin.save();
  res.json({ message: 'Admin created' });
});

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  console.log('Login attempt:', username, password); 

  const admin = await Admin.findOne({ username });
  if (!admin) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const isMatch = await comparePassword(password, admin.password); 
  if (!isMatch) {
    console.log('Password mismatch');
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET_KEY);
  res.json({ token });
});


//Mongodb Connect
const db = process.env.MONGODB_URL;
const connection = mongoose.connect(db)
.then(() => {
    console.log('MongoDB connected');
  }).catch(err => {
    console.error('MongoDB connection error:', err);
  });


// Server Running
const port = process.env.PORT;
app.listen(port, (req, res)=> { 
  console.log(`Server is running on port ${port}`);
})

