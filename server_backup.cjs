const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const otpStore = new Map();
const SECRET = "blockchain_secret_2024";

// Test API
app.get('/api/test', (req, res) => {
    res.json({ message: 'Backend is working!' });
});

// Login API
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    if (email === 'iqra@edu.pk' && password === '1234') {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore.set(email, { otp, expires: Date.now() + 5 * 60000 });
        console.log(`📱 OTP for ${email}: ${otp}`);
        res.json({ success: true, message: 'OTP sent', email });
    } 
    else if (email === 'admin@iqra.edu.pk' && password === 'admin123') {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore.set(email, { otp, expires: Date.now() + 5 * 60000 });
        console.log(`📱 OTP for ${email}: ${otp}`);
        res.json({ success: true, message: 'OTP sent', email });
    }
    else {
        res.status(401).json({ error: 'Invalid credentials. Only iqra@edu.pk allowed' });
    }
});

// Verify OTP
app.post('/api/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    const record = otpStore.get(email);
    
    if (!record) {
        return res.status(400).json({ error: 'No OTP found' });
    }
    if (Date.now() > record.expires) {
        return res.status(400).json({ error: 'OTP expired' });
    }
    if (record.otp !== otp) {
        return res.status(400).json({ error: 'Invalid OTP' });
    }
    
    otpStore.delete(email);
    const role = email === 'admin@iqra.edu.pk' ? 'admin' : 'student';
    const token = jwt.sign({ email, role }, SECRET, { expiresIn: '24h' });
    
    res.json({ token, user: { email, role, name: role === 'admin' ? 'Admin' : 'Student' } });
});

app.listen(5000, () => {
    console.log('✅ Server running on http://localhost:5000');
    console.log('📝 Use these credentials:');
    console.log('   Student: iqra@edu.pk / 1234');
    console.log('   Admin: admin@iqra.edu.pk / admin123');
});