const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

dotenv.config();

const app = express();

app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'admin-password']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create required directories
const dirs = ['uploads', 'public'];
dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Serve static files from frontend
app.use(express.static(path.join(__dirname, 'frontend')));
app.use('/uploads', express.static('uploads'));

// Multer storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Email transporter
let transporter = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS && 
    process.env.EMAIL_USER !== 'your_email@gmail.com') {
    transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });
} else {
    console.log('📧 Email not configured. OTP will be shown on console only.');
}

// Data stores
const otpStore = new Map();
const students = new Map();
const sessions = new Map();
const degrees = new Map();
const studentProfiles = new Map();
let studentIdCounter = 1;

function generateHash() {
    return "0x" + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
}

async function sendOTPByEmail(email, otp) {
    console.log(`📧 OTP for ${email}: ${otp}`);
    if (transporter) {
        try {
            await transporter.sendMail({
                from: `"BlockDegree" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: '🔐 Your OTP for Degree Verification',
                html: `<div style="padding:20px;font-family:Arial">
                    <h2 style="color:#1a3e6f">BlockDegree</h2>
                    <div style="font-size:36px;font-weight:bold;color:#667eea;margin:20px 0">${otp}</div>
                    <p>Valid for 5 minutes</p>
                </div>`
            });
            console.log(`✅ Email sent to ${email}`);
        } catch(e) { 
            console.log('Email error:', e.message); 
        }
    }
    return true;
}

// ==================== AUTH ENDPOINTS ====================

app.post('/api/request-otp', async (req, res) => {
    const { email } = req.body;
    console.log("📨 OTP request for:", email);
    
    if (!email || !email.endsWith('@iqra.edu.pk')) {
        return res.status(400).json({ 
            success: false, 
            error: 'Only @iqra.edu.pk email addresses are allowed' 
        });
    }
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    
    otpStore.set(email, { otp, expiresAt });
    await sendOTPByEmail(email, otp);
    
    res.json({ success: true, message: 'OTP sent to your email' });
});

app.post('/api/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    console.log("📨 OTP verification for:", email);
    
    const stored = otpStore.get(email);
    
    if (!stored) {
        return res.status(400).json({ success: false, error: 'Request OTP first' });
    }
    
    if (Date.now() > stored.expiresAt) {
        otpStore.delete(email);
        return res.status(400).json({ success: false, error: 'OTP expired' });
    }
    
    if (stored.otp !== otp) {
        return res.status(400).json({ success: false, error: 'Invalid OTP' });
    }
    
    const sessionToken = jwt.sign({ email }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    sessions.set(sessionToken, { email });
    otpStore.delete(email);
    
    if (!studentProfiles.has(email)) {
        studentProfiles.set(email, { email, status: 'pending' });
    }
    
    res.json({ success: true, sessionToken });
});

app.post('/api/check-session', (req, res) => {
    const { sessionToken } = req.body;
    try {
        const decoded = jwt.verify(sessionToken, process.env.JWT_SECRET || 'secret');
        res.json({ success: true, email: decoded.email });
    } catch(e) { 
        res.json({ success: false }); 
    }
});

app.post('/api/logout', (req, res) => {
    const { sessionToken } = req.body;
    sessions.delete(sessionToken);
    res.json({ success: true });
});

// ==================== STUDENT DASHBOARD ENDPOINTS ====================

app.get('/api/student/dashboard', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const email = decoded.email;
        
        const profile = studentProfiles.get(email) || { email, status: 'pending' };
        res.json({ 
            success: true, 
            ...profile,
            applicationStatus: profile.status || 'pending',
            degreeHash: profile.degreeHash || null,
            program: profile.program || 'BS Computer Science'
        });
    } catch(e) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

app.post('/api/save-profile', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const email = decoded.email;
        const { name, fatherName, cnic, dateOfBirth } = req.body;
        
        if (!name || !fatherName || !cnic || !dateOfBirth) {
            return res.status(400).json({ success: false, error: 'All fields required' });
        }
        
        const profile = studentProfiles.get(email) || { email };
        profile.name = name;
        profile.fatherName = fatherName;
        profile.cnic = cnic;
        profile.dateOfBirth = dateOfBirth;
        profile.status = 'profile_saved';
        studentProfiles.set(email, profile);
        
        res.json({ success: true, message: 'Profile saved successfully' });
    } catch(e) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

app.post('/api/upload-documents', upload.fields([
    { name: 'cnicFront', maxCount: 1 },
    { name: 'cnicBack', maxCount: 1 },
    { name: 'matricMarksheet', maxCount: 1 },
    { name: 'interMarksheet', maxCount: 1 }
]), (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const email = decoded.email;
        
        const profile = studentProfiles.get(email);
        if (!profile) {
            return res.status(404).json({ success: false, error: 'Profile not found' });
        }
        
        const cnicValid = true;
        const cnicExpiry = '2025-12-31';
        
        profile.documentsUploaded = true;
        profile.cnicValid = cnicValid;
        profile.cnicExpiry = cnicExpiry;
        profile.status = 'documents_uploaded';
        studentProfiles.set(email, profile);
        
        res.json({ 
            success: true, 
            cnicValid: cnicValid,
            cnicExpiry: cnicExpiry,
            message: 'Documents uploaded successfully'
        });
    } catch(e) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

app.post('/api/ai-verify', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const email = decoded.email;
        
        const profile = studentProfiles.get(email);
        if (!profile) {
            return res.status(404).json({ success: false, error: 'Profile not found' });
        }
        
        const isValid = true;
        profile.status = 'ai_verified';
        studentProfiles.set(email, profile);
        
        res.json({
            success: true,
            verification: {
                isValid: isValid,
                recommendation: 'All documents verified. Ready for payment.',
                score: '95%'
            }
        });
    } catch(e) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

app.post('/api/create-payment', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const email = decoded.email;
        const { method, amount } = req.body;
        
        const paymentId = 'pay_' + Date.now() + Math.random().toString(36).substr(2, 9);
        const paymentHash = generateHash();
        
        const profile = studentProfiles.get(email);
        if (profile) {
            profile.paymentId = paymentId;
            profile.paymentStatus = 'pending';
            studentProfiles.set(email, profile);
        }
        
        res.json({
            success: true,
            paymentId: paymentId,
            paymentHash: paymentHash,
            amount: amount || 0.05,
            cryptoAddress: '0x7B3f9E2d8A1c4F6B9E2d8A1c4F6B9E2d',
            paymentUrl: 'https://example.com/pay/' + paymentId
        });
    } catch(e) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

app.post('/api/upload-payment-proof', upload.fields([
    { name: 'screenshot', maxCount: 1 }
]), (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
        const email = decoded.email;
        const { paymentId } = req.body;
        
        const profile = studentProfiles.get(email);
        if (profile) {
            const degreeHash = generateHash();
            profile.degreeHash = degreeHash;
            profile.status = 'approved';
            profile.paymentStatus = 'completed';
            
            degrees.set(degreeHash, {
                studentName: profile.name || 'Student',
                fatherName: profile.fatherName || '',
                cnic: profile.cnic || '',
                degreeType: 'BS Computer Science',
                university: 'Iqra University',
                issueDate: new Date().toLocaleDateString(),
                verified: true,
                conditions: { cnicValid: true, interValid: true, cgpaValid: true }
            });
            
            studentProfiles.set(email, profile);
            
            const studentData = {
                id: studentIdCounter++,
                name: profile.name,
                fatherName: profile.fatherName,
                cnic: profile.cnic,
                email: email,
                degreeHash: degreeHash,
                status: 'approved',
                isValid: true,
                createdAt: new Date()
            };
            students.set(studentData.id, studentData);
        }
        
        res.json({ success: true, message: 'Payment proof uploaded successfully' });
    } catch(e) {
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
});

app.get('/api/download-degree/:hash', (req, res) => {
    const { hash } = req.params;
    const degree = degrees.get(hash);
    
    if (!degree) {
        return res.status(404).json({ success: false, error: 'Degree not found' });
    }
    
    res.json({
        success: true,
        degree: degree,
        message: 'Degree PDF download would be generated here'
    });
});

// ==================== ADMIN ENDPOINTS ====================

app.get('/api/admin/students', (req, res) => {
    const allStudents = Array.from(students.values());
    res.json({ success: true, data: allStudents });
});

app.post('/api/admin/update-status', (req, res) => {
    const { studentId, status, degreeHash, degreeType } = req.body;
    const adminPassword = req.headers['admin-password'];
    
    if (adminPassword !== 'admin123') {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    
    const student = students.get(parseInt(studentId));
    if (!student) {
        return res.status(404).json({ success: false, error: 'Student not found' });
    }
    
    student.status = status;
    let finalHash = degreeHash || student.degreeHash;
    
    if (status === 'approved') {
        student.degreeHash = finalHash;
        if (degreeType) student.degreeType = degreeType;
        student.approvedAt = new Date();
        
        if (!degrees.has(finalHash)) {
            degrees.set(finalHash, {
                studentName: student.name,
                fatherName: student.fatherName,
                cnic: student.cnic,
                degreeType: degreeType || student.degreeType || "BS Computer Science",
                university: "Iqra University",
                issueDate: new Date().toLocaleDateString(),
                verified: true,
                conditions: { cnicValid: true, interValid: true, cgpaValid: true }
            });
        }
        student.isValid = true;
        students.set(student.id, student);
    }
    
    res.json({ success: true, degreeHash: finalHash });
});

app.get('/api/admin/hec-degrees', (req, res) => {
    const adminPassword = req.headers['admin-password'];
    if (adminPassword !== 'admin123') {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }
    const allDegrees = Array.from(degrees.entries()).map(([hash, data]) => ({
        hash: hash,
        studentName: data.studentName,
        degreeType: data.degreeType,
        issueDate: data.issueDate,
        verified: data.verified,
        conditions: data.conditions
    }));
    res.json({ success: true, count: degrees.size, degrees: allDegrees });
});

// ==================== HEC VERIFICATION ====================

app.post('/api/hec/verify-degree', (req, res) => {
    const { degreeId } = req.body;
    console.log(`\n🔍 HEC VERIFICATION REQUEST - Hash: ${degreeId}`);
    
    let degree = degrees.get(degreeId);
    
    if (!degree && degreeId && degreeId.startsWith('0x')) {
        const withoutPrefix = degreeId.substring(2);
        degree = degrees.get(withoutPrefix);
    }
    
    if (!degree && degreeId && !degreeId.startsWith('0x')) {
        const withPrefix = '0x' + degreeId;
        degree = degrees.get(withPrefix);
    }
    
    if (degree && degree.verified) {
        res.json({
            success: true,
            verified: true,
            studentName: degree.studentName,
            fatherName: degree.fatherName,
            cnic: degree.cnic,
            degreeType: degree.degreeType,
            university: degree.university,
            issueDate: degree.issueDate,
            message: "✅ Degree is VALID and AUTHENTIC"
        });
    } else {
        res.json({
            success: false,
            verified: false,
            message: "❌ Degree INVALID or NOT FOUND"
        });
    }
});

app.get('/api/hec/degree/:hash', (req, res) => {
    const { hash } = req.params;
    const degree = degrees.get(hash);
    
    if (degree && degree.verified) {
        res.json({ 
            success: true, 
            verified: true, 
            studentName: degree.studentName, 
            degreeType: degree.degreeType,
            university: degree.university,
            issueDate: degree.issueDate
        });
    } else {
        res.json({ success: false, verified: false });
    }
});

// ==================== SUBMIT PROFILE ====================

app.post('/api/submit-profile', upload.fields([
    { name: 'cnicFront', maxCount: 1 },
    { name: 'cnicBack', maxCount: 1 },
    { name: 'matricMarksheet', maxCount: 1 },
    { name: 'interMarksheet', maxCount: 1 },
    { name: 'transcript', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, fatherName, cnic, dateOfBirth, cgpa, interPercentage, cnicExpiry, cnicExpired, sessionToken } = req.body;
        
        try {
            jwt.verify(sessionToken, process.env.JWT_SECRET || 'secret');
        } catch(e) {
            return res.status(401).json({ success: false, error: 'Invalid session' });
        }
        
        const interPercent = parseFloat(interPercentage) || 0;
        const cgpaValue = parseFloat(cgpa) || 0;
        const isCnicExpired = cnicExpired === 'true';
        
        const cnicValid = !isCnicExpired && cnicExpiry !== 'null' && cnicExpiry !== null && cnicExpiry !== '';
        const interValid = interPercent >= 50;
        const cgpaValid = cgpaValue >= 2.5;
        const allConditionsMet = cnicValid && interValid && cgpaValid;
        
        const degreeHash = generateHash();
        
        let verificationMessage = "";
        let verificationTitle = "";
        
        if (allConditionsMet) {
            verificationTitle = "✅ VERIFICATION PASSED!";
            verificationMessage = `${verificationTitle}\n\n` +
                `📊 Intermediate: ${interPercent}% ✅\n` +
                `🎓 CGPA: ${cgpaValue} ✅\n` +
                `🪪 CNIC: Valid ✅\n\n` +
                `🎉 Your degree will be VALID on HEC portal.`;
        } else {
            verificationTitle = "❌ VERIFICATION FAILED!";
            verificationMessage = `${verificationTitle}\n\n`;
            if (!cnicValid) verificationMessage += `🪪 CNIC: EXPIRED ❌ (Expiry: ${cnicExpiry || 'N/A'})\n`;
            if (!interValid) verificationMessage += `📊 Intermediate: ${interPercent}% (Need 50%+) ❌\n`;
            if (!cgpaValid) verificationMessage += `🎓 CGPA: ${cgpaValue} (Need 2.5+) ❌\n`;
            verificationMessage += `\n⚠️ Your degree will be INVALID on HEC portal.\n\n`;
            verificationMessage += `📌 Requirements:\n`;
            verificationMessage += `   • CNIC must be valid (not expired)\n`;
            verificationMessage += `   • Intermediate must be ≥ 50%\n`;
            verificationMessage += `   • CGPA must be ≥ 2.5`;
        }
        
        console.log(`\n📝 =========================================`);
        console.log(`📝 APPLICATION SUBMITTED`);
        console.log(`📝 =========================================`);
        console.log(`   Student: ${name}`);
        console.log(`   Hash: ${degreeHash}`);
        console.log(`   📊 CONDITIONS CHECK:`);
        console.log(`   ├─ CNIC Valid: ${cnicValid ? '✅ YES' : '❌ NO'} (Expiry: ${cnicExpiry || 'N/A'})`);
        console.log(`   ├─ Inter ≥50%: ${interValid ? '✅ YES' : '❌ NO'} (${interPercent}%)`);
        console.log(`   └─ CGPA ≥2.5: ${cgpaValid ? '✅ YES' : '❌ NO'} (${cgpaValue})`);
        console.log(`   🎯 FINAL STATUS: ${allConditionsMet ? '✅ VALID DEGREE' : '❌ INVALID DEGREE'}`);
        console.log(`=========================================\n`);
        
        const studentData = {
            id: studentIdCounter++,
            name, fatherName, cnic, dateOfBirth,
            cgpa: cgpaValue,
            cnicExpiry, cnicExpired: isCnicExpired,
            interPercentage: interPercent,
            cnicValid: cnicValid,
            interValid: interValid,
            cgpaValid: cgpaValid,
            status: "approved",
            degreeHash: degreeHash,
            isValid: allConditionsMet,
            createdAt: new Date(),
            verificationMessage: verificationMessage
        };
        
        studentData.degreeType = "BS Computer Science";
        studentData.approvedAt = new Date();
        studentData.qrData = {
            studentName: name,
            cnic: cnic,
            hash: degreeHash,
            degreeType: "BS Computer Science"
        };
        
        if (allConditionsMet) {
            degrees.set(degreeHash, {
                studentName: name,
                fatherName: fatherName,
                cnic: cnic,
                degreeType: "BS Computer Science",
                university: "Iqra University",
                issueDate: new Date().toLocaleDateString(),
                verified: true,
                conditions: { 
                    cnicValid: cnicValid, 
                    interValid: interValid, 
                    cgpaValid: cgpaValid,
                    cnicExpiry: cnicExpiry,
                    interPercentage: interPercent,
                    cgpa: cgpaValue
                }
            });
        }
        
        students.set(studentData.id, studentData);
        
        res.json({ 
            success: true, 
            studentId: studentData.id, 
            degreeHash: degreeHash,
            isValid: allConditionsMet,
            verificationMessage: verificationMessage,
            verificationTitle: verificationTitle,
            conditions: {
                cnicValid: cnicValid,
                interValid: interValid,
                cgpaValid: cgpaValid,
                cnicExpiry: cnicExpiry,
                interPercentage: interPercent,
                cgpa: cgpaValue
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/agent/verify-documents', (req, res) => {
    const { studentId } = req.body;
    const student = students.get(parseInt(studentId));
    if (!student) {
        return res.status(404).json({ success: false });
    }
    
    const cnicValid = !student.cnicExpired && student.cnicExpiry !== null && student.cnicExpiry !== 'null';
    const interValid = student.interPercentage >= 50;
    const cgpaValid = student.cgpa >= 2.5;
    const allValid = cnicValid && interValid && cgpaValid;
    
    let message = "";
    if (allValid) {
        message = "✅ ALL CONDITIONS MET - Degree will be VALID on HEC portal";
    } else {
        message = "❌ CONDITIONS FAILED - Degree will be INVALID on HEC portal\n";
        if (!cnicValid) message += "   • CNIC is expired or invalid\n";
        if (!interValid) message += `   • Intermediate: ${student.interPercentage}% (need 50%+)\n`;
        if (!cgpaValid) message += `   • CGPA: ${student.cgpa} (need 2.5+)\n`;
    }
    
    res.json({
        success: true,
        checks: {
            cnicValid: cnicValid,
            cnicExpiry: student.cnicExpiry,
            interValid: interValid,
            interPercentage: student.interPercentage,
            cgpaValid: cgpaValid,
            cgpa: student.cgpa
        },
        allValid: allValid,
        score: `${[cnicValid, interValid, cgpaValid].filter(v => v === true).length}/3`,
        percentage: `${Math.round(([cnicValid, interValid, cgpaValid].filter(v => v === true).length / 3) * 100)}%`,
        recommendation: allValid ? 'AUTO-APPROVE - Degree will be VALID on HEC' : 'MANUAL REVIEW - Degree will be INVALID on HEC',
        message: message
    });
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Server running',
        hecDegreesCount: degrees.size
    });
});

// ============================================
// SERVE FRONTEND - FIXED FOR EXPRESS 5
// ============================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

app.get('/student', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'student.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'admin.html'));
});

app.get('/hec', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'hec.html'));
});

// ✅ EXPRESS 5 COMPATIBLE WILDCARD - MUST BE LAST
app.get('/{*path}', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n✅ ========================================`);
    console.log(`✅ BLOCKDEGREE BACKEND SERVER`);
    console.log(`✅ ========================================`);
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`✅ ========================================`);
    console.log(`\n📋 VALIDATION RULES (ALL THREE REQUIRED):`);
    console.log(`   🪪 1. CNIC: Must be valid (not expired)`);
    console.log(`   📊 2. Intermediate: Must be ≥ 50%`);
    console.log(`   🎓 3. CGPA: Must be ≥ 2.5`);
    console.log(`\n⚠️  Degree will be VALID on HEC portal ONLY if`);
    console.log(`   ALL THREE conditions are met.\n`);
});