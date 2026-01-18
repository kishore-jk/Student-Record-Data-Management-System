// server.js - Backend Server for Student Record Management System
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
const uploadsDir = './uploads';
const timetablesDir = './uploads/timetables';
const contentDir = './uploads/content';

[uploadsDir, timetablesDir, contentDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = req.path.includes('timetable') ? timetablesDir : contentDir;
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|pdf|docx/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Invalid file type'));
    }
});

// Initialize SQLite Database
const db = new sqlite3.Database('./studentdb.sqlite', (err) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

// Database Schema Initialization
function initializeDatabase() {
    db.serialize(() => {
        // Users table (for admin/staff)
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Students table
        db.run(`CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            dob TEXT NOT NULL,
            gender TEXT NOT NULL,
            dept TEXT NOT NULL,
            year TEXT NOT NULL,
            current_semester INTEGER NOT NULL,
            password TEXT NOT NULL,
            forgot_password_requested TEXT DEFAULT 'false',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Attendance table
        db.run(`CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_roll TEXT NOT NULL,
            total_days INTEGER DEFAULT 0,
            days_present INTEGER DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_roll) REFERENCES students(roll) ON DELETE CASCADE
        )`);

        // Marks table
        db.run(`CREATE TABLE IF NOT EXISTS marks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_roll TEXT NOT NULL,
            semester TEXT NOT NULL,
            int1 INTEGER,
            int2 INTEGER,
            model INTEGER,
            sem_final INTEGER,
            assignment INTEGER,
            mini_project INTEGER,
            rmk_next_gen INTEGER,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_roll) REFERENCES students(roll) ON DELETE CASCADE,
            UNIQUE(student_roll, semester)
        )`);

        // Timetables table
        db.run(`CREATE TABLE IF NOT EXISTS timetables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            semester TEXT NOT NULL UNIQUE,
            file_path TEXT NOT NULL,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Digital Content table
        db.run(`CREATE TABLE IF NOT EXISTS digital_content (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            semester TEXT NOT NULL,
            title TEXT NOT NULL,
            file_path TEXT,
            url TEXT,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Create default admin user
        const defaultAdminPassword = bcrypt.hashSync('ADMIN@1234', 10);
        db.run(`INSERT OR IGNORE INTO users (username, password, role) 
                VALUES (?, ?, ?)`, ['ADMIN', defaultAdminPassword, 'staff']);

        console.log('Database tables initialized');
    });
}

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Authorization Middleware
function authorizeRole(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}

// ============== AUTHENTICATION ENDPOINTS ==============

// Login endpoint
app.post('/api/auth/login', (req, res) => {
    const { userType, username, password } = req.body;

    if (userType === 'staff') {
        db.get('SELECT * FROM users WHERE username = ? AND role = ?', 
            [username.toUpperCase(), 'staff'], 
            async (err, user) => {
                if (err) {
                    return res.status(500).json({ error: 'Database error' });
                }
                if (!user || !await bcrypt.compare(password, user.password)) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                const token = jwt.sign(
                    { id: user.id, username: user.username, role: user.role },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                res.json({ 
                    token, 
                    user: { username: user.username, role: user.role } 
                });
            }
        );
    } else if (userType === 'student' || userType === 'parent') {
        let query = 'SELECT * FROM students WHERE ';
        let param;

        if (userType === 'student') {
            query += 'roll = ?';
            param = username.toUpperCase();
        } else {
            const lastThree = username.toLowerCase().replace('parent@', '');
            query += "substr(roll, -3) = ?";
            param = lastThree.toUpperCase();
        }

        db.get(query, [param], async (err, student) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!student) {
                return res.status(401).json({ error: 'User not found' });
            }

            // Check forgot password status
            if (student.forgot_password_requested === 'requested') {
                return res.status(403).json({ 
                    error: 'Password reset pending approval',
                    status: 'requested'
                });
            }

            // Generate default password
            const deptCode = student.roll.substring(6, 9);
            const defaultPassword = userType === 'student' 
                ? `${deptCode}@1234` 
                : `parent@${student.roll.slice(-3)}1234`;

            // Verify password
            const passwordMatch = await bcrypt.compare(password, student.password) || 
                                  password === defaultPassword;

            if (!passwordMatch) {
                return res.status(401).json({ error: 'Invalid password' });
            }

            // Reset forgot password flag if approved
            if (student.forgot_password_requested === 'approved') {
                db.run('UPDATE students SET forgot_password_requested = ? WHERE roll = ?',
                    ['false', student.roll]);
            }

            const token = jwt.sign(
                { roll: student.roll, name: student.name, role: userType },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({ 
                token, 
                user: { 
                    roll: student.roll, 
                    name: student.name, 
                    role: userType 
                } 
            });
        });
    } else {
        res.status(400).json({ error: 'Invalid user type' });
    }
});

// Change password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
    const { newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    if (req.user.role === 'staff') {
        db.run('UPDATE users SET password = ? WHERE username = ?',
            [hashedPassword, req.user.username],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to update password' });
                }
                res.json({ message: 'Password updated successfully' });
            }
        );
    } else {
        db.run('UPDATE students SET password = ?, forgot_password_requested = ? WHERE roll = ?',
            [hashedPassword, 'false', req.user.roll],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to update password' });
                }
                res.json({ message: 'Password updated successfully' });
            }
        );
    }
});

// Forgot password request
app.post('/api/auth/forgot-password', (req, res) => {
    const { userType, username } = req.body;

    if (userType === 'staff') {
        return res.status(400).json({ error: 'Staff must contact system support' });
    }

    let query = 'SELECT * FROM students WHERE ';
    let param;

    if (userType === 'student') {
        query += 'roll = ?';
        param = username.toUpperCase();
    } else {
        const lastThree = username.toLowerCase().replace('parent@', '');
        query += "substr(roll, -3) = ?";
        param = lastThree.toUpperCase();
    }

    db.get(query, [param], (err, student) => {
        if (err || !student) {
            return res.status(404).json({ error: 'User not found' });
        }

        db.run('UPDATE students SET forgot_password_requested = ? WHERE roll = ?',
            ['requested', student.roll],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to submit request' });
                }
                res.json({ 
                    message: 'Password reset request submitted',
                    status: 'requested'
                });
            }
        );
    });
});

// Approve password reset (staff only)
app.post('/api/auth/approve-reset/:roll', 
    authenticateToken, 
    authorizeRole('staff'), 
    async (req, res) => {
        const { roll } = req.params;

        db.get('SELECT * FROM students WHERE roll = ?', [roll], async (err, student) => {
            if (err || !student) {
                return res.status(404).json({ error: 'Student not found' });
            }

            const deptCode = student.roll.substring(6, 9);
            const defaultPassword = `${deptCode}@1234`;
            const hashedPassword = await bcrypt.hash(defaultPassword, 10);

            db.run('UPDATE students SET password = ?, forgot_password_requested = ? WHERE roll = ?',
                [hashedPassword, 'approved', roll],
                (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to approve reset' });
                    }
                    res.json({ message: 'Password reset approved' });
                }
            );
        });
    }
);

// ============== STUDENT MANAGEMENT ENDPOINTS ==============

// Get all students (staff only)
app.get('/api/students', authenticateToken, authorizeRole('staff'), (req, res) => {
    const query = `
        SELECT s.*, 
               a.total_days, a.days_present,
               CASE 
                   WHEN a.total_days > 0 THEN ROUND((a.days_present * 100.0) / a.total_days, 2)
                   ELSE 0 
               END as attendance_percentage
        FROM students s
        LEFT JOIN attendance a ON s.roll = a.student_roll
        ORDER BY s.roll
    `;

    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(rows);
    });
});

// Get single student
app.get('/api/students/:roll', authenticateToken, (req, res) => {
    const { roll } = req.params;

    // Authorization check
    if (req.user.role !== 'staff' && req.user.roll !== roll) {
        return res.status(403).json({ error: 'Unauthorized access' });
    }

    const query = `
        SELECT s.*, 
               a.total_days, a.days_present
        FROM students s
        LEFT JOIN attendance a ON s.roll = a.student_roll
        WHERE s.roll = ?
    `;

    db.get(query, [roll], (err, student) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!student) {
            return res.status(404).json({ error: 'Student not found' });
        }

        // Get all marks
        db.all('SELECT * FROM marks WHERE student_roll = ?', [roll], (err, marks) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            student.marks = {};
            marks.forEach(mark => {
                student.marks[mark.semester] = {
                    int1: mark.int1,
                    int2: mark.int2,
                    model: mark.model,
                    semFinal: mark.sem_final,
                    assignment: mark.assignment,
                    miniProject: mark.mini_project,
                    rmkNextGen: mark.rmk_next_gen
                };
            });

            res.json(student);
        });
    });
});

// Create student (staff only)
app.post('/api/students', authenticateToken, authorizeRole('staff'), async (req, res) => {
    const { name, roll, dob, gender, dept, year, currentSemester } = req.body;

    // Generate default password
    const deptCode = roll.substring(6, 9);
    const defaultPassword = `${deptCode}@1234`;
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);

    db.run(`INSERT INTO students (roll, name, dob, gender, dept, year, current_semester, password)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [roll, name, dob, gender, dept, year, currentSemester, hashedPassword],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Roll number already exists' });
                }
                return res.status(500).json({ error: 'Failed to create student' });
            }

            // Create attendance record
            db.run('INSERT INTO attendance (student_roll) VALUES (?)', [roll]);

            // Create marks records for all semesters
            const semesters = ['sem1', 'sem2', 'sem3', 'sem4', 'sem5', 'sem6', 'sem7', 'sem8'];
            const stmt = db.prepare('INSERT INTO marks (student_roll, semester) VALUES (?, ?)');
            semesters.forEach(sem => stmt.run(roll, sem));
            stmt.finalize();

            res.status(201).json({ 
                message: 'Student created successfully',
                roll: roll,
                defaultPassword: defaultPassword
            });
        }
    );
});

// Update student (staff only)
app.put('/api/students/:roll', authenticateToken, authorizeRole('staff'), (req, res) => {
    const { roll } = req.params;
    const { name, dob, gender, dept, year, currentSemester } = req.body;

    db.run(`UPDATE students 
            SET name = ?, dob = ?, gender = ?, dept = ?, year = ?, current_semester = ?, updated_at = CURRENT_TIMESTAMP
            WHERE roll = ?`,
        [name, dob, gender, dept, year, currentSemester, roll],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to update student' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Student not found' });
            }
            res.json({ message: 'Student updated successfully' });
        }
    );
});

// Delete student (staff only)
app.delete('/api/students/:roll', authenticateToken, authorizeRole('staff'), (req, res) => {
    const { roll } = req.params;

    db.run('DELETE FROM students WHERE roll = ?', [roll], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete student' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Student not found' });
        }
        res.json({ message: 'Student deleted successfully' });
    });
});

// Get password reset requests (staff only)
app.get('/api/students/password-requests', authenticateToken, authorizeRole('staff'), (req, res) => {
    db.all(`SELECT roll, name FROM students WHERE forgot_password_requested = 'requested'`,
        [], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(rows);
        }
    );
});

// ============== ATTENDANCE ENDPOINTS ==============

// Update attendance
app.put('/api/attendance/:roll', authenticateToken, authorizeRole('staff'), (req, res) => {
    const { roll } = req.params;
    const { totalDays, daysPresent } = req.body;

    if (daysPresent > totalDays) {
        return res.status(400).json({ error: 'Days present cannot exceed total days' });
    }

    db.run(`INSERT INTO attendance (student_roll, total_days, days_present) 
            VALUES (?, ?, ?)
            ON CONFLICT(student_roll) 
            DO UPDATE SET total_days = ?, days_present = ?, updated_at = CURRENT_TIMESTAMP`,
        [roll, totalDays, daysPresent, totalDays, daysPresent],
        (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to update attendance' });
            }
            res.json({ message: 'Attendance updated successfully' });
        }
    );
});

// ============== MARKS ENDPOINTS ==============

// Update marks for a semester
app.put('/api/marks/:roll/:semester', authenticateToken, authorizeRole('staff'), (req, res) => {
    const { roll, semester } = req.params;
    const { int1, int2, model, semFinal, assignment, miniProject, rmkNextGen } = req.body;

    db.run(`UPDATE marks 
            SET int1 = ?, int2 = ?, model = ?, sem_final = ?, 
                assignment = ?, mini_project = ?, rmk_next_gen = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE student_roll = ? AND semester = ?`,
        [int1, int2, model, semFinal, assignment, miniProject, rmkNextGen, roll, semester],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to update marks' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Record not found' });
            }
            res.json({ message: 'Marks updated successfully' });
        }
    );
});

// ============== CONTENT MANAGEMENT ENDPOINTS ==============

// Upload timetable (staff only)
app.post('/api/timetable', 
    authenticateToken, 
    authorizeRole('staff'), 
    upload.single('timetable'), 
    (req, res) => {
        const { semester } = req.body;
        const filePath = `/uploads/timetables/${req.file.filename}`;

        db.run(`INSERT INTO timetables (semester, file_path) 
                VALUES (?, ?)
                ON CONFLICT(semester) 
                DO UPDATE SET file_path = ?, uploaded_at = CURRENT_TIMESTAMP`,
            [semester, filePath, filePath],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to save timetable' });
                }
                res.json({ 
                    message: 'Timetable uploaded successfully',
                    filePath: filePath
                });
            }
        );
    }
);

// Upload digital content (staff only)
app.post('/api/digital-content', 
    authenticateToken, 
    authorizeRole('staff'), 
    upload.single('content'), 
    (req, res) => {
        const { semester, title, url } = req.body;
        const filePath = req.file ? `/uploads/content/${req.file.filename}` : null;

        if (!filePath && !url) {
            return res.status(400).json({ error: 'File or URL required' });
        }

        db.run(`INSERT INTO digital_content (semester, title, file_path, url) 
                VALUES (?, ?, ?, ?)`,
            [semester, title, filePath, url],
            (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to save content' });
                }
                res.json({ 
                    message: 'Content uploaded successfully',
                    filePath: filePath || url
                });
            }
        );
    }
);

// Get timetable for semester
app.get('/api/timetable/:semester', authenticateToken, (req, res) => {
    const { semester } = req.params;

    db.get('SELECT * FROM timetables WHERE semester = ?', [semester], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(row || null);
    });
});

// Get digital content for semester
app.get('/api/digital-content/:semester', authenticateToken, (req, res) => {
    const { semester } = req.params;

    db.all('SELECT * FROM digital_content WHERE semester = ? ORDER BY uploaded_at DESC', 
        [semester], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(rows);
        }
    );
});

// ============== ERROR HANDLING ==============

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Database: studentdb.sqlite`);
});