// api/index.js - Vercel Serverless Function
// Note: This uses Vercel KV for storage instead of SQLite (serverless compatible)

import { kv } from '@vercel/kv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Helper to create response
function createResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

// Verify JWT token
function verifyToken(authHeader) {
  if (!authHeader) return null;
  const token = authHeader.split(' ')[1];
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Initialize default admin
async function initializeAdmin() {
  const adminExists = await kv.get('user:ADMIN');
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('ADMIN@1234', 10);
    await kv.set('user:ADMIN', {
      username: 'ADMIN',
      password: hashedPassword,
      role: 'staff',
    });
  }
}

// Main handler
export default async function handler(req) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  await initializeAdmin();

  const url = new URL(req.url);
  const path = url.pathname.replace('/api', '');
  const method = req.method;

  try {
    // ============== AUTHENTICATION ROUTES ==============
    
    if (path === '/auth/login' && method === 'POST') {
      const { userType, username, password } = await req.json();

      if (userType === 'staff') {
        const user = await kv.get(`user:${username.toUpperCase()}`);
        if (!user || !(await bcrypt.compare(password, user.password))) {
          return createResponse({ error: 'Invalid credentials' }, 401);
        }

        const token = jwt.sign(
          { username: user.username, role: user.role },
          JWT_SECRET,
          { expiresIn: '24h' }
        );

        return createResponse({ token, user: { username: user.username, role: user.role } });
      }

      if (userType === 'student' || userType === 'parent') {
        let studentRoll;
        
        if (userType === 'student') {
          studentRoll = username.toUpperCase();
        } else {
          // Parent login: parent@XXX
          const lastThree = username.toLowerCase().replace('parent@', '');
          const allStudents = await kv.keys('student:*');
          const studentKey = allStudents.find(async (key) => {
            const student = await kv.get(key);
            return student.roll.slice(-3).toLowerCase() === lastThree;
          });
          
          if (!studentKey) {
            return createResponse({ error: 'User not found' }, 401);
          }
          studentRoll = studentKey.replace('student:', '');
        }

        const student = await kv.get(`student:${studentRoll}`);
        if (!student) {
          return createResponse({ error: 'User not found' }, 401);
        }

        if (student.forgotPasswordRequested === 'requested') {
          return createResponse({ 
            error: 'Password reset pending approval',
            status: 'requested'
          }, 403);
        }

        const deptCode = student.roll.substring(6, 9);
        const defaultPassword = userType === 'student' 
          ? `${deptCode}@1234` 
          : `parent@${student.roll.slice(-3)}1234`;

        const passwordMatch = student.password 
          ? await bcrypt.compare(password, student.password)
          : password === defaultPassword;

        if (!passwordMatch && password !== defaultPassword) {
          return createResponse({ error: 'Invalid password' }, 401);
        }

        if (student.forgotPasswordRequested === 'approved') {
          student.forgotPasswordRequested = 'false';
          await kv.set(`student:${student.roll}`, student);
        }

        const token = jwt.sign(
          { roll: student.roll, name: student.name, role: userType },
          JWT_SECRET,
          { expiresIn: '24h' }
        );

        return createResponse({ 
          token, 
          user: { roll: student.roll, name: student.name, role: userType } 
        });
      }

      return createResponse({ error: 'Invalid user type' }, 400);
    }

    if (path === '/auth/change-password' && method === 'POST') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user) return createResponse({ error: 'Unauthorized' }, 401);

      const { newPassword, confirmPassword } = await req.json();

      if (newPassword !== confirmPassword) {
        return createResponse({ error: 'Passwords do not match' }, 400);
      }

      if (newPassword.length < 6) {
        return createResponse({ error: 'Password must be at least 6 characters' }, 400);
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);

      if (user.role === 'staff') {
        const staffUser = await kv.get(`user:${user.username}`);
        staffUser.password = hashedPassword;
        await kv.set(`user:${user.username}`, staffUser);
      } else {
        const student = await kv.get(`student:${user.roll}`);
        student.password = hashedPassword;
        student.forgotPasswordRequested = 'false';
        await kv.set(`student:${user.roll}`, student);
      }

      return createResponse({ message: 'Password updated successfully' });
    }

    if (path === '/auth/forgot-password' && method === 'POST') {
      const { userType, username } = await req.json();

      if (userType === 'staff') {
        return createResponse({ error: 'Staff must contact system support' }, 400);
      }

      let studentRoll;
      if (userType === 'student') {
        studentRoll = username.toUpperCase();
      } else {
        const lastThree = username.toLowerCase().replace('parent@', '');
        const allStudents = await kv.keys('student:*');
        
        for (const key of allStudents) {
          const student = await kv.get(key);
          if (student.roll.slice(-3).toLowerCase() === lastThree) {
            studentRoll = student.roll;
            break;
          }
        }
      }

      const student = await kv.get(`student:${studentRoll}`);
      if (!student) {
        return createResponse({ error: 'User not found' }, 404);
      }

      student.forgotPasswordRequested = 'requested';
      await kv.set(`student:${student.roll}`, student);

      return createResponse({ 
        message: 'Password reset request submitted',
        status: 'requested'
      });
    }

    if (path.startsWith('/auth/approve-reset/') && method === 'POST') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const roll = path.split('/').pop();
      const student = await kv.get(`student:${roll}`);
      
      if (!student) {
        return createResponse({ error: 'Student not found' }, 404);
      }

      const deptCode = student.roll.substring(6, 9);
      const defaultPassword = `${deptCode}@1234`;
      const hashedPassword = await bcrypt.hash(defaultPassword, 10);

      student.password = hashedPassword;
      student.forgotPasswordRequested = 'approved';
      await kv.set(`student:${student.roll}`, student);

      return createResponse({ message: 'Password reset approved' });
    }

    // ============== STUDENT ROUTES ==============

    if (path === '/students' && method === 'GET') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const studentKeys = await kv.keys('student:*');
      const students = [];
      
      for (const key of studentKeys) {
        const student = await kv.get(key);
        const attendance = await kv.get(`attendance:${student.roll}`) || { totalDays: 0, daysPresent: 0 };
        const attendancePercentage = attendance.totalDays > 0 
          ? ((attendance.daysPresent / attendance.totalDays) * 100).toFixed(2)
          : 0;

        students.push({
          ...student,
          total_days: attendance.totalDays,
          days_present: attendance.daysPresent,
          attendance_percentage: attendancePercentage,
        });
      }

      return createResponse(students);
    }

    if (path.startsWith('/students/') && method === 'GET') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user) return createResponse({ error: 'Unauthorized' }, 401);

      const roll = path.split('/').pop();
      
      if (user.role !== 'staff' && user.roll !== roll) {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const student = await kv.get(`student:${roll}`);
      if (!student) {
        return createResponse({ error: 'Student not found' }, 404);
      }

      const attendance = await kv.get(`attendance:${roll}`) || { totalDays: 0, daysPresent: 0 };
      
      // Get all semester marks
      const marks = {};
      const semesters = ['sem1', 'sem2', 'sem3', 'sem4', 'sem5', 'sem6', 'sem7', 'sem8'];
      for (const sem of semesters) {
        const semMarks = await kv.get(`marks:${roll}:${sem}`);
        marks[sem] = semMarks || {
          int1: null, int2: null, model: null, semFinal: null,
          assignment: null, miniProject: null, rmkNextGen: null
        };
      }

      return createResponse({
        ...student,
        total_days: attendance.totalDays,
        days_present: attendance.daysPresent,
        marks,
      });
    }

    if (path === '/students' && method === 'POST') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const { name, roll, dob, gender, dept, year, currentSemester } = await req.json();

      const exists = await kv.get(`student:${roll}`);
      if (exists) {
        return createResponse({ error: 'Roll number already exists' }, 400);
      }

      const deptCode = roll.substring(6, 9);
      const defaultPassword = `${deptCode}@1234`;
      const hashedPassword = await bcrypt.hash(defaultPassword, 10);

      const student = {
        roll, name, dob, gender, dept, year,
        currentSemester,
        password: hashedPassword,
        forgotPasswordRequested: 'false',
        createdAt: new Date().toISOString(),
      };

      await kv.set(`student:${roll}`, student);
      await kv.set(`attendance:${roll}`, { totalDays: 0, daysPresent: 0 });

      // Initialize marks for all semesters
      const semesters = ['sem1', 'sem2', 'sem3', 'sem4', 'sem5', 'sem6', 'sem7', 'sem8'];
      for (const sem of semesters) {
        await kv.set(`marks:${roll}:${sem}`, {
          int1: null, int2: null, model: null, semFinal: null,
          assignment: null, miniProject: null, rmkNextGen: null
        });
      }

      return createResponse({ 
        message: 'Student created successfully',
        roll,
        defaultPassword
      }, 201);
    }

    if (path.startsWith('/students/') && method === 'PUT') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const roll = path.split('/').pop();
      const student = await kv.get(`student:${roll}`);
      
      if (!student) {
        return createResponse({ error: 'Student not found' }, 404);
      }

      const { name, dob, gender, dept, year, currentSemester } = await req.json();

      student.name = name;
      student.dob = dob;
      student.gender = gender;
      student.dept = dept;
      student.year = year;
      student.currentSemester = currentSemester;
      student.updatedAt = new Date().toISOString();

      await kv.set(`student:${roll}`, student);

      return createResponse({ message: 'Student updated successfully' });
    }

    if (path.startsWith('/students/') && method === 'DELETE') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const roll = path.split('/').pop();
      
      await kv.del(`student:${roll}`);
      await kv.del(`attendance:${roll}`);
      
      const semesters = ['sem1', 'sem2', 'sem3', 'sem4', 'sem5', 'sem6', 'sem7', 'sem8'];
      for (const sem of semesters) {
        await kv.del(`marks:${roll}:${sem}`);
      }

      return createResponse({ message: 'Student deleted successfully' });
    }

    if (path === '/students/password-requests' && method === 'GET') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const studentKeys = await kv.keys('student:*');
      const requests = [];

      for (const key of studentKeys) {
        const student = await kv.get(key);
        if (student.forgotPasswordRequested === 'requested') {
          requests.push({ roll: student.roll, name: student.name });
        }
      }

      return createResponse(requests);
    }

    // ============== ATTENDANCE ROUTES ==============

    if (path.startsWith('/attendance/') && method === 'PUT') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const roll = path.split('/').pop();
      const { totalDays, daysPresent } = await req.json();

      if (daysPresent > totalDays) {
        return createResponse({ error: 'Days present cannot exceed total days' }, 400);
      }

      await kv.set(`attendance:${roll}`, {
        totalDays,
        daysPresent,
        updatedAt: new Date().toISOString(),
      });

      return createResponse({ message: 'Attendance updated successfully' });
    }

    // ============== MARKS ROUTES ==============

    if (path.startsWith('/marks/') && method === 'PUT') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const parts = path.split('/');
      const roll = parts[2];
      const semester = parts[3];

      const { int1, int2, model, semFinal, assignment, miniProject, rmkNextGen } = await req.json();

      await kv.set(`marks:${roll}:${semester}`, {
        int1, int2, model, semFinal,
        assignment, miniProject, rmkNextGen,
        updatedAt: new Date().toISOString(),
      });

      return createResponse({ message: 'Marks updated successfully' });
    }

    // ============== CONTENT ROUTES ==============

    if (path.startsWith('/timetable/') && method === 'GET') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user) return createResponse({ error: 'Unauthorized' }, 401);

      const semester = path.split('/').pop();
      const timetable = await kv.get(`timetable:${semester}`);

      return createResponse(timetable || null);
    }

    if (path === '/timetable' && method === 'POST') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const { semester, fileUrl } = await req.json();

      await kv.set(`timetable:${semester}`, {
        semester,
        file_path: fileUrl,
        uploaded_at: new Date().toISOString(),
      });

      return createResponse({ 
        message: 'Timetable uploaded successfully',
        filePath: fileUrl
      });
    }

    if (path.startsWith('/digital-content/') && method === 'GET') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user) return createResponse({ error: 'Unauthorized' }, 401);

      const semester = path.split('/').pop();
      const content = await kv.get(`content:${semester}`) || [];

      return createResponse(content);
    }

    if (path === '/digital-content' && method === 'POST') {
      const authHeader = req.headers.get('authorization');
      const user = verifyToken(authHeader);
      if (!user || user.role !== 'staff') {
        return createResponse({ error: 'Unauthorized' }, 403);
      }

      const { semester, title, url } = await req.json();

      const existingContent = await kv.get(`content:${semester}`) || [];
      existingContent.push({
        title,
        url,
        uploaded_at: new Date().toISOString(),
      });

      await kv.set(`content:${semester}`, existingContent);

      return createResponse({ 
        message: 'Content uploaded successfully',
        filePath: url
      });
    }

    return createResponse({ error: 'Route not found' }, 404);

  } catch (error) {
    console.error('Error:', error);
    return createResponse({ error: 'Internal server error' }, 500);
  }
}