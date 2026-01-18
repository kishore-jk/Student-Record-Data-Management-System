// script.js - FULLY UPDATED: Final version with fixes for Login, Registration, Content Upload, Password Approval, and Display Logic.

// --- CONSTANTS ---
const VALID_DEPT_CODES = {
    '100': 'AI & Data Science (AI&DS)',
    '101': 'Cyber Security (CS)',
    '102': 'Computer Science (CSE)', 
    '103': 'Electronics/VLSI (VLSI)',
    '104': 'Electronics & Comm. (ECE)',
};
let STAFF_USERNAME_CHECK = 'ADMIN';
let STAFF_PASSWORD_CHECK = 'ADMIN@1234'; 

const CURRENT_YEAR_LAST_TWO_DIGITS = new Date().getFullYear().toString().substring(2, 4); 
const ALL_SEMESTERS = ['sem1', 'sem2', 'sem3', 'sem4', 'sem5', 'sem6', 'sem7', 'sem8'];

let currentUser = null; 
let currentStudentRoll = null; 
let currentStudentName = null; 
let performanceChartInstance = null; // To hold the chart object

// --- DOM References ---
const loginForm = document.getElementById('loginForm');
const loginScreen = document.getElementById('loginScreen');
const mainApp = document.getElementById('mainApp');
const welcomeMessage = document.getElementById('welcomeMessage');
const staffFormSection = document.getElementById('staffFormSection');
const studentTableBody = document.getElementById('studentTableBody');
const studentTableHeader = document.getElementById('studentTableHeader');
const studentForm = document.getElementById('studentForm');
const rollInput = document.getElementById('roll');
const marksForm = document.getElementById('marksForm');
const marksEntrySection = document.getElementById('marksEntrySection');
const marksStudentNameSpan = document.getElementById('marksStudentName');
const marksStudentRollInput = document.getElementById('marksStudentRoll');
const noRecordsMessage = document.getElementById('noRecords');
const printContainer = document.getElementById('printContainer');
const passwordInput = document.getElementById('password'); 
const togglePasswordButton = document.getElementById('togglePassword');
const semesterSelect = document.getElementById('semesterSelect'); 
const currentSemHeader = document.getElementById('currentSemHeader'); 
const saveMarksBtn = document.getElementById('saveMarksBtn'); 
const chartContainer = document.getElementById('chartContainer'); 
const forgotPasswordBtn = document.getElementById('forgotPasswordBtn');
const forgotPasswordStatus = document.getElementById('forgotPasswordStatus');
const changePasswordBtn = document.getElementById('changePasswordBtn');
const passwordChangeSection = document.getElementById('passwordChangeSection');
const changePasswordForm = document.getElementById('changePasswordForm');
const passwordChangeStatus = document.getElementById('passwordChangeStatus');
const parentViewDetails = document.getElementById('parentViewDetails');
const singleStudentDetailsTable = document.getElementById('singleStudentDetailsTable');
const studentDigitalContent = document.getElementById('studentDigitalContent');
const timetableDisplay = document.getElementById('timetableDisplay');
const digitalContentList = document.getElementById('digitalContentList');
const recordsHeader = document.getElementById('recordsHeader');
const genderInput = document.getElementById('gender');
const adminContentSection = document.getElementById('adminContentSection');
const resetRequestsBody = document.getElementById('resetRequestsBody');
// NEW: Date of Birth DOM Reference
const dobInput = document.getElementById('dob');

// File upload forms
const timetableForm = document.getElementById('timetableForm');
const timetableSemInput = document.getElementById('timetableSem');
const timetableFileInput = document.getElementById('timetableFile');
const digitalContentForm = document.getElementById('digitalContentForm');
const contentSemInput = document.getElementById('contentSem');
const contentTitleInput = document.getElementById('contentTitle');
const contentFileInput = document.getElementById('contentFile');
const contentUrlInput = document.getElementById('contentUrl');


// --- Local Storage Functions ---
function loadStudents() {
    const studentData = localStorage.getItem('students');
    let loadedStudents = studentData ? JSON.parse(studentData) : [];
    loadedStudents = loadedStudents.filter(s => s && s.roll && s.roll.length === 12);
    return loadedStudents;
}

function saveStudents() {
    localStorage.setItem('students', JSON.stringify(students));
}

// Mock Content Storage (Admin managed)
let mockTimetableData = localStorage.getItem('timetable') ? JSON.parse(localStorage.getItem('timetable')) : {};
let mockDigitalContentData = localStorage.getItem('digitalContent') ? JSON.parse(localStorage.getItem('digitalContent')) : {};

function saveContent() {
    localStorage.setItem('timetable', JSON.stringify(mockTimetableData));
    localStorage.setItem('digitalContent', JSON.stringify(mockDigitalContentData));
}

function loadAdminCredentials() {
    const creds = localStorage.getItem('adminCredentials');
    if (creds) {
        const { username, password } = JSON.parse(creds);
        STAFF_USERNAME_CHECK = username;
        STAFF_PASSWORD_CHECK = password;
    }
}

function saveAdminCredentials() {
    localStorage.setItem('adminCredentials', JSON.stringify({
        username: STAFF_USERNAME_CHECK,
        password: STAFF_PASSWORD_CHECK
    }));
}

let students;
try {
    loadAdminCredentials();
    students = loadStudents();
} catch (e) {
    localStorage.removeItem('students');
    localStorage.removeItem('adminCredentials');
    students = [];
}

// --- INITIALIZATION & Event Listeners ---
document.addEventListener('DOMContentLoaded', () => {
    if(studentTableBody) studentTableBody.addEventListener('click', handleTableClicks);
    if (togglePasswordButton) {
        togglePasswordButton.addEventListener('click', togglePasswordVisibility);
    }
    if(forgotPasswordBtn) forgotPasswordBtn.addEventListener('click', handleForgotPassword);
    if(changePasswordBtn) changePasswordBtn.addEventListener('click', () => {
        if(passwordChangeSection) passwordChangeSection.style.display = 'block';
        if(passwordChangeStatus) passwordChangeStatus.textContent = '';
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
    if(changePasswordForm) changePasswordForm.addEventListener('submit', handleChangePassword);
    
    // Admin Content Management Event Listeners
    if (timetableForm) timetableForm.addEventListener('submit', handleTimetableUpload);
    if (digitalContentForm) digitalContentForm.addEventListener('submit', handleDigitalContentUpload);
    
    // Marks Form listener
    if(marksForm) marksForm.addEventListener('submit', handleMarksSubmission);

    checkForgotPasswordStatusDisplay();
    // Only display students if user is staff (to prevent running into errors if user loads page while logged in as staff)
    if (currentUser === 'staff') {
        displayStudents(); 
    }
    
    // Ensure event listeners are attached to the login screen elements
    if(document.getElementById('userType')) document.getElementById('userType').addEventListener('change', checkForgotPasswordStatusDisplay);
    if(document.getElementById('username')) document.getElementById('username').addEventListener('input', checkForgotPasswordStatusDisplay);
});


// Helper to check and display status on login screen
function checkForgotPasswordStatusDisplay() {
    const userType = document.getElementById('userType')?.value;
    const usernameInput = document.getElementById('username')?.value.trim().toUpperCase();
    
    if (!userType || !usernameInput) {
        if(forgotPasswordStatus) forgotPasswordStatus.textContent = '';
        return;
    }
    
    let student;
    if (userType === 'student') {
        student = students.find(s => s.roll === usernameInput);
    } else if (userType === 'parent') {
        const parentId = usernameInput.toLowerCase();
        // Use student roll slice in lowercase for robust comparison
        student = students.find(s => `parent@${s.roll.slice(-3).toLowerCase()}` === parentId);
    }
    
    if(forgotPasswordStatus) {
        if (student && student.forgotPasswordRequested === 'requested') {
            forgotPasswordStatus.textContent = '⚠ Waiting for Admin/Staff approval...';
            forgotPasswordStatus.style.color = '#ff9800';
        } else if (student && student.forgotPasswordRequested === 'approved') {
            forgotPasswordStatus.textContent = '✅ Approved! You can now log in with the default password.';
            forgotPasswordStatus.style.color = 'green';
        } else {
             forgotPasswordStatus.textContent = '';
        }
    }
}


// --- ADMIN CONTENT MANAGEMENT HANDLERS ---
function handleTimetableUpload(e) {
    e.preventDefault();
    if (currentUser !== 'staff') return;
    
    const sem = timetableSemInput.value;
    const file = timetableFileInput.files[0];

    if (!file) {
        alert("Please select a timetable image (JPG/PNG).");
        return;
    }
    
    // NOTE: In a real app, you would save the file to a server/storage, this is a mock path
    const fileIdentifier = `assets/timetables/${file.name}`; // Simulate relative path/URL
    mockTimetableData[sem] = fileIdentifier;
    saveContent();
    alert(`Timetable for Semester ${sem.toUpperCase()} uploaded successfully! (File: ${file.name})`);
    timetableForm.reset();
}

function handleDigitalContentUpload(e) {
    e.preventDefault();
    if (currentUser !== 'staff') return;

    const sem = contentSemInput.value;
    const contentTitle = contentTitleInput.value.trim();
    const file = contentFileInput.files[0];
    const url = contentUrlInput.value.trim();
    
    let contentIdentifier = url;

    if (file) {
        // NOTE: In a real app, you would save the file to a server/storage, this is a mock path
        contentIdentifier = `assets/content/${file.name}`; // Simulate relative path/URL
    } else if (!url) {
        alert("Please select a PDF/DOCX file OR paste a direct link (URL).");
        return;
    }
    
    if (!contentTitle) {
        alert("Please enter a title for the content.");
        return;
    }

    if (!mockDigitalContentData[sem]) {
        mockDigitalContentData[sem] = [];
    }
    
    mockDigitalContentData[sem].push({ title: contentTitle, url: contentIdentifier });
    saveContent();
    alert(`Digital content '${contentTitle}' for Semester ${sem.toUpperCase()} uploaded successfully!`);
    digitalContentForm.reset();
}

// --- STUDENT CONTENT DISPLAY ---
function renderStudentTimetableAndContent(student) {
    if(!timetableDisplay || !digitalContentList) return;
    
    timetableDisplay.innerHTML = '';
    digitalContentList.innerHTML = '';
    
    const currentSem = `sem${student.currentSemester}`; 
    
    // 1. Timetable Display
    const timetableUrl = mockTimetableData[currentSem];
    if (timetableUrl) {
        timetableDisplay.innerHTML = `
            <h4>Timetable for ${currentSem.toUpperCase()}</h4>
            <p style="font-size: 0.9em; color: green; font-weight: 600;">Timetable Available:</p>
            <a href="${timetableUrl}" target="_blank" style="display: block; margin-top: 5px;">View/Download Timetable (${timetableUrl.replace('assets/timetables/', '')})</a>
        `;
    } else {
        timetableDisplay.innerHTML = `<p style="color: #999;">No timetable uploaded for ${currentSem.toUpperCase()}.</p>`;
    }
    
    // 2. Digital Content List
    const content = mockDigitalContentData[currentSem];
    if (content && content.length > 0) {
        let listHtml = '<ul>';
        content.forEach(item => {
            listHtml += `<li><a href="${item.url}" target="_blank">${item.title}</a> (Path/Link: ${item.url.replace('assets/content/', '')})</li>`;
        });
        listHtml += '</ul>';
        digitalContentList.innerHTML = `<h4>Digital Resources for ${currentSem.toUpperCase()}</h4>` + listHtml;
    } else {
        digitalContentList.innerHTML = `<h4>Digital Resources for ${currentSem.toUpperCase()}</h4><p style="color: #999;">No digital content available for ${currentSem.toUpperCase()}.</p>`;
    }
}

// --- PASSWORD TOGGLE ---
function togglePasswordVisibility() {
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        togglePasswordButton.textContent = '🔒'; 
    } else {
        passwordInput.type = 'password';
        togglePasswordButton.textContent = '👁'; 
    }
}

// --- ACTION BUTTON HANDLER ---
function handleTableClicks(event) {
    const target = event.target;
    const button = target.closest('button');

    if (!button || !button.dataset.roll) return; 

    const roll = button.dataset.roll;
    const action = button.dataset.action;

    if (currentUser !== 'staff' && (action === 'marks' || action === 'edit' || action === 'delete' || action === 'approve')) {
        alert("Permission denied. Only Staff/Admin can perform this action.");
        return;
    }

    switch (action) {
        case 'marks':
            showMarksEntry(roll);
            drawPerformanceChart(roll); 
            break;
        case 'edit':
            editStudent(roll);
            break;
        case 'print':
            printStudentReport(roll);
            break;
        case 'delete':
            deleteStudent(roll);
            break;
        case 'approve':
            approvePasswordReset(roll);
            break;
        default:
            console.warn(`Unknown action: ${action}`);
    }
}

// --- FORGOT PASSWORD LOGIC ---
function handleForgotPassword() {
    const userType = document.getElementById('userType').value;
    const usernameInput = document.getElementById('username').value.trim();

    if (userType === 'staff') {
        if(forgotPasswordStatus) {
            forgotPasswordStatus.textContent = 'Staff/Admin: Please contact system support for manual reset.';
            forgotPasswordStatus.style.color = 'red';
        }
        return;
    }

    if (userType !== 'student' && userType !== 'parent') {
        if(forgotPasswordStatus) {
            forgotPasswordStatus.textContent = 'Please select Student or Parent first.';
            forgotPasswordStatus.style.color = 'red';
        }
        return;
    }
    
    let student;
    if (userType === 'student') {
        student = students.find(s => s.roll === usernameInput.toUpperCase());
    } else if (userType === 'parent') {
        const parentId = usernameInput.toLowerCase();
        student = students.find(s => `parent@${s.roll.slice(-3).toLowerCase()}` === parentId);
        
        if (!student) {
             if(forgotPasswordStatus) {
                forgotPasswordStatus.textContent = 'User ID not found.';
                forgotPasswordStatus.style.color = 'red';
            }
             return;
        }
    }
    
    if (!student) {
        if(forgotPasswordStatus) {
            forgotPasswordStatus.textContent = 'User ID not found.';
            forgotPasswordStatus.style.color = 'red';
        }
        return;
    }

    // Set request status to 'requested'
    student.forgotPasswordRequested = 'requested';
    saveStudents();

    if(forgotPasswordStatus) {
        forgotPasswordStatus.textContent = '⚠ Waiting for Admin/Staff approval...';
        forgotPasswordStatus.style.color = '#ff9800';
    }
    displayStudents(); // Refresh admin view to show the request
}

// --- PASSWORD RESET APPROVAL FIX ---
function approvePasswordReset(roll) {
    if (currentUser !== 'staff') return;
    
    const studentIndex = students.findIndex(s => s.roll === roll);
    if (studentIndex > -1) {
        students[studentIndex].forgotPasswordRequested = 'approved';
        
        // CRITICAL FIX: Reset the student's password to the default password immediately upon approval
        students[studentIndex].password = getStudentPassword(students[studentIndex]);

        saveStudents();
        displayStudents(); // Refresh staff view to update the list/remove the request
        alert(`Password reset approved for ${students[studentIndex].name}. They can now log in with their default password.`);
    }
}

// --- CHANGE PASSWORD LOGIC ---
function handleChangePassword(e) {
    e.preventDefault();
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (newPassword !== confirmPassword) {
        if(passwordChangeStatus) {
             passwordChangeStatus.textContent = 'Error: New passwords do not match.';
             passwordChangeStatus.style.color = 'red';
        }
        return;
    }
    
    if (newPassword.length < 6) {
        if(passwordChangeStatus) {
            passwordChangeStatus.textContent = 'Error: Password must be at least 6 characters.';
            passwordChangeStatus.style.color = 'red';
        }
        return;
    }


    if (currentUser === 'staff') {
        STAFF_PASSWORD_CHECK = newPassword;
        saveAdminCredentials();
        if(passwordChangeStatus) passwordChangeStatus.textContent = 'Admin Password updated successfully!';
    } else {
        const student = students.find(s => s.roll === currentStudentRoll);
        if (student) {
            student.password = newPassword;
            student.forgotPasswordRequested = false; 
            saveStudents();
            if(passwordChangeStatus) passwordChangeStatus.textContent = 'Password updated successfully!';
        }
    }
    if(passwordChangeStatus) passwordChangeStatus.style.color = 'green';
    changePasswordForm.reset();
    
    setTimeout(() => {
        if(passwordChangeSection) passwordChangeSection.style.display = 'none';
        if(passwordChangeStatus) passwordChangeStatus.textContent = '';
    }, 2000);
}


// --- PASSWORD HELPERS ---
function getStudentPassword(student) {
    // Robust check for student object integrity
    if (student && student.roll && student.roll.length >= 9) {
        const deptCode = student.roll.substring(6, 9);
        return `${deptCode}@1234`;
    }
    return 'default@1234'; 
}

function getParentPassword(student) {
    if (student && student.roll && student.roll.length >= 3) {
        const lastThreeDigits = student.roll.slice(-3);
        return `parent@${lastThreeDigits}1234`; // Note: This is the default *parent* password, not the username
    }
    return 'parent@0001234';
}

// --- LOGIN LOGIC (FINAL FIXES) ---
if(loginForm) loginForm.addEventListener('submit', handleLogin);

function handleLogin(e) {
    e.preventDefault();
    const userType = document.getElementById('userType').value;
    const usernameInput = document.getElementById('username').value.trim();
    const passwordInput = document.getElementById('password').value.trim();
    
    if(forgotPasswordStatus) forgotPasswordStatus.textContent = ''; 

    if (userType === 'staff') {
        if (usernameInput.toUpperCase() === STAFF_USERNAME_CHECK && passwordInput === STAFF_PASSWORD_CHECK) {
            login('staff', usernameInput.toUpperCase(), 'ADMINISTRATOR');
        } else {
            alert('Invalid Staff Username or Password.');
        }
        return;
    }

    let student;
    let usernameUpper = usernameInput.toUpperCase();
    
    if (userType === 'student') {
        student = students.find(s => s.roll === usernameUpper);
    } else if (userType === 'parent') {
        const parentId = usernameInput.toLowerCase();
        // CRITICAL FIX: Ensure the student roll slice is used in lowercase for the lookup
        // The saved default parent username is parent@XXX, where XXX is roll.slice(-3).toLowerCase()
        student = students.find(s => `parent@${s.roll.slice(-3).toLowerCase()}` === parentId);
        
        if (student && parentId !== `parent@${student.roll.slice(-3).toLowerCase()}`) {
             // This case should ideally not be hit if the student is found using the lookup above, but keeping the format check:
             // Note: The parent username format is parent@XXX (XXX are the last 3 digits of the roll)
        }
    }
    
    if (!student) {
        alert('User ID not found.');
        return;
    }
    
    // Ensure the student object has a 'password' field, initialize it if missing
    if (!student.password) {
        student.password = getStudentPassword(student);
        saveStudents();
    }
    
    let loginSuccess = false;
    // CRITICAL FIX: The default password for parent is different from the student's default password
    let defaultPassword = (userType === 'student') ? getStudentPassword(student) : getParentPassword(student); 
    
    if (student.forgotPasswordRequested === 'requested') {
        if(forgotPasswordStatus) {
            forgotPasswordStatus.textContent = '❌ Login failed. Your request is pending Admin approval.';
            forgotPasswordStatus.style.color = 'red';
        }
        return;
    }
    
    // Check against: 1. Custom/Saved Student Password (for students) OR Default Parent Password (for parents), 2. Default Password
    let savedPasswordCheck = (userType === 'student') ? student.password : defaultPassword;

    if (passwordInput === savedPasswordCheck || passwordInput === defaultPassword) {
        loginSuccess = true;
        
        // If they used the approved default password, clear the approved flag
        if (passwordInput === defaultPassword && student.forgotPasswordRequested === 'approved') {
            student.forgotPasswordRequested = false;
            if(userType === 'student') {
                // Only update the student's saved password to default if they logged in with the default
                student.password = defaultPassword;
            }
            // Note: Parent password is always the default, so no need to save it to the student object
            saveStudents();
        }
    }
    
    if (loginSuccess) {
        login(userType, student.roll, student.name);
    } else {
        alert('Invalid Password.');
    }
}

function logout() {
    currentUser = null;
    currentStudentRoll = null;
    currentStudentName = null;
    if(mainApp) mainApp.style.display = 'none';
    if(loginScreen) loginScreen.style.display = 'flex';
    if(document.getElementById('loginForm')) document.getElementById('loginForm').reset();
    if(marksEntrySection) marksEntrySection.style.display = 'none';
    
    if(chartContainer) chartContainer.style.display = 'none';
    if (performanceChartInstance) performanceChartInstance.destroy();
    
    if(forgotPasswordStatus) forgotPasswordStatus.textContent = '';
    if(passwordChangeStatus) passwordChangeStatus.textContent = '';
}

function login(role, userRoll, displayName) {
    currentUser = role;
    currentStudentRoll = userRoll;
    currentStudentName = displayName;
    
    if(loginScreen) loginScreen.style.display = 'none';
    if(mainApp) mainApp.style.display = 'block';

    if(welcomeMessage) welcomeMessage.innerHTML = `Welcome, **${currentStudentName || userRoll}**. You are logged in as **${role.toUpperCase()}**.`;
    
    // Toggle Sections
    const isStaff = role === 'staff';
    const isStudent = role === 'student';
    const isParent = role === 'parent';
    const isStudentOrParent = isStudent || isParent;
    
    if(staffFormSection) staffFormSection.style.display = isStaff ? 'block' : 'none';
    if(adminContentSection) adminContentSection.style.display = isStaff ? 'block' : 'none';
    if(marksEntrySection) marksEntrySection.style.display = 'none';
    if(passwordChangeSection) passwordChangeSection.style.display = 'none';
    
    // Student/Parent Specific Views
    if(studentDigitalContent) studentDigitalContent.style.display = isStudent ? 'block' : 'none'; // Only Student sees content upload/timetable links
    if(parentViewDetails) parentViewDetails.style.display = isStudentOrParent ? 'block' : 'none';
    if(chartContainer) chartContainer.style.display = isStudentOrParent ? 'block' : 'none';

    if (isStudentOrParent) {
        const student = students.find(s => s.roll === currentStudentRoll);
        if (student) {
            drawPerformanceChart(currentStudentRoll);
            renderSingleStudentDetails(student);
            // Render timetable/content only for the Student role
            if (isStudent) { 
                renderStudentTimetableAndContent(student);
            }
        }
    } else {
        if (performanceChartInstance) performanceChartInstance.destroy();
    }
    
    displayStudents();
}


// --- STUDENT FORM SUBMISSION FIX (Updated for Correct Semester Calculation) ---

if(studentForm) studentForm.addEventListener('submit', function(e) {
    e.preventDefault();
    
    if (currentUser !== 'staff') {
        alert("Session Error: You are not logged in as Staff/Admin. Please re-login.");
        logout();
        return; 
    }

    const nameResult = validateAndFormatName(document.getElementById('name').value);
    if (nameResult.error) { alert(`Validation Error (Name): ${nameResult.error}`); return; }
    const name = nameResult.name; 
    
    const roll = rollInput.value.trim().toUpperCase();
    const gender = genderInput.value;
    // NEW: Get Date of Birth
    const dob = dobInput.value;
    const deptInput = document.getElementById('dept');
    const deptCode = deptInput.value; 
    const deptName = deptInput.options[deptInput.selectedIndex].text; 
    const year = document.getElementById('year').value;
    
    const isEditing = rollInput.disabled;

    if (!roll || !name || !deptCode || !year || !gender || !dob) { alert("Please fill in all student details including Date of Birth."); return; }

    const rollError = validateRollNumber(roll, deptCode);
    if (rollError) { alert(`Validation Error (Roll/Dept): ${rollError}`); return; }

    const yearError = validateAcademicYear(roll, year);
    if (yearError) { alert(`Validation Error (Academic Year): ${yearError}`); return; }
    
    // Check for existence only if not editing
    if (!isEditing && students.some(s => s.roll === roll)) { alert(`Roll Number ${roll} already exists! Please use a unique Roll Number.`); return; }

    const cleanedDeptName = deptName.substring(0, deptName.indexOf('(')).trim();

    // === CRITICAL SEMESTER CALCULATION FIX ===
    const enrollmentYearDigits = parseInt(roll.substring(0, 2));
    const currentYear = new Date().getFullYear();
    const currentYearDigits = parseInt(currentYear.toString().substring(2, 4));
    const currentMonth = new Date().getMonth() + 1; // 1=Jan, 9=Sept (Common start months)

    let activeYear = currentYearDigits - enrollmentYearDigits + 1;
    if (activeYear > 4) activeYear = 4;
    
    let calculatedSemester;
    
    if (year === 'Passed Out') {
        calculatedSemester = 8;
    } 
    // Odd Semesters (Starts in Sept: Month 9)
    else if (currentMonth >= 9) { 
        calculatedSemester = activeYear * 2 - 1;
    } 
    // Even Semesters (Starts in Jan: Month 1)
    else { 
        calculatedSemester = activeYear * 2;
    }
    
    calculatedSemester = Math.max(1, Math.min(8, calculatedSemester));
    
    const currentSemester = calculatedSemester;
    // === END OF CRITICAL SEMESTER CALCULATION FIX ===

    if (!isEditing) {
        const defaultPassword = getStudentPassword({ roll, deptCode });
        const student = {
            name, roll, dob, dept: cleanedDeptName, year, gender, currentSemester,
            attendance: { totalDays: 0, daysPresent: 0 },
            marks: {},
            password: defaultPassword, // Store the calculated default password
            forgotPasswordRequested: false
        };
        
        ALL_SEMESTERS.forEach(sem => {
            student.marks[sem] = { 
                int1: null, int2: null, model: null, semFinal: null, 
                assignment: null, miniProject: null, rmkNextGen: null 
            };
        });
        
        students.push(student);
        alert(`Student ${name} (${roll}) registered successfully! Default Student Password: ${defaultPassword}. Default Parent Username: parent@${roll.slice(-3)}.`);
    } else {
        const studentIndex = students.findIndex(s => s.roll === roll);
        if (studentIndex > -1) {
            students[studentIndex].name = name;
            students[studentIndex].dob = dob; // NEW: Update DOB
            students[studentIndex].dept = cleanedDeptName;
            students[studentIndex].year = year;
            students[studentIndex].gender = gender;
            students[studentIndex].currentSemester = currentSemester; 
            
            const newDeptCode = roll.substring(6, 9);
            const currentDefault = getStudentPassword(students[studentIndex]);
            // Only update the saved password if the student hasn't changed it from the old default
            if(students[studentIndex].password === currentDefault) {
                students[studentIndex].password = getStudentPassword({ roll, deptCode: newDeptCode });
            }
            
            alert(`Student record for ${name} (${roll}) updated successfully!`);
        }
        
        rollInput.disabled = false;
        rollInput.placeholder = "Roll Number (e.g., 111625104001)";
    }

    saveStudents();
    displayStudents();
    studentForm.reset();
});

// --- CORE UTILITY FUNCTIONS ---

function validateAndFormatName(name) {
    name = name.trim().toUpperCase();
    if (name.length < 2) {
        return { error: "Name must be at least 2 characters.", name: null };
    }
    return { error: null, name: name };
}

function validateRollNumber(roll, deptCode) {
    if (roll.length !== 12 || isNaN(roll)) {
        return "Roll number must be exactly 12 digits.";
    }
    const deptPart = roll.substring(6, 9);
    
    if (deptPart !== deptCode) {
        return `Department code in Roll Number (${deptPart}) does not match the selected department code (${deptCode}).`;
    }
    return null;
}

function validateAcademicYear(roll, selectedYear) {
    if (selectedYear === 'Passed Out') return null;
    
    const enrollmentYearDigits = parseInt(roll.substring(0, 2));
    const currentYear = new Date().getFullYear();
    const currentYearDigits = parseInt(currentYear.toString().substring(2, 4));
    const selectedYearInt = parseInt(selectedYear);
    
    let expectedYear = currentYearDigits - enrollmentYearDigits + 1;
    if (expectedYear > 4) expectedYear = 4;
    if (expectedYear < 1) expectedYear = 1;

    if (selectedYearInt > expectedYear) {
        return `Based on the Roll Number's enrollment year, the student should not be in Academic Year ${selectedYear}. Expected max: Year ${expectedYear}.`;
    }
    return null;
}

function getAttendancePercentage(student) {
    if (student.attendance && student.attendance.totalDays > 0) {
        return ((student.attendance.daysPresent / student.attendance.totalDays) * 100).toFixed(2);
    }
    return '0.00';
}

function calculateTotalScore(student, semester) {
    const marks = student.marks[semester];
    if (!marks || marks.int1 === null || marks.semFinal === null) return null; 

    // Internal Marks: Average of Int 1, Int 2, Model (Max 100 each)
    const avgInternal = (marks.int1 + marks.int2 + marks.model) / 3;
    
    // Activities: Assignment (Max 10), Mini Project (Max 5), RMK NextGen (Max 10). Total Max 25.
    const activitiesTotal = marks.assignment + marks.miniProject + marks.rmkNextGen;
    
    // Simplified Total Calculation (Max 100): 
    // Internal Theory (Max 25) + Internal Practical/Activity (Max 25) + Final Exam (Max 50)
    
    const internalTheoryScore = (avgInternal / 100) * 25;
    const internalActivityScore = activitiesTotal; // Max 25
    const finalExamScore = (marks.semFinal / 100) * 50; // Max 50

    return (internalTheoryScore + internalActivityScore + finalExamScore);
}

// --- MARKS ENTRY AND SUBMISSION ---

function showMarksEntry(roll) {
    const student = students.find(s => s.roll === roll);
    if (!student) return;

    if(marksStudentRollInput) marksStudentRollInput.value = roll;
    if(marksStudentNameSpan) marksStudentNameSpan.textContent = student.name;
    if(marksEntrySection) marksEntrySection.style.display = 'block';
    
    // Load attendance
    if(document.getElementById('totalDays')) document.getElementById('totalDays').value = student.attendance.totalDays || '';
    if(document.getElementById('daysPresent')) document.getElementById('daysPresent').value = student.attendance.daysPresent || '';
    
    // Set current semester in the dropdown
    if(semesterSelect) semesterSelect.value = `sem${student.currentSemester}`;
    loadSemesterMarks();
    drawPerformanceChart(roll); // Redraw chart for context
    window.scrollTo({ top: 0, behavior: 'smooth' });
}


function loadSemesterMarks() {
    const roll = marksStudentRollInput.value;
    const sem = semesterSelect.value;
    const student = students.find(s => s.roll === roll);
    
    if (!student) return;
    
    if (!student.marks[sem]) {
        student.marks[sem] = { int1: null, int2: null, model: null, semFinal: null, assignment: null, miniProject: null, rmkNextGen: null };
    }
    const marks = student.marks[sem];
    
    if(currentSemHeader) currentSemHeader.textContent = `${sem.toUpperCase()} Marks`;
    if(saveMarksBtn) saveMarksBtn.textContent = `Save ${sem.toUpperCase()} Records`;
    
    if(document.getElementById('int1')) document.getElementById('int1').value = marks.int1 || '';
    if(document.getElementById('int2')) document.getElementById('int2').value = marks.int2 || '';
    if(document.getElementById('model')) document.getElementById('model').value = marks.model || '';
    if(document.getElementById('assignment')) document.getElementById('assignment').value = marks.assignment || '';
    if(document.getElementById('miniProject')) document.getElementById('miniProject').value = marks.miniProject || '';
    if(document.getElementById('rmkNextGen')) document.getElementById('rmkNextGen').value = marks.rmkNextGen || '';
    if(document.getElementById('semFinal')) document.getElementById('semFinal').value = marks.semFinal || '';
}

if(semesterSelect) semesterSelect.addEventListener('change', loadSemesterMarks);

function handleMarksSubmission(e) {
    e.preventDefault();
    const roll = marksStudentRollInput.value;
    const sem = semesterSelect.value;
    const studentIndex = students.findIndex(s => s.roll === roll);

    if (studentIndex === -1) {
        alert("Student not found.");
        return;
    }

    const student = students[studentIndex];
    
    // 1. Attendance Update
    const totalDays = parseInt(document.getElementById('totalDays').value) || 0;
    const daysPresent = parseInt(document.getElementById('daysPresent').value) || 0;

    if (daysPresent > totalDays) {
        alert("Days present cannot exceed total days.");
        return;
    }
    
    student.attendance.totalDays = totalDays;
    student.attendance.daysPresent = daysPresent;
    
    // 2. Marks Update
    const marks = {
        int1: parseInt(document.getElementById('int1').value) || 0,
        int2: parseInt(document.getElementById('int2').value) || 0,
        model: parseInt(document.getElementById('model').value) || 0,
        semFinal: parseInt(document.getElementById('semFinal').value) || 0,
        assignment: parseInt(document.getElementById('assignment').value) || 0,
        miniProject: parseInt(document.getElementById('miniProject').value) || 0,
        rmkNextGen: parseInt(document.getElementById('rmkNextGen').value) || 0
    };
    
    if (marks.int1 > 100 || marks.int2 > 100 || marks.model > 100 || marks.semFinal > 100 || 
        marks.assignment > 10 || marks.miniProject > 5 || marks.rmkNextGen > 10) {
        alert("Marks validation failed: Check max scores (Int/Model/Final: 100, Assignment: 10, Mini Project: 5, RMK NextGen: 10).");
        return;
    }
    
    student.marks[sem] = marks;
    
    saveStudents();
    alert(`Academic records for ${student.name} (${sem.toUpperCase()}) saved successfully!`);
    
    drawPerformanceChart(roll);
    displayStudents(); 
}

// --- STUDENT TABLE DISPLAY ---

function displayStudents() {
    if (!studentTableBody) return;

    studentTableBody.innerHTML = ''; 
    const isStaff = currentUser === 'staff';
    
    if (!isStaff) return;

    if(recordsHeader) recordsHeader.textContent = '📋 Student Records (Admin View)';
    if(studentTableHeader) studentTableHeader.innerHTML = `
        <th>Roll No</th>
        <th>Name</th>
        <th>Dept</th>
        <th>Year</th>
        <th>Attendance (%)</th>
        <th>Actions</th>
    `;
    
    if (students.length === 0) {
        if(noRecordsMessage) noRecordsMessage.style.display = 'block';
        return;
    }

    students.forEach(student => {
        const attendance = getAttendancePercentage(student);
        const row = document.createElement('tr');
        
        row.innerHTML = `
            <td>${student.roll}</td>
            <td>${student.name}</td>
            <td>${student.dept}</td>
            <td>${student.year}</td>
            <td style="color: ${parseFloat(attendance) < 75 ? 'red' : 'green'}; font-weight: bold;">${attendance}%</td>
            <td>
                <button class="action-btn marks-btn" data-roll="${student.roll}" data-action="marks">Marks/Att</button>
                <button class="action-btn secondary-btn" data-roll="${student.roll}" data-action="edit">Edit</button>
                <button class="action-btn print-btn" data-roll="${student.roll}" data-action="print">Print</button>
                <button class="action-btn delete-btn" data-roll="${student.roll}" data-action="delete">Delete</button>
            </td>
        `;
        studentTableBody.appendChild(row);
    });

    if(noRecordsMessage) noRecordsMessage.style.display = students.length > 0 ? 'none' : 'block';
    
    // Render Reset Requests
    if(resetRequestsBody) {
        resetRequestsBody.innerHTML = '';
        
        const pendingRequests = students.filter(s => s.forgotPasswordRequested === 'requested');
        
        if (pendingRequests.length > 0) {
            let requestsHTML = '';
            pendingRequests.forEach(student => {
                requestsHTML += `
                    <tr>
                        <td>${student.roll} - ${student.name}</td>
                        <td>
                            <button class="action-btn primary-btn" data-roll="${student.roll}" data-action="approve">Approve Reset</button>
                        </td>
                    </tr>
                `;
            });
            resetRequestsBody.innerHTML = requestsHTML;
        } else {
            resetRequestsBody.innerHTML = '<tr><td colspan="2" style="text-align: center;">No pending requests.</td></tr>';
        }
    }
}

// --- STUDENT/PARENT DETAILS VIEW ---

function renderSingleStudentDetails(student) {
    if (!student || !singleStudentDetailsTable) return;

    if(document.getElementById('parentChildName')) document.getElementById('parentChildName').textContent = `Child: ${student.name} (${student.roll})`;
    singleStudentDetailsTable.innerHTML = '';

    const attendancePct = getAttendancePercentage(student);
    
    let html = `
        <tr><th>Name</th><td>${student.name}</td></tr>
        <tr><th>Roll Number</th><td>${student.roll}</td></tr>
        <tr><th>Date of Birth</th><td>${student.dob}</td></tr>
        <tr><th>Department</th><td>${student.dept}</td></tr>
        <tr><th>Academic Year</th><td>${student.year}</td></tr>
        <tr><th>Current Semester</th><td>Semester ${student.currentSemester}</td></tr>
        <tr><th>Attendance (Days Present / Total Days)</th><td>${student.attendance.daysPresent} / ${student.attendance.totalDays}</td></tr>
        <tr><th>Attendance Percentage</th><td style="color: ${parseFloat(attendancePct) < 75 ? 'red' : 'green'}; font-weight: bold;">${attendancePct}%</td></tr>
    `;
    
    const lastSemWithMarks = ALL_SEMESTERS.slice().reverse().find(sem => {
        const marks = student.marks[sem];
        return marks && marks.semFinal !== null;
    }) || 'sem1'; 
    
    const score = calculateTotalScore(student, lastSemWithMarks);

    html += `
        <tr><td colspan="2" style="background-color: #f0f8ff; text-align: center; font-weight: bold; border-top: 3px solid #007bff;">Latest Performance: ${lastSemWithMarks.toUpperCase()}</td></tr>
        <tr><th>Total Percentage (Max 100%)</th><td style="font-weight: bold; color: ${score >= 50 ? 'green' : 'red'};">${score !== null ? score.toFixed(2) + '%' : 'N/A'}</td></tr>
        <tr><th>Status</th><td>${score !== null ? (score >= 50 ? 'PASS' : 'FAIL') : 'Data Missing'}</td></tr>
    `;

    singleStudentDetailsTable.innerHTML = html;
}

// --- CHART.JS INTEGRATION ---

// Requires Chart.js library to be loaded in HTML
function drawPerformanceChart(roll) {
    const student = students.find(s => s.roll === roll);
    if (!student) return;

    if (performanceChartInstance) {
        performanceChartInstance.destroy(); 
    }

    const dataPoints = ALL_SEMESTERS.map(sem => {
        const score = calculateTotalScore(student, sem);
        return score !== null ? parseFloat(score.toFixed(2)) : null;
    });
    
    const semestersLabels = ALL_SEMESTERS.map((sem, index) => `Sem ${index + 1}`);

    const ctx = document.getElementById('performanceChart')?.getContext('2d');
    if (!ctx) return;

    performanceChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: semestersLabels,
            datasets: [{
                label: 'Overall Score Percentage (Max 100%)',
                data: dataPoints,
                backgroundColor: 'rgba(0, 123, 255, 0.2)',
                borderColor: 'rgba(0, 123, 255, 1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Score Percentage (%)'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: `Academic Performance for ${student.name}`,
                    font: { size: 16 }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.parsed.y !== null) {
                                label += context.parsed.y + '%';
                            }
                            return label;
                        }
                    }
                }
            }
        }
    });
}

// --- EDIT/DELETE/PRINT STUBS ---

function editStudent(roll) {
    const student = students.find(s => s.roll === roll);
    if (!student || !rollInput || !document.getElementById('name') || !document.getElementById('gender') || !document.getElementById('year') || !document.getElementById('dept') || !dobInput) return;
    
    rollInput.value = student.roll;
    rollInput.disabled = true; 
    document.getElementById('name').value = student.name;
    document.getElementById('gender').value = student.gender;
    document.getElementById('year').value = student.year;
    dobInput.value = student.dob; // NEW: Set DOB for editing
    
    const deptCode = Object.keys(VALID_DEPT_CODES).find(key => VALID_DEPT_CODES[key].includes(student.dept));
    if (deptCode) {
        document.getElementById('dept').value = deptCode;
    }

    rollInput.placeholder = "Editing Student: Roll Number Disabled";
    alert(`Editing record for ${student.name}. Roll number is disabled.`);
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function deleteStudent(roll) {
    if (confirm(`Are you sure you want to delete the record for student with Roll No: ${roll}? This action cannot be undone.`)) {
        const initialLength = students.length;
        students = students.filter(s => s.roll !== roll);
        if (students.length < initialLength) {
            saveStudents();
            displayStudents();
            alert(`Record for ${roll} deleted successfully.`);
        }
    }
}

function printStudentReport(roll) {
    const student = students.find(s => s.roll === roll);
    if (!student || !printContainer) return;

    let reportHTML = `
        <div class="print-report" style="padding: 20px; font-family: Arial, sans-serif;">
            <h1 style="text-align: center; color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 10px;">STUDENT ACADEMIC REPORT</h1>
            
            <h2 style="font-size: 1.2em; margin-top: 20px; color: #333;">Student Details</h2>
            <table class="report-table" style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <tr><th>Name</th><td>${student.name}</td></tr>
                <tr><th>Roll Number</th><td>${student.roll}</td></tr>
                <tr><th>Date of Birth</th><td>${student.dob}</td></tr>
                <tr><th>Department</th><td>${student.dept}</td></tr>
                <tr><th>Academic Year</th><td>${student.year}</td></tr>
                <tr><th>Current Semester</th><td>Semester ${student.currentSemester}</td></tr>
            </table>

            <h2 style="font-size: 1.2em; margin-top: 20px; color: #333;">Attendance</h2>
            <table class="report-table" style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <tr><th>Total Days</th><td>${student.attendance.totalDays}</td></tr>
                <tr><th>Days Present</th><td>${student.attendance.daysPresent}</td></tr>
                <tr><th>Percentage</th><td>${getAttendancePercentage(student)}%</td></tr>
            </table>

            <h2 style="font-size: 1.2em; margin-top: 20px; color: #333;">Semester Wise Performance</h2>
            <table class="report-table" style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <thead>
                    <tr>
                        <th>Semester</th>
                        <th>Internal (Avg/100)</th>
                        <th>Activity (Total/25)</th>
                        <th>Final Exam (Score/100)</th>
                        <th>Overall % (Max 100%)</th>
                    </tr>
                </thead>
                <tbody>
    `;

    ALL_SEMESTERS.forEach((sem, index) => {
        const marks = student.marks[sem];
        let score = calculateTotalScore(student, sem);
        
        if (marks && marks.int1 !== null && marks.semFinal !== null) {
            const avgInternal = (marks.int1 + marks.int2 + marks.model) / 3;
            const activitiesTotal = marks.assignment + marks.miniProject + marks.rmkNextGen;
            
            reportHTML += `
                <tr>
                    <td>Sem ${index + 1}</td>
                    <td>${avgInternal.toFixed(0)}</td>
                    <td>${activitiesTotal}</td>
                    <td>${marks.semFinal}</td>
                    <td style="font-weight: bold; color: ${score >= 50 ? 'green' : 'red'};">${score.toFixed(2)}%</td>
                </tr>
            `;
        } else {
            reportHTML += `
                <tr>
                    <td>Sem ${index + 1}</td>
                    <td colspan="4">No Data Recorded</td>
                </tr>
            `;
        }
    });

    reportHTML += `
                </tbody>
            </table>
            <p style="text-align: right; margin-top: 30px;">Report Generated: ${new Date().toLocaleDateString()}</p>
        </div>
    `;

    printContainer.innerHTML = reportHTML;
    window.print();
}