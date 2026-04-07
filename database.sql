CREATE DATABASE IF NOT EXISTS srms_db;
USE srms_db;

-- Users table (सर्व यूजर्ससाठी)
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','teacher','student') NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    phone VARCHAR(15),
    address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reset_token VARCHAR(255),
    reset_token_expiry DATETIME
);

-- Students table
CREATE TABLE students (
    student_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNIQUE,
    seat_number VARCHAR(20) UNIQUE NOT NULL,
    roll_number INT,
    class VARCHAR(50),
    section VARCHAR(10),
    academic_year VARCHAR(20),
    father_name VARCHAR(100),
    mother_name VARCHAR(100),
    date_of_birth DATE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Teachers table
CREATE TABLE teachers (
    teacher_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNIQUE,
    employee_id VARCHAR(20) UNIQUE NOT NULL,
    qualification VARCHAR(100),
    experience INT,
    department VARCHAR(100),
    subject_specialization VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Subjects table (optional)
CREATE TABLE subjects (
    subject_id INT PRIMARY KEY AUTO_INCREMENT,
    subject_code VARCHAR(20) UNIQUE NOT NULL,
    subject_name VARCHAR(100) NOT NULL,
    max_marks INT DEFAULT 100,
    pass_marks INT DEFAULT 35,
    class VARCHAR(50),
    semester INT,
    teacher_id INT,
    FOREIGN KEY (teacher_id) REFERENCES teachers(teacher_id) ON DELETE SET NULL
);

-- Results table
CREATE TABLE results (
    result_id INT PRIMARY KEY AUTO_INCREMENT,
    student_id INT NOT NULL,
    subject_id INT NOT NULL,
    marks_obtained DECIMAL(5,2) NOT NULL,
    grade VARCHAR(2),
    status ENUM('PASS','FAIL') DEFAULT 'FAIL',
    exam_term VARCHAR(20),
    exam_year YEAR NOT NULL,
    entered_by INT,
    entered_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_date DATE,
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE,
    FOREIGN KEY (subject_id) REFERENCES subjects(subject_id) ON DELETE CASCADE,
    FOREIGN KEY (entered_by) REFERENCES users(user_id),
    CHECK (marks_obtained BETWEEN 0 AND 100)
);

-- Default admin (password: admin123)
INSERT INTO users (username, email, password_hash, role, full_name) VALUES
('admin', 'admin@srms.edu', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj2N/LHd7q.u', 'admin', 'System Administrator');