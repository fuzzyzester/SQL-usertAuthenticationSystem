# SQL-usertAuthenticationSystem
 
# Hederlige Harrys Bilar – Secure SQL Authentication System

This project is a complete, secure **user authentication system** built with **T-SQL** for **Hederlige Harrys Bilar (HHB)**, a fictional car dealership. The system includes user registration, login verification, role management, password recovery, and full security controls such as account lockouts and IP logging.

It follows **industry best practices in SQL database design, security, optimization, and modular procedure-based logic**.

---

## 🔍 Project Overview

**Goal:**  
To design and implement a scalable and secure user authentication system that supports:

- Email-based account verification
- Role-based access control (Admin & Customer)
- Secure password storage (SHA-256 + salting)
- Password recovery with token expiration
- Login attempt logging with IP tracking
- Account lockout on failed login attempts
- Views for login reporting and suspicious behavior

---

## ✅ What I Did

This project demonstrates a full SQL development lifecycle:

### 1. **Database Design**
- Created normalized schema based on authentication best practices
- Designed an ER diagram with primary keys, relationships, and foreign keys
- Created tables:
  - `Users`, `Roles`, `UserRoles`
  - `UserVerification`, `PasswordReset`
  - `LoginAttempts`, `Lockout`

### 2. **Security Implementation**
- Hashed passwords using SHA-256 and unique user-specific salt
- Added support for:
  - Email verification (via tokens)
  - Token expiration for verification and reset links
  - Lockout after 3 failed login attempts within 15 minutes
  - IP-based tracking for login behavior analysis

### 3. **Stored Procedures**
- `RegisterUser`: Handles new account registration and role assignment  
- `VerifyUserEmail`: Activates account via secure email token  
- `TryLogin`: Validates credentials, logs attempts, triggers lockout if needed  
- `ForgotPassword`: Sends password reset token with expiry  
- `SetForgottenPassword`: Validates reset token and updates password  

### 4. **Views & Reports**
- `UserLoginReport`: Summarizes each user's latest login success/failure  
- `LoginAttemptsPerIP`: Tracks login activity per IP using window functions  

### 5. **Performance Optimization**
- Added indexes on commonly searched fields: `email`, `user_id`, `attempt_time`  
- Optimized queries using indexed joins and window functions  
- Tested system with real-life login scenarios to validate behavior and response codes

### 6. **Testing**
- Inserted test users with hashed credentials  
- Simulated successful and failed login attempts  
- Verified lockout enforcement  
- Checked login logs and reporting views  
- Manually unlocked test accounts

---

## 🗂️ Key Features

| Feature                  | Description |
|--------------------------|-------------|
| **Secure Login**         | Uses hashed & salted passwords, validates credentials, and tracks attempts |
| **Role Management**      | Assigns users to roles (Admin, Customer) via `UserRoles` table |
| **Email Verification**   | Requires users to verify via unique token link |
| **Password Reset**       | Generates expirable reset tokens for secure password recovery |
| **Account Lockout**      | Locks account after 3 failed attempts within 15 minutes |
| **IP Logging**           | Tracks login attempts and flags suspicious IP patterns |
| **Reporting Views**      | Real-time login summary by user and by IP |
| **Optimized Performance**| Indexed queries, efficient joins, and materialized reports |

---

## 🧠 Technologies Used

- **SQL Server (T-SQL)**
- Stored Procedures
- Window Functions
- Indexing & Optimization
- Hashing & Salting (SHA-256)
- ER Diagram (Draw.io)

---

## 📄 Files in the Repository

| File | Description |
|------|-------------|
| `RiannaAalto-SQL2-inlämningsuppgift.sql` | All SQL code for database creation, procedures, and views |
| `RiannaAalto_SQL2_HHB_doc2.pdf` | Project documentation with explanation, testing, and future improvements |
| `RiannaAalto_hhb.drawio.pdf` | ER diagram for the authentication system |

---

## 🚀 Future Improvements

| Area | Enhancement |
|------|-------------|
| **Security** | Implement Argon2 or bcrypt for stronger password hashing |
| **Authentication** | Add Two-Factor Authentication (2FA) |
| **Admin Panel** | Build a front-end for managing users, roles, and login history |
| **Scalability** | Shard user table, use replicas, and consider microservices for auth |
| **Monitoring** | Add alerts and logging for brute-force detection and suspicious IPs |

---

## 📌 Summary

This project showcases the creation of a **robust, secure, and scalable authentication system** using advanced SQL practices. It’s ideal for real-world applications such as SaaS platforms, customer portals, and admin panels requiring secure account handling, role-based access, and detailed login reporting.

