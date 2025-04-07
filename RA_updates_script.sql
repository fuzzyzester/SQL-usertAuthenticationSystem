-- CREATE DATABASE
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'UserManagementDB_HederligeBilar13')
BEGIN
    CREATE DATABASE UserManagementDB_HederligeBilar13;
END;
GO
USE UserManagementDB_HederligeBilar13;
GO

-----------------------------
-- TABLES
-----------------------------

-- USERS TABLE
CREATE TABLE Users (
    user_id INT PRIMARY KEY IDENTITY(1,1),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARBINARY(64) NOT NULL,
    salt VARBINARY(16) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    address VARCHAR(255),
    city VARCHAR(100),
    country VARCHAR(100),
    phone VARCHAR(20),
    verified BIT DEFAULT 0,
    locked_out BIT DEFAULT 0,
    deleted_at DATETIME NULL, 
    created_at DATETIME DEFAULT GETDATE()
);
GO

-- ROLES TABLE
CREATE TABLE Roles (
    role_id INT PRIMARY KEY IDENTITY(1,1),
    role_name VARCHAR(50) UNIQUE NOT NULL
);
GO

-- USER ROLES TABLE 
CREATE TABLE UserRoles (
    user_id INT,
    role_id INT,
    deleted_at DATETIME NULL, 
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES Roles(role_id)
);
GO

-- USER VERIFICATION TABLE
CREATE TABLE UserVerification (
    user_id INT PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    expiration DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
);
GO

-- PASSWORD RESET TABLE
CREATE TABLE PasswordReset (
    user_id INT,
    reset_token VARCHAR(255) UNIQUE NOT NULL,
    expiration DATETIME NOT NULL,
    PRIMARY KEY (user_id, reset_token),
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
);
GO

-- LOGIN ATTEMPTS TABLE
CREATE TABLE LoginAttempts (
    attempt_id INT PRIMARY KEY IDENTITY(1,1),
    user_id INT,
    ip_address VARCHAR(50),
    success BIT,
    attempt_time DATETIME DEFAULT GETDATE(),
    deleted_at DATETIME NULL, 
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
);
GO

-- LOCKOUT TABLE 
CREATE TABLE Lockout (
    user_id INT PRIMARY KEY,
    locked_until DATETIME NOT NULL,
    lock_reason VARCHAR(255) NULL,
    FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
);
GO

-----------------------------
-- INDEXES
-----------------------------

CREATE INDEX idx_users_email ON Users(email);
GO
CREATE INDEX idx_login_attempts_userid ON LoginAttempts(user_id);
GO
CREATE INDEX idx_login_attempts_ip ON LoginAttempts(ip_address);
GO
CREATE INDEX idx_passwordreset_userid ON PasswordReset(user_id);
GO

-- INSERT DEFAULT ROLES (Check before inserting)
IF NOT EXISTS (SELECT 1 FROM Roles WHERE role_name = 'Customer')
    INSERT INTO Roles (role_name) VALUES ('Customer');
GO
IF NOT EXISTS (SELECT 1 FROM Roles WHERE role_name = 'Admin')
    INSERT INTO Roles (role_name) VALUES ('Admin');
GO

-----------------------------
-- STORED PROCEDURES
-----------------------------

-- SP - REGISTER USER
GO
CREATE OR ALTER PROCEDURE RegisterUser
    @p_email VARCHAR(255),
    @p_password_plaintext NVARCHAR(255),
    @p_first_name VARCHAR(100),
    @p_last_name VARCHAR(100),
    @p_address VARCHAR(255),
    @p_city VARCHAR(100),
    @p_country VARCHAR(100),
    @p_phone VARCHAR(20)
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @salt VARBINARY(16) = CRYPT_GEN_RANDOM(16);
    DECLARE @hashed_password VARBINARY(64) = HASHBYTES('SHA2_256', CONVERT(NVARCHAR(4000), @salt) + @p_password_plaintext);
    DECLARE @user_id INT, @default_role_id INT;

    IF EXISTS (SELECT 1 FROM Users WHERE email = @p_email)
    BEGIN
        RAISERROR ('Email already exists', 16, 1);
        RETURN;
    END;

    INSERT INTO Users (email, password_hash, salt, first_name, last_name, address, city, country, phone, verified, locked_out, created_at)
    VALUES (@p_email, @hashed_password, @salt, @p_first_name, @p_last_name, @p_address, @p_city, @p_country, @p_phone, 0, 0, GETDATE());
    
    SET @user_id = SCOPE_IDENTITY();
    SELECT @default_role_id = role_id FROM Roles WHERE role_name = 'Customer';
    INSERT INTO UserRoles (user_id, role_id) VALUES (@user_id, @default_role_id);
END;
GO

-- SP - VERIFY USER EMAIL
GO
CREATE OR ALTER PROCEDURE VerifyUserEmail
    @p_user_id INT, @p_token VARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (SELECT 1 FROM UserVerification WHERE user_id = @p_user_id AND token = @p_token AND expiration > GETDATE())
    BEGIN
        UPDATE Users SET verified = 1 WHERE user_id = @p_user_id;
        DELETE FROM UserVerification WHERE user_id = @p_user_id;
    END;
    ELSE
    BEGIN
        RAISERROR ('Invalid or expired token', 16, 1);
    END;
END;
GO

-- SP- FORGOT PASSWORD 
GO
CREATE OR ALTER PROCEDURE ForgotPassword
    @p_email VARCHAR(255),
    @p_reset_token VARCHAR(255) OUTPUT
AS
BEGIN
    DECLARE @user_id INT;
    SELECT @user_id = user_id FROM Users WHERE email = @p_email;

    IF @user_id IS NULL
    BEGIN
        PRINT 'Error: Email not found.';
        RETURN -1;
    END

    DELETE FROM PasswordReset WHERE user_id = @user_id;
    SET @p_reset_token = NEWID();
    INSERT INTO PasswordReset (user_id, reset_token, expiration)
    VALUES (@user_id, @p_reset_token, DATEADD(HOUR, 24, GETDATE()));
END;
GO

-- SP - SET FORGOTTEN PASSWORD
GO 
CREATE OR ALTER PROCEDURE SetForgottenPassword
    @p_email VARCHAR(255),
    @p_new_password_plaintext NVARCHAR(255),
    @p_reset_token VARCHAR(255)
AS
BEGIN
    DECLARE @user_id INT;

    SELECT @user_id = user_id FROM PasswordReset 
    WHERE reset_token = @p_reset_token AND expiration > GETDATE();

    IF @user_id IS NULL
    BEGIN
        RETURN -1; --invalid/expired token
    END

    
    DECLARE @new_salt VARBINARY(16) = CRYPT_GEN_RANDOM(16);
    DECLARE @new_hashed_password VARBINARY(64) = HASHBYTES('SHA2_256', CONVERT(NVARCHAR(4000), @new_salt) + @p_new_password_plaintext);

    
    UPDATE Users 
    SET password_hash = @new_hashed_password, salt = @new_salt 
    WHERE user_id = @user_id;

    DELETE FROM PasswordReset WHERE user_id = @user_id;

    RETURN 0; -- Success
END;
GO

-- SP- TRY LOGIN 
GO
CREATE OR ALTER PROCEDURE TryLogin
    @p_email VARCHAR(255),
    @p_password_plaintext NVARCHAR(255),
    @p_ip_address VARCHAR(50)
AS
BEGIN

    CREATE TABLE #LoginDebug (
        attempt_time DATETIME DEFAULT GETDATE(),
        user_id INT NULL,
        email VARCHAR(255),
        ip_address VARCHAR(50),
        status_message VARCHAR(100)
    );

    DECLARE @user_id INT, @db_password_hash VARBINARY(64), @salt VARBINARY(16), @input_hashed VARBINARY(64);
    DECLARE @failed_attempts INT, @locked_until DATETIME;

    SELECT @user_id = user_id, @db_password_hash = password_hash, @salt = salt
    FROM Users WHERE email = @p_email;

    IF @user_id IS NULL 
    BEGIN
        INSERT INTO #LoginDebug (email, ip_address, status_message) 
        VALUES (@p_email, @p_ip_address, 'User Not Found');
        RETURN -1;
    END;

    SELECT @locked_until = locked_until FROM Lockout WHERE user_id = @user_id;
    IF @locked_until IS NOT NULL AND @locked_until > GETDATE()
    BEGIN
        INSERT INTO #LoginDebug (user_id, email, ip_address, status_message) 
        VALUES (@user_id, @p_email, @p_ip_address, 'User Locked Out');
        RETURN -2;
    END;

    SET @input_hashed = HASHBYTES('SHA2_256', CONVERT(NVARCHAR(4000), @salt) + @p_password_plaintext);

    IF @db_password_hash = @input_hashed
    BEGIN
    
        INSERT INTO LoginAttempts (user_id, ip_address, success, attempt_time) VALUES (@user_id, @p_ip_address, 1, GETDATE());
        INSERT INTO #LoginDebug (user_id, email, ip_address, status_message) 
        VALUES (@user_id, @p_email, @p_ip_address, 'Login Successful');
        RETURN 0;
    END
    ELSE
    BEGIN
 
        INSERT INTO LoginAttempts (user_id, ip_address, success, attempt_time) VALUES (@user_id, @p_ip_address, 0, GETDATE());

        SELECT @failed_attempts = COUNT(*) FROM LoginAttempts
        WHERE user_id = @user_id AND success = 0 AND attempt_time > DATEADD(MINUTE, -15, GETDATE());

        IF @failed_attempts >= 3 AND NOT EXISTS (SELECT 1 FROM Lockout WHERE user_id = @user_id)
        BEGIN
            INSERT INTO Lockout (user_id, locked_until, lock_reason) VALUES (@user_id, DATEADD(MINUTE, 15, GETDATE()), 'Too many failed login attempts');
            INSERT INTO #LoginDebug (user_id, email, ip_address, status_message) 
            VALUES (@user_id, @p_email, @p_ip_address, 'User Locked Out (Too Many Attempts)');
            RETURN -3;
        END;

        INSERT INTO #LoginDebug (user_id, email, ip_address, status_message) 
        VALUES (@user_id, @p_email, @p_ip_address, 'Login Failed');
        RETURN -4;
    END;

    SELECT * FROM #LoginDebug;
END;
GO

-----------------------------
-- VIEWS
-----------------------------


-- View - LOGIN ATTEMPTS PER IP
GO
CREATE OR ALTER VIEW LoginAttemptsPerIP AS
WITH AttemptStats AS (
    SELECT 
        ip_address,
        COUNT(*) AS total_attempts,
        SUM(CAST(success AS INT)) AS successful_attempts,
        SUM(1 - CAST(success AS INT)) AS failed_attempts,
        MAX(attempt_time) AS last_attempt_time,
        ROUND(AVG(CAST(success AS FLOAT)), 2) AS success_rate -- Optimized Aggregation
    FROM LoginAttempts
    GROUP BY ip_address
)
SELECT *,
    SUM(total_attempts) OVER (ORDER BY last_attempt_time ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cumulative_attempts,
    SUM(successful_attempts) OVER (ORDER BY last_attempt_time ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cumulative_successes,
    SUM(failed_attempts) OVER (ORDER BY last_attempt_time ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS cumulative_failures
FROM AttemptStats;
GO


-- VIEW, USER LOGIN REPORT
GO
CREATE OR ALTER VIEW UserLoginReport AS
SELECT u.email, u.first_name, u.last_name,
       (SELECT MAX(attempt_time) FROM LoginAttempts WHERE user_id = u.user_id AND success = 1) AS senaste_lyckade,
       (SELECT MAX(attempt_time) FROM LoginAttempts WHERE user_id = u.user_id AND success = 0) AS senaste_misslyckade
FROM Users u;
GO

-----------------------------
-- TESTING & VALIDATION
-----------------------------

--measure Execution Time
SET STATISTICS TIME, IO ON;
GO

--insert test users
DECLARE @salt1 VARBINARY(16) = CRYPT_GEN_RANDOM(16);
DECLARE @salt2 VARBINARY(16) = CRYPT_GEN_RANDOM(16);
DECLARE @user1_id INT, @user2_id INT;

INSERT INTO Users (email, password_hash, salt, first_name, last_name, address, city, country, phone, verified, locked_out, created_at)
VALUES 
('erik.nilsson@gmail.com', HASHBYTES('SHA2_256', CONVERT(NVARCHAR(4000), @salt1) + 'Lösenord123@X9!b$2#'), @salt1, 'Erik', 'Nilsson', 'Storgatan 12', 'Stockholm', 'Sweden', '0701234567', 1, 0, GETDATE());

SET @user1_id = SCOPE_IDENTITY(); -- Get user ID

INSERT INTO Users (email, password_hash, salt, first_name, last_name, address, city, country, phone, verified, locked_out, created_at)
VALUES 
('emma.svensson@hotmail.com', HASHBYTES('SHA2_256', CONVERT(NVARCHAR(4000), @salt2) + 'Lösenord456M$7&K!Q4'), @salt2, 'Emma', 'Svensson', 'Björkgatan 5', 'Göteborg', 'Sweden', '0732345678', 1, 0, GETDATE());

SET @user2_id = SCOPE_IDENTITY(); -- Get second user ID
GO

--insert test login attempts
INSERT INTO LoginAttempts (user_id, ip_address, success, attempt_time) 
VALUES ((SELECT user_id FROM Users WHERE email = 'erik.nilsson@gmail.com'), '192.168.1.1', 1, GETDATE());

INSERT INTO LoginAttempts (user_id, ip_address, success, attempt_time) 
VALUES ((SELECT user_id FROM Users WHERE email = 'emma.svensson@hotmail.com'), '192.168.1.2', 0, GETDATE());
GO

--performance Test for TryLogin
EXEC TryLogin 'erik.nilsson@gmail.com', 'WrongPassword', '192.168.1.10';
EXEC TryLogin 'emma.svensson@hotmail.com', 'WrongPassword', '192.168.1.11';
EXEC TryLogin 'erik.nilsson@gmail.com', 'CorrectPassword', '192.168.1.10';
GO

--Check Lockout Efficiency
SELECT * FROM Lockout WHERE user_id = (SELECT user_id FROM Users WHERE email = 'erik.nilsson@gmail.com');
GO

--generate Forgot Password Token and Validate Storage
DECLARE @reset_token VARCHAR(255);
EXEC ForgotPassword 'erik.nilsson@gmail.com', @reset_token OUTPUT;
SELECT 'Generated Reset Token:' AS Info, @reset_token AS Token;
GO

SELECT * FROM PasswordReset WHERE user_id = (SELECT user_id FROM Users WHERE email = 'erik.nilsson@gmail.com');
GO

--index Usage Validation
SELECT * FROM LoginAttempts WHERE user_id = (SELECT user_id FROM Users WHERE email = 'erik.nilsson@gmail.com');
GO

--validate Performance of Views
SELECT * FROM UserLoginReport;
SELECT * FROM LoginAttemptsPerIP ORDER BY last_attempt_time ASC;
GO