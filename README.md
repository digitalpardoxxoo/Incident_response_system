YOU WOULD NEED TO CREATE A SQL DATABASE WITH THE NAME-incident_db
change the password in app.py file and create 2 tables named incident and users 
queries for them are-
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    email VARCHAR(100),
    password VARCHAR(255)
);

CREATE TABLE incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    title VARCHAR(255),
    description TEXT,
    priority VARCHAR(50),
    category VARCHAR(100),
    due_date DATE,
    location VARCHAR(100),
    incident_type VARCHAR(100),
    department VARCHAR(100),
    impact_level VARCHAR(50),
    actions_taken TEXT,
    status VARCHAR(50) DEFAULT 'Open',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
