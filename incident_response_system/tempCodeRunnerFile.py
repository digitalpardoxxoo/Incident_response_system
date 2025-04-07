from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import mysql.connector
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import io
import xlsxwriter
from scanner import scan_website  # 👀 Now returns both results + autofill data

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # 💡 Change this for production use!

def connect_to_database():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="raghav34soul",
        database="incident_db"
    )

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    db = connect_to_database()
    cursor = db.cursor()
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            flash("Username already exists!")
            return redirect('/register')

        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                       (username, email, password))
        db.commit()
        flash("Account created successfully! Please login.")
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    db = connect_to_database()
    cursor = db.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['scanned'] = False
            session['reported'] = False
            session['autofill'] = None
            return redirect('/scan-url')
        else:
            flash("Invalid credentials")
    return render_template('login.html')

@app.route('/scan-url', methods=['GET', 'POST'])
def scan_url():
    if 'user_id' not in session:
        return redirect('/login')

    results = []
    if request.method == 'POST':
        url = request.form['url']
        scan_output = scan_website(url)

        if "error" in scan_output:
            flash("Scan failed: " + scan_output["error"])
        else:
            results = scan_output["vulnerabilities"]
            session['autofill'] = scan_output["autofill"]
            session['scanned'] = True

    return render_template('scan_url.html', results=results)

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect('/login')

    if not session.get('scanned'):
        flash("Please scan a website before reporting an incident.")
        return redirect('/scan-url')

    db = connect_to_database()
    cursor = db.cursor()

    autofill = session.get('autofill') or {}

    if request.method == 'POST':
        user_id = session['user_id']
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']
        category = request.form['category']
        due_date = request.form['due_date']
        location = request.form['location']
        incident_type = request.form['incident_type']
        department = request.form['department']
        impact_level = request.form['impact_level']
        actions_taken = request.form['actions_taken']

        query = """INSERT INTO incidents 
                   (user_id, title, description, priority, category, due_date, location, 
                   incident_type, department, impact_level, actions_taken) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        cursor.execute(query, (user_id, title, description, priority, category, due_date,
                               location, incident_type, department, impact_level, actions_taken))
        db.commit()

        session['scanned'] = False
        session['reported'] = True
        session['autofill'] = None
        flash("Incident reported successfully!")
        return redirect('/dashboard')

    return render_template('report.html', autofill=autofill)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    if not session.get('reported'):
        flash("Please submit an incident report before viewing the dashboard.")
        return redirect('/report')

    db = connect_to_database()
    cursor = db.cursor()
    user_id = session['user_id']

    cursor.execute("SELECT * FROM incidents WHERE user_id = %s", (user_id,))
    incidents = cursor.fetchall()

    priorities = ['Low', 'Medium', 'High', 'Critical']
    priority_counts = [0, 0, 0, 0]
    for inc in incidents:
        if inc[4] in priorities:
            idx = priorities.index(inc[4])
            priority_counts[idx] += 1

    return render_template('dashboard.html', incidents=incidents, priority_counts=priority_counts)

@app.route('/export-excel')
def export_excel():
    if 'user_id' not in session:
        return redirect('/login')

    db = connect_to_database()
    cursor = db.cursor()
    user_id = session['user_id']

    cursor.execute("SELECT * FROM incidents WHERE user_id = %s", (user_id,))
    incidents = cursor.fetchall()

    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    headers = ['ID', 'User ID', 'Title', 'Description', 'Priority', 'Status', 'Timestamp', 'Category', 'Due Date', 
               'Location', 'Incident Type', 'Department', 'Impact Level', 'Actions Taken']

    for col_num, header in enumerate(headers):
        worksheet.write(0, col_num, header)

    for row_num, incident in enumerate(incidents, start=1):
        for col_num, data in enumerate(incident):
            worksheet.write(row_num, col_num, str(data))

    workbook.close()
    output.seek(0)

    return send_file(output, download_name="incident_report.xlsx", as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!")
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
