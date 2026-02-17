from flask import Flask, render_template, request, redirect, session
import sqlite3
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"


# -------------------------
# DATABASE SETUP
# -------------------------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')

    # Income table (linked to user)
    c.execute('''
        CREATE TABLE IF NOT EXISTS income (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            source TEXT,
            amount REAL,
            month TEXT
        )
    ''')

    # Expense table (linked to user)
    c.execute('''
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            category TEXT,
            amount REAL,
            month TEXT
        )
    ''')

    conn.commit()
    conn.close()

init_db()


# -------------------------
# REGISTER
# -------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                      (username, hashed_password))
            conn.commit()
        except:
            return "Username already exists"

        conn.close()
        return redirect('/login')

    return render_template('register.html')


# -------------------------
# LOGIN
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return redirect('/')
        else:
            return "Invalid username or password"

    return render_template('login.html')


# -------------------------
# LOGOUT
# -------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# -------------------------
# HOME (PROTECTED)
# -------------------------
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    c.execute("SELECT * FROM income WHERE user_id=?", (user_id,))
    incomes = c.fetchall()

    c.execute("SELECT * FROM expenses WHERE user_id=?", (user_id,))
    expenses = c.fetchall()

    total_income = sum([row[3] for row in incomes])
    total_expense = sum([row[4] for row in expenses])
    balance = total_income - total_expense

    c.execute("SELECT category, SUM(amount) FROM expenses WHERE user_id=? GROUP BY category", (user_id,))
    data = c.fetchall()

    labels = []
    values = []

    for row in data:
        labels.append(row[0])
        values.append(row[1])

    category_data = json.dumps({
        "labels": labels,
        "values": values
    })

    conn.close()

    return render_template(
        "index.html",
        incomes=incomes,
        expenses=expenses,
        total_income=total_income,
        total_expense=total_expense,
        balance=balance,
        category_data=category_data
    )


# -------------------------
# ADD INCOME
# -------------------------
@app.route('/add_income', methods=['POST'])
def add_income():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    source = request.form['source']
    amount = request.form['amount']
    month = request.form['month']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO income (user_id, source, amount, month) VALUES (?, ?, ?, ?)",
              (user_id, source, amount, month))
    conn.commit()
    conn.close()

    return redirect('/')


# -------------------------
# ADD EXPENSE
# -------------------------
@app.route('/add', methods=['POST'])
def add_expense():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    title = request.form['title']
    category = request.form['category']
    amount = request.form['amount']
    month = request.form['month']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO expenses (user_id, title, category, amount, month) VALUES (?, ?, ?, ?, ?)",
              (user_id, title, category, amount, month))
    conn.commit()
    conn.close()

    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
