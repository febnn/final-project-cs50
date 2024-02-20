from flask import Flask, render_template, session, redirect, flash, request
from flask_session import Session
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///tasks.db")

icons = [
    '/static/clock-svgrepo-com.svg',
    '/static/knowledge-svgrepo-com.svg',
    '/static/e-learning-svgrepo-com.svg',
    '/static/research-svgrepo-com.svg',
    '/static/student-svgrepo-com.svg',
    '/static/schedule-svgrepo-com.svg'
]


# MAIN PAGE
@app.route('/')
@login_required
def index():
    return render_template('main.html')

# CREATE PAGE
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        status = request.form.get('status')
        icon = request.form.get('icon')
        print(icon)
    return render_template('task.html', icons=icons)

# LOGIN PAGE
@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
 
# LOG OUT
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# REGISTER PAGE
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    username = request.form.get('username')
    password = request.form.get('password')
    confirmation = request.form.get('confirmation')
    users_in_db = db.execute('SELECT username FROM users')
    
    if request.method == 'POST':
        if not username:
            error = 'Provide a username'
            return render_template('register.html', error=error)
        for user in users_in_db:
            if user['username'] == username:
                error = 'Username already exists'
                return render_template('register.html', error=error)
        if not password:
            error = 'Prove a password'
            return render_template('register.html', error=error)
        if password != confirmation:
            error = "Passwords doesn't match"
            return render_template('register.html', error=error)
        
        hash = generate_password_hash(password)
        
        db.execute('INSERT INTO users (username, hash) VALUES (?, ?)', username, hash)
        flash('Account has been created')
        
        return redirect('/login')
        
    
    return render_template('register.html', error=error)

# COMPLETED PAGE
@app.route('/completed')
@login_required
def completed():
    return render_template('completed.html')