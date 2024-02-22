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

links = [{"in_progress":'/in_progress'}, {'completed': '/completed'}, {'wont_do': '/wont_do'}]


# MAIN PAGE
@app.route('/')
@login_required
def index():
    user_id = session['user_id']
    in_progress = db.execute("SELECT COUNT(id) as count FROM tasks WHERE userid = ? AND status = 'in_progress'", user_id)
    completed = db.execute("SELECT COUNT(id) as count FROM tasks WHERE userid = ? AND status = 'completed'", user_id)
    wont_do = db.execute("SELECT COUNT(id) as count FROM tasks WHERE userid = ? AND status = 'wont_do'", user_id)
    return render_template('main.html', link=links[0], in_progress=in_progress[0]['count'], completed=completed[0]['count'], wont_do=wont_do[0]['count'])

# CREATE PAGE
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    user_id = session['user_id']
    error_title = None
    error_status = None
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        icon = request.form.get('icon')
        if not title:
            error_title = 'error_border'
            return render_template('add_task.html', error_title=error_title)
        db.execute("INSERT INTO tasks (userid, title, description, icon, status) VALUES (?, ?, ?, ?, ?)", user_id, title, description, icon, 'in_progress')
        
        
        return redirect('/')
    return render_template('add_task.html')

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
        
        db.execute('INSERT INTO users (username, hash) VALUES (?, ?)', username.strip(), hash)
        flash('Account has been created')
        
        return redirect('/login')
        
    
    return render_template('register.html', error=error)


# IN PROGRESS PAGE
@app.route('/in_progress')
@login_required
def in_progress():
    user_id = session['user_id']
    in_progress_tasks = db.execute("SELECT id, icon, title FROM tasks WHERE userid = ? AND status = 'in_progress'", user_id)
    return render_template('in_progress.html', in_progress_tasks=in_progress_tasks)

@app.route('/edit/<task_id>', methods=["GET", "POST"])
@login_required
def edit_in_progress_task(task_id):
    error_title = None
    task_details = db.execute("SELECT id, title, description, icon, status FROM tasks WHERE id = ?", task_id)
    if request.method == 'POST':
        title = request.form.get('title')
        if not title:
            error_title = 'error_border'
            return render_template('edit_task.html',task=task_details[0], error_title=error_title)
        description = request.form.get('description')
        icon = request.form.get('icon')
        status = request.form.get('status')

        db.execute("UPDATE tasks SET title = ?, description = ?, icon = ?, status = ? WHERE id = ?", 
                   title, description, icon, status, task_id)
        
        return redirect('/')
        
        
    return render_template('edit_task.html', task=task_details[0])

@app.route('/delete/<task_id>')
@login_required
def delete_task(task_id):
    db.execute("DELETE FROM tasks WHERE id = ?", task_id)
    return redirect('/')

# COMPLETED PAGE
@app.route('/completed')
@login_required
def completed():
    user_id = session['user_id']
    completed_tasks = db.execute("SELECT id, icon, title FROM tasks WHERE userid = ? AND status = 'completed'", user_id)
    return render_template('completed.html', completed_tasks=completed_tasks)

# WONT DO PAGE
@app.route('/wont_do')
@login_required
def wont_do():
    user_id = session['user_id']
    wont_do_tasks = db.execute("SELECT id, icon, title FROM tasks WHERE userid = ? AND status = 'wont_do'", user_id)
    return render_template('wont_do.html', wont_do_tasks=wont_do_tasks)