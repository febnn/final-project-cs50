from flask import Flask, render_template
from flask_session import Session

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.route('/')
def index():
    return render_template('main.html')

@app.route('/create')
def create():
    return render_template('task.html')

@app.route('/intro')
def intro():
    return render_template('intro.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/completed')
def completed():
    return render_template('completed.html')