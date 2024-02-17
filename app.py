from flask import Flask, render_template

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route('/')
def index():
    return render_template('main.html')

@app.route('/create')
def create():
    return render_template('task.html')

@app.route('/intro')
def intro():
    return render_template('intro.html')