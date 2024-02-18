import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import re

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    print('userId', user_id)
    db_purchases = db.execute(
        "SELECT symbol, SUM(shares) as sum_shares FROM transactions WHERE userid = ? GROUP BY symbol", user_id)

    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']
    total_money = user_cash
    updated_purchases = []
    for row in db_purchases:
        print('purchases', row)
        symbol = row["symbol"]
        curr_stock_price = lookup(symbol)["price"]
        shares = row["sum_shares"]
        total = curr_stock_price * shares
        total_money += total
        updated_purchases.append({'symbol': symbol, 'shares': shares, 'price': usd(curr_stock_price), 'total': usd(total)})

    return render_template('index.html', updated_purchases=updated_purchases, user_cash=usd(user_cash), total_money=usd(total_money))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')
        user_id = session["user_id"]

        if not symbol:
            return apology('missing symbol', 400)

        try:
            shares = int(shares)
            if shares <= 0:
                return apology("incorrect number of shares", 400)
        except ValueError:
            return apology('incorrect type of share', 400)

        price = None
        if lookup(symbol):
            price = lookup(symbol)["price"]
        else:
            return apology('symbol not found', 400)

        row = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        curr_deposit = row[0]["cash"]

        curr_purchase = price * shares

        if curr_deposit < curr_purchase:
            return apology('not enough money on deposit', 403)

        db.execute("INSERT INTO transactions (userid, symbol, shares, price) VALUES (?, ? ,?, ?)",
                   user_id, symbol.upper(), shares, price)
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", curr_purchase, user_id)
        return redirect('/')

    return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    history = db.execute("SELECT symbol, shares, price, timestamp FROM transactions WHERE userid = ?", user_id)

    return render_template('history.html', history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
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


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    symbol = request.form.get('symbol')
    price = None

    if request.method == 'POST':
        if not symbol:
            return apology('missing symbol input', 400)
        if not lookup(symbol):
            return apology('symbol has not found', 400)
        else:
            price = lookup(symbol)['price']

        return render_template('quoted.html', symbols=symbol.upper(), price=usd(price))

    return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    username = request.form.get('username')
    password = request.form.get('password')
    repeat_password = request.form.get('confirmation')
    users_in_db = db.execute("SELECT username FROM users")

    if request.method == 'POST':
        if not username:
            return apology('must provide username', 400)

        for user in users_in_db:
            if user['username'] == username:
                return apology('user already exist', 400)

        if not password:
            return apology('must provide password', 400)
        if password != repeat_password:
            return apology('passwords does not match', 400)

        hash = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        return redirect('/login')

    return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    curr_stock = db.execute(
        "SELECT symbol, SUM(shares) as shares FROM transactions WHERE userid = ? and shares > 0 GROUP BY symbol", user_id)

    if request.method == 'POST':
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')

        if not shares or int(shares) < 0:
            return apology('incorrent number of shares', 400)
        for stock in curr_stock:
            if stock['symbol'] == symbol:
                if stock['shares'] < int(shares):
                    return apology('not sufficient shares', 400)

        cur_price = lookup(symbol)['price']
        sell = float(shares) * cur_price

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sell, user_id)
        db.execute("INSERT INTO transactions (userid, symbol, shares, price) VALUES (?, ? ,-?, ?)",
                   user_id, symbol.upper(), shares, cur_price)

        return redirect('/')

    return render_template('sell.html', curr_stock=curr_stock)


@app.route("/top-up", methods=["GET", "POST"])
@login_required
def top_up():
    user_id = session["user_id"]
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]['cash']
    if request.method == 'POST':
        amount = int(request.form.get('amount'))
        if amount < 0:
            return apology('wrong amount', 403)
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", amount, user_id)
        return redirect("/top-up")

    return render_template('top-up.html', user_cash=user_cash)