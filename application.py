import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    worth = 0
    # Get the the types of stocks and the number the user currently has
    rows = db.execute("SELECT symbol, nmb_of_shares FROM shares WHERE user_id = :user", user=session["user_id"])
    index = 0
    # for each row line up the values of the stocks, lookup and add the price and format in USD.
    for row in rows:
        price = lookup(row["symbol"])
        shares = int(row["nmb_of_shares"])
        total = (price["price"] * shares)
        total2 = usd(total)
        rows[index]["price"] = usd(price["price"])
        rows[index]["name"] = price["name"]
        rows[index]["shares"] = shares
        rows[index]["total"] = total2
        worth += total
        index += 1
    # Find out the remaining cash of the user and their net worth
    cash = db.execute("SELECT cash FROM users WHERE id = :user", user=session["user_id"])
    cash2 = usd(cash[0]["cash"])
    worth += float(cash[0]["cash"])
    # render the page passing the information to the page
    return render_template("index.html", rows=rows, cash2=cash2, worth=usd(worth))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    if request.method == "POST":
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        # Ensure a quantity was provided
        if not request.form.get("shares"):
            return apology("must provide quantity", 400)
        # Try to cast the quantity to an int
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("must enter a number", 400)
        # make sure the symbols are uppercase
        symbol = request.form.get("symbol").upper()
        # Lookup the stock
        quote = lookup(symbol)
        # check to see if a positive number were entered
        if shares < 1:
            return apology("must enter a positive number", 400)
        # check if the stock exists
        if not quote:
            return apology("Stock not found", 400)
        else:
            # Figure out is the user can afford the purchase
            balance = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
            balance2 = float(balance[0]["cash"])
            total = (quote["price"] * shares)
            # if not enough funds send error
            if total > balance2:
                return apology("Not enough funds")
            else:
                # check to see if the user already owns share with this symbol
                available = db.execute("SELECT id, user_id, nmb_of_shares FROM shares WHERE symbol = :symbol ", symbol=symbol)
                # update if available
                if available:
                    db.execute("UPDATE shares SET nmb_of_shares = :newquant WHERE id = :id",
                               newquant=(available[0]["nmb_of_shares"]+shares), id=available[0]["id"])
                # insert if new
                else:
                    db.execute("INSERT INTO shares (user_id, symbol, nmb_of_shares) VALUES (:user, :symbol, :shares)",
                               user=session["user_id"], symbol=symbol, shares=shares)
                dollar = usd(total)
                # add a transaction to history and update the balance of the user
                db.execute("INSERT INTO history (user_id, symbol, type, quantity, price) VALUES (:user, :symbol, 1, :quantity, :price)",
                           user=session["user_id"], symbol=symbol, quantity=shares, price=dollar)
                db.execute("UPDATE users SET cash = :newbalance WHERE id = :id", newbalance=(balance2-total), id=session["user_id"])
                return redirect("/")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    if len(username) > 0:
        # Search the database for the username
        user = db.execute("SELECT username FROM users WHERE username = :name", name=username)
        # if not found return true
        if not user:
            return jsonify(True)
        # else return false
        else:
            return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT symbol, time, quantity, price FROM history WHERE user_id = :user", user=session["user_id"])
    return render_template("history.html", rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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
    if request.method == "GET":
        return render_template("quote.html")
    if request.method == "POST":
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        else:
            # lookup the stock
            quote = lookup(request.form.get("symbol"))
            # if the stock is unknown send error
            if not quote:
                return apology("Stock not found", 400)
            # else show the stockprice
            else:
                price = usd(quote["price"])
                return render_template("quoted.html", quote=quote, price=price)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        user = db.execute("SELECT username FROM users WHERE username = :name", name=(request.form.get("username")))
        # if found return apology
        if user:
            return apology("User already exists", 400)
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)
        # Ensure password2 was submitted
        if not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)
        # Ensure password and confirmation are the same
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords are not the same", 400)
        # Generate hash
        pw = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        # insert hash in user table
        db.execute("INSERT INTO users (username, hash, cash) VALUES (:username, :pw, 10000.00)",
                   username=request.form.get("username"), pw=pw)
        # Redirect user to home page
        return redirect("/")


@app.route("/chngpw", methods=["GET", "POST"])
@login_required
def chngpw():
    """Change password"""
    if request.method == "GET":
        return render_template("chngpw.html")
    if request.method == "POST":
        # Ensure current password is correct
        rows = db.execute("SELECT * FROM users WHERE id = :userid", userid=session["user_id"])
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("current password is incorrect")
        # Ensure new password was submitted
        if not request.form.get("newpassword"):
            return apology("must provide new password", 400)
        # Ensure confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)
        # Ensure password and confirmation are the same
        if request.form.get("newpassword") != request.form.get("confirmation"):
            return apology("passwords are not the same", 400)
        # generate hash
        pw = generate_password_hash(request.form.get("newpassword"), method='pbkdf2:sha256', salt_length=8)
        # update hash in user table
        db.execute("UPDATE users SET hash=:pw WHERE id=:userid", pw=pw, userid=session["user_id"])
        # Redirect user to home page
        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        rows = db.execute("SELECT symbol FROM shares WHERE user_id = :userid ", userid=session["user_id"])
        return render_template("sell.html", rows=rows)
    if request.method == "POST":
        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        # Ensure a quantity was provided
        if not request.form.get("shares"):
            return apology("must provide quantity", 400)
        # try to cast quantity to an int
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("must enter a number", 400)
        symbol = request.form.get("symbol")
        # lookup the stock
        quote = lookup(symbol)
        # if 0 or negative stocks return error
        if shares < 1:
            return apology("must enter a positive number", 400)
        # is stock is not found return error
        if not quote:
            return apology("Stock not found", 400)
        else:
            # check if the user has stocks of that type
            available = db.execute("SELECT id, user_id, nmb_of_shares FROM shares WHERE symbol = :symbol ", symbol=symbol)
            # send error if not available
            if not available:
                return apology("No stocks available to sell")
            # send error if not enough stocks are available
            if available[0]["nmb_of_shares"] < shares:
                return apology("not enough shares to sell")
            else:
                # Figure out the value of the stocks that should be sold
                total = (quote["price"] * shares)
                # check the current balance
                balance = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
                balance2 = float(balance[0]["cash"])
                # if selling all shares of the same type, delete the entry from the table
                if available[0]["nmb_of_shares"] == shares:
                    db.execute("DELETE FROM shares WHERE id = :id AND symbol = :symbol", id=available[0]["id"], symbol=symbol)
                # Else update the tabel to the correct amount
                else:
                    db.execute("UPDATE shares SET nmb_of_shares = :newquant WHERE id = :id",
                               newquant=(available[0]["nmb_of_shares"]-shares), id=available[0]["id"])
                dollar = usd(total)
                # insert a transaction into history and update the balance of the user
                db.execute("INSERT INTO history (user_id, symbol, type, quantity, price) VALUES (:user, :symbol, 0, :quantity, :price)",
                           user=session["user_id"], symbol=symbol, quantity=-(shares), price=dollar)
                db.execute("UPDATE users SET cash = :newbalance WHERE id = :id", newbalance=(balance2+total), id=session["user_id"])
                return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
