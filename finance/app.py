import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from html import escape
from werkzeug.security import check_password_hash, generate_password_hash

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

    current_user_id = session["user_id"]

    current_username = db.execute(
        "SELECT username FROM users WHERE id = ?",
        current_user_id
    )[0]['username']

    cash_total = db.execute(
        "SELECT cash FROM users WHERE id = ?",
        current_user_id
    )[0]['cash']

    portfolio_total = 0

    # Intialise dict
    stock_index = {}

    symbols_quantities = db.execute(
        "SELECT symbol, quantity FROM portfolios WHERE id = ? AND quantity > 0;",
        current_user_id
    )

    # Loop through query rows
    for entry in symbols_quantities:
        try:
            symbol_info = lookup(entry['symbol'])
        except:
            return apology("unable to lookup stock information")
        total_stock_value = symbol_info['price'] * entry['quantity']

        # Assign symbol to key and second dict to value
        stock_index[entry['symbol']] = {'quantity': entry['quantity'],
                                        'current_price': usd(symbol_info['price']),
                                        'total_value': usd(total_stock_value)
                                        }
        portfolio_total += total_stock_value

    grand_total = cash_total + portfolio_total

    return render_template("index.html", username=current_username, cash_total=usd(cash_total), portfolio_total=usd(portfolio_total), grand_total=usd(grand_total), stocks=stock_index)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # Display buy form
    if request.method == "GET":
        return render_template("buy.html")

    # Submitting buy request
    else:

        # Check symbol input
        symbol_buy = request.form.get("symbol").upper()
        if not symbol_buy or (lookup(symbol_buy) == None):
            return apology("incorrect stock symbol", 400)

        # Sanitise symbol input after lookup to avoid api issues
        symbol_buy = escape(symbol_buy)

        # Check quantity input
        try:
            quantity_buy = int(request.form.get("shares"))
        except:
            return apology("invalid quantity")
        if quantity_buy < 1:
            return apology("invalid quantity")

        # Correct symbol and quantity
        else:

            # Lookup stock price
            current_price_buy = lookup(symbol_buy)["price"]
            price_buy = current_price_buy * quantity_buy

            # Saving user id and user's cash balance
            current_user_id = session["user_id"]
            balance_buy = db.execute(
                "SELECT cash FROM users WHERE id = ?",
                current_user_id
            )[0]['cash']

            # Not enough cash
            if price_buy > balance_buy:
                return apology("not enough cash")

            else:
                # Update user's cash total
                db.execute(
                    "UPDATE users SET cash = ? WHERE id = ?",
                    (balance_buy - price_buy), current_user_id
                )

                # Check if stock already exists in user's portfolio
                stock_existing = db.execute(
                    "SELECT * FROM portfolios WHERE id = ? AND symbol = ?",
                    current_user_id, symbol_buy
                )

                # Stock doesn't exist in portfolio
                if len(stock_existing) != 1:
                    db.execute(
                        "INSERT INTO portfolios (id, symbol, quantity) VALUES (?, ?, ?)",
                        current_user_id, symbol_buy, quantity_buy
                    )
                    db.execute(
                        "INSERT INTO transactions (user_id, symbol, current_price, quantity, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                        current_user_id, symbol_buy, current_price_buy, quantity_buy
                    )
                    flash("Shares purchased successfully!")
                    return redirect("/")

                # Stock exists in portfolio
                else:
                    db.execute(
                        "UPDATE portfolios SET quantity = quantity + ? WHERE id = ? AND symbol = ?",
                        quantity_buy, current_user_id, symbol_buy
                    )
                    db.execute(
                        "INSERT INTO transactions (user_id, symbol, current_price, quantity, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                        current_user_id, symbol_buy, current_price_buy, quantity_buy
                    )
                    flash("Shares purchased successfully!")
                    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    current_user_id = session["user_id"]

    # Intialise dict
    user_transactions = {}

    transactions = db.execute(
        "SELECT transaction_id, symbol, current_price, quantity, timestamp FROM transactions WHERE user_id = ?;",
        current_user_id
    )

    # Loop through query rows
    for transaction in transactions:
        if transaction['quantity'] > 0:
            transaction_type = "Buy"
        else:
            transaction_type = "Sell"
        transaction_total = usd(abs(transaction['current_price'] * transaction['quantity']))

        # Assign symbol to key and second dict to value
        user_transactions[transaction['transaction_id']] = {'type': transaction_type,
                                                            'symbol': transaction['symbol'],
                                                            'quantity': transaction['quantity'],
                                                            'stock_price': usd(transaction['current_price']),
                                                            'total': transaction_total,
                                                            'date_time': transaction['timestamp']
                                                            }

    return render_template("history.html", history=user_transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "GET":
        return render_template("login.html")

    # User reached route via POST (as by submitting a form via POST)
    else:

        # Sanitise user input
        input_username = escape(request.form.get("username"))
        input_password = escape(request.form.get("password"))

        # Ensure username was submitted
        if not input_username:
            return apology("username not provided", 400)

        # Ensure password was submitted
        elif not input_password:
            return apology("password not provided", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?",
            input_username
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], input_password
        ):
            return apology("invalid login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Logged in successfully!")
        return redirect("/")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash("Logged out successfully!")
    return render_template("login.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # Display search for stock
    if request.method == "GET":
        return render_template("quote.html")

    # Requesting quote for submitted symbol
    else:
        quoted = lookup(request.form.get("symbol"))
        if quoted is None:
            return apology("stock not found", 400)
        quoted_symbol = quoted["symbol"]
        quoted_price = usd(quoted["price"])
        return render_template("quote.html", symbol=quoted_symbol, price=quoted_price)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reacher route via POST (by submitting register form via POST
    if request.method == "POST":

        # Sanitising input
        input_username = escape(request.form.get("username"))
        input_password = escape(request.form.get("password"))
        input_confirmation = escape(request.form.get("confirmation"))

        # Checking if username was entered
        if not input_username:
            return apology("please enter a username", 400)

        # Checking if password weas entered
        elif not input_password:
            return apology("please enter a password", 400)

        # Checking if confirmation password was entered
        elif not input_confirmation:
            return apology("please confirm password", 400)

        # Checking password and confirmation password match
        elif input_password != input_confirmation:
            return apology("passwords don't match", 400)

        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                input_username, generate_password_hash(input_password)
            )

        except ValueError:
            return apology("username already exists")

        flash("Registered successfully!")
        return render_template("login.html")
        return redirect("/login")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    current_user_id = session["user_id"]

    # Display sell form
    if request.method == "GET":
        symbols_sell = db.execute(
            "SELECT symbol FROM portfolios WHERE id = ? AND quantity > 0",
            current_user_id
        )
        return render_template("sell.html", symbols=symbols_sell)

    # Submitting sell request
    else:

        symbol_sell = request.form.get("symbol")

        # Sanitised symbol input for db queries
        input_symbol = escape(symbol_sell)

        if not symbol_sell or (lookup(symbol_sell) == None):
            return apology("incorrect stock symbol", 400)

        # Check quantity input
        try:
            quantity_sell = int(request.form.get("shares"))
        except:
            return apology("invalid quantity")
        if quantity_sell < 1:
            return apology("invalid quantity")

        portfolio_existing_quantity = db.execute(
            "SELECT quantity FROM portfolios WHERE id = ? AND symbol = ?",
            current_user_id, input_symbol
        )

        # Stock doesn't exist in portfolio
        if len(portfolio_existing_quantity) != 1:
            return apology("you don't own this stock")

        # Stock exists in portfolio table but user no longer owns it
        if portfolio_existing_quantity[0]['quantity'] < 1:
            return apology("you don't own this stock anymore")

        # User tries to sell more than they own
        if quantity_sell > portfolio_existing_quantity[0]['quantity']:
            return apology("you can't sell more stock than you have...")

        # Update portfolio with new quantity
        db.execute(
            "UPDATE portfolios SET quantity = quantity - ? WHERE id = ? AND symbol = ?",
            quantity_sell, current_user_id, input_symbol
        )

        # Update new cash total
        current_price_sell = lookup(symbol_sell)['price']
        sold_stock_total = current_price_sell * quantity_sell
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            sold_stock_total, current_user_id
        )

        # Add new transaction entry
        db.execute(
            "INSERT INTO transactions (user_id, symbol, current_price, quantity, timestamp) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
            current_user_id, input_symbol, current_price_sell, (quantity_sell - (quantity_sell * 2))
        )

        flash("Shares sold successfully!")
        return redirect("/")


@app.errorhandler(404)
def page_not_found(e):
    """ Error 404 """
    return apology("this page has experienced a market crash...", 404)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user's password"""

    current_user_id = session["user_id"]

    # Redirect user to change password form
    if request.method == "GET":
        return render_template("change_password.html")

    else:

        # Sanitise user input
        input_current_password = escape(request.form.get("current_password"))
        input_new_password = escape(request.form.get("new_password"))
        input_confirm_password = escape(request.form.get("confirmation_new_password"))

        if not input_current_password:
            return apology("missing current password", 400)

        elif not input_new_password:
            return apology("missing new password", 400)

        elif not input_confirm_password:
            return apology("missing password confirmation", 400)

        rows = db.execute(
            "SELECT hash FROM users WHERE id = ?",
            current_user_id
        )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], input_current_password
        ):
            return apology("wrong current password")

        if check_password_hash(
            rows[0]["hash"], input_new_password
        ):
            return apology("you need to enter a new password")

        if input_new_password != input_confirm_password:
            return apology("new passwords do not match")

        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?",
            (generate_password_hash(input_new_password)), current_user_id
        )

        flash("Password changed successfully!")
        return redirect("/")
