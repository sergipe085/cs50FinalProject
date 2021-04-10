from flask import Flask, render_template, request, redirect, session
from flask_session import Session
from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash
from tempfile import mkdtemp
from helpers import login_required

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
Session(app)

db = SQL("sqlite:///database.db")

@app.route("/")
@login_required
def index():
    return "TODO"


@app.route("/register", methods=["GET", "POST"])
def register():

    def post():
        username = request.form.get("username")
        password = request.form.get("password")

        db.execute("INSERT INTO user(username, password) VALUES(?, ?)", username, generate_password_hash(password))
        return redirect("/login")
    def get(msg):
        return render_template("register.html", msg=msg)

    if request.method == "POST": 
        return post()
    return get("")


@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    def post():
        username = request.form.get("username")
        password = request.form.get("password")

        user = db.execute("SELECT * FROM user WHERE username = ?", username)
        if len(user) == 0:
            return "User not found"
        user = user[0]
        if check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            print(user["id"])
            return redirect("/")
    def get(msg):
        return render_template("login.html", msg=msg)

    if request.method == "POST":
        return post()
    return get("")