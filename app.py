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

@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    def get():
        user = db.execute("SELECT * FROM user WHERE id = ?", session["user_id"])[0]
        user["username"] = user["username"].capitalize()

        roles = db.execute("SELECT * FROM role")
        animDelays = []
        for i in range(len(roles)):
            animDelays.append(((i + 1) * 300) + 4500)

        jobs = db.execute("SELECT * FROM job WHERE role_id IN (SELECT role_id FROM user_role WHERE user_id = ?)", session["user_id"])
        jobsAnimDelays = []
        for i in range(len(jobs)):
            jobsAnimDelays.append(((i + 1) * 300) + 1000)
        print(jobsAnimDelays)

        return render_template("index.html", user=user, roles=roles, animDelays=animDelays, jobsAnimDelays=jobsAnimDelays, jobs=jobs)
    def post():
        db.execute("UPDATE user SET first_time = 1 WHERE id = ?", session["user_id"])

        role_id = request.form.get("role_id")
        db.execute("INSERT INTO user_role(user_id, role_id) VALUES(?, ?)", session["user_id"], role_id)

        return get()

    if request.method == "POST":
        return post()
    return get()

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
        else:
            return "Password wrong"
    def get():
        return render_template("login.html")

    if request.method == "POST":
        return post()
    return get()


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/job")
@login_required
def job():
    job_id = request.args.get("job_id")
    job = db.execute("SELECT * FROM job WHERE id = ?", job_id)[0]

    responsabilities = db.execute("SELECT responsability FROM responsabilities WHERE job_id = ?", job_id)
    print(responsabilities)

    return render_template("job.html", job=job, responsabilities=responsabilities)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user_role = int(db.execute("SELECT role_id FROM user_role WHERE user_id = ?", session["user_id"])[0]["role_id"])
    user = db.execute("SELECT * FROM user WHERE id = ?", session["user_id"])[0]

    def get():
        roles = db.execute("SELECT * FROM role")

        return render_template("profile.html", roles=roles, user=user, user_role=user_role)
    def post():
        username = request.form.get("username")
        password = request.form.get("password")
        psw_confirm = request.form.get("psw_confirm")
        role = int(request.form.get("role"))

        if not check_password_hash(user["password"], psw_confirm):
            return render_template("message.html", message="Password confirmation failed!", type="Error")

        if username != "":
            db.execute("UPDATE user SET username = ?", username)
        if password != "" and not check_password_hash(user["password"], password):
            db.execute("UPDATE user SET password = ?", generate_password_hash(password))
        if role != user_role:
            db.execute("UPDATE user_role SET role_id = ? WHERE user_id = ?", role, session["user_id"])

        return render_template("message.html", message="Data Changed", type="Sucess!")

    if request.method == "POST":
        return post()
    return get()


@app.route("/apply", methods=["POST"])
@login_required
def apply():
    job = request.form.get("job")
    db.execute("INSERT INTO applies(job_id, owner_id, user_applied_id) VALUES(?, ?, ?)", job["id"], job["user_id"], session["user_id"])

    return render_template("message.html", message="You're applied to this job! Wait for response.", type="Sucess!") 