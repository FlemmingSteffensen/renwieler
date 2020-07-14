import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, getRole

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

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///rw.db")
db.execute("PRAGMA foreign_keys = ON")

@app.route("/")
@login_required
def index():
    """Show available current competition"""
    role = getRole()
    # Get all active competitions
    comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop FROM competitions WHERE reg_active = 'on' AND strftime('%s', reg_stop) > strftime('%s', 'now') ")
    # render the page passing the information to the page
    return render_template("index.html", role=role, comps=comps)


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format (CS50 based, no changes)"""
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

@app.route("/checkRace", methods=["GET"])
def checkRace():
    """Return true if competition is available, else false, in JSON format"""
    racetype = request.args.get("racetype")
    year = request.args.get("year")
    # TODO
    if len(racetype) > 0:
        # Search the database for existing competitions
        comp = db.execute("SELECT id FROM competitions AS C \
                            WHERE C.racetype_id = :racetype AND C.Year = :year", racetype=racetype, year=year)
        # if not found return true
        if not comp:
            return jsonify(True)
        # else return false
        else:
            return jsonify(False)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in (CS50 based, no changes)"""
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
    """Log user out (CS50 based, no changes)"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user (CS50 based, no changes)"""
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
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :pw)",
                   username=request.form.get("username"), pw=pw)
        # Redirect user to home page
        return redirect("/")


@app.route("/chngpw", methods=["GET", "POST"])
@login_required
def chngpw():
    """Change password (CS50 based, no changes)"""
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

@app.route("/frgtpw")
@login_required
def frgtpw():
    """Changes password for the user"""
    #TODO
    # Redirect user to login form
    return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show results from past competitons"""
    #TODO
    # Direct user to history page
    return render_template("history.html")  


@app.route("/myteam", methods=["GET", "POST"])
@login_required
def myteam():
    """Show the current team of the user"""
    if request.method == "GET":
        user_id = session.get("user_id")
        activecomps = db.execute("SELECT c.id, c.startdate, c.racetype_id, c.year, t.id AS team_id \
                                        FROM competitions AS c \
                                        INNER JOIN racetypes AS r ON c.racetype_id = r.id\
                                        INNER JOIN team AS t ON c.id = t.comp_id \
                                            WHERE t.user_id = :user_id \
                                            AND c.reg_active = 'on' \
                                        ORDER BY c.startdate DESC", user_id = user_id)
        riders = db.execute("SELECT r.rider, r.nationality, r.rides_for, tm.team_id, t.comp_id \
                                    FROM riders AS r \
                                    INNER JOIN team_member AS tm ON r.id = tm.rider_id \
                                    INNER JOIN team AS t ON t.id = tm.team_id \
                                        WHERE t.user_id = :user_id \
                                        AND t.comp_id = :activecomps \
                                    ORDER BY tm.rank ASC" , user_id=user_id, activecomps=activecomps[0]["id"])

    # Direct user to my team page
        return render_template("myteam.html", activecomps = activecomps, riders=riders)  


@app.route("/regteam", methods=["GET", "POST"])
@login_required
def regteam():
    """Show the register team page of the current race"""
    if request.method == "GET":
        compid = request.args.get('activecomp', None)
        # Get all the riders of the competition
        riders = db.execute("SELECT id, comp_id, rider, nationality, rides_for, contraint_id, comp_id FROM riders WHERE comp_id = :compid Order by rides_for ASC, rider ASC", compid=compid)
        # Direct user to register team page
        return render_template("regteam.html", riders=riders)

    if request.method == "POST":
        user = session.get("user_id")
        compid = request.form.get("comp")
        team = db.execute("SELECT id FROM team WHERE user_id = :user AND comp_id = :compid", user=user, compid=compid)
        # Ensure that a competition is selected
        if not compid:
            return apology("Please select a competition before registering a team", 400)
        # Ensure that users doesn't already have a team
        elif team:
            return apology("You already have a team", 400)
        else:
            # insert competion in competition table
            db.execute("INSERT INTO team (user_id, comp_id) VALUES (:user, :compid)", user=user, compid=compid)
            teamid = db.execute("SELECT id FROM team WHERE user_id = :user AND comp_id = :compid", user=user, compid=compid)
            team_id = teamid[0]["id"]
            for k in request.form.keys():
                if k.isdigit():
                    db.execute("INSERT INTO team_member (team_id, rider_id) VALUES (:team_id, :rider_id)", team_id=team_id, rider_id=k)
            return render_template("/myteam")

@app.route("/score")
@login_required
def score():
    """Show the scores of the current race"""
    #TODO
    # Direct user to score page
    return render_template("score.html") 


@app.route("/oskar")
@login_required
def oskar():
    """Show blog posts by Oskar"""
    #TODO
    # Redirect user to login form
    return render_template("oskar.html")  

@app.route("/admin")
@login_required
def admin():
    """Show page for administration to users with proper credentials"""
    #if someone requests access to the admin page
    if request.method == "GET":
        #Get the role of the user from de DB
        role = getRole()
        #if the role equals 2 than grant access
        if role==2:
            return render_template("admin.html", role=role) 
        #else deny access
        else: 
            return apology("access denied", 400) 

@app.route("/newComp", methods=["GET", "POST"])
@login_required
# TODO @admin_required
def newComp():
    """Show new competition page"""
    if request.method == "GET":
        return render_template("newcomp.html")
    """register a new competition in the database"""
    if request.method == "POST":
        #Get the role of the user from de DB
        role = getRole()
        # insert competion in competition table
        db.execute("INSERT INTO competitions (racetype_id, year, startdate, reg_active, reg_stop, restdays, racedays) VALUES (:racetype, :year, :startdate, :reg_active, :reg_stop, :restdays, :racedays)",
                   racetype=request.form.get("racetype"), year=request.form.get("year"), startdate=request.form.get("startdate"), reg_active=request.form.get("reg_active"),
                   reg_stop=request.form.get("reg_stop"), restdays=request.form.get("restdays"), racedays=request.form.get("racedays"))
        # Redirect user to home page
        return render_template("admin.html", role=role)

@app.route("/editComp")
@login_required
#TODO @admin_required
def editComp():
    """Show page to edit competitions"""
    #TODO
    # Redirect user to login form
    return render_template("editcomp.html")

@app.route("/editPoints")
@login_required
#TODO @admin_required
def editPoints():
    """Show available competitions for editing points"""
    role = getRole()
    # Get all competitions and sort by startdate
    comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop FROM competitions ORDER BY startdate DESC")
    # render the page passing the information to the page
    return render_template("editPoints.html", role=role, comps=comps)

@app.route("/points")
@login_required
#TODO @admin_required
def points():
    """Show all riders and their points per day"""
    role = getRole()
    compid = request.args.get('activecomp', None)
    # Get all the riders of the competition with their points per day
    riderpoints = db.execute("SELECT ri.rider, po.day1, po.day2, po.day3, po.day4, po.day5, po.day6, po.day7, po.day8, po.day9, po.day10, po.day11, po.day12, po.day13, po.day14, po.day15, po.day16, po.day17, po.day18, po.day19, po.day20, po.day21, po.day22, po.day23, po.day24, po.day25, po.day26, po.day27, po.day28, po.day29, po.day30 FROM riders ri LEFT JOIN points po ON po.rider_id = ri.id WHERE ri.comp_id = :compid ORDER BY ri.rider DESC", compid=compid)
    # Get the number of days for the competition
    daysInComp = db.execute("SELECT racedays FROM competitions WHERE id = :compid", compid=compid)
    # render the page passing the information to the page
    return render_template("points.html", role=role, riderpoints=riderpoints, daysInComp=daysInComp, compid=compid)    

@app.route("/editBlog")
#TODO @admin_required
@login_required
def editBlog():
    """Show page to edit and add blog posts"""
    #TODO
    # Redirect user to login form
    return render_template("editblog.html")

@app.route("/newUser")
@login_required
#TODO @admin_required
def newUser():
    """Show page to edit and add users"""
    #TODO
    # Redirect user to login form
    return render_template("newuser.html")       

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
