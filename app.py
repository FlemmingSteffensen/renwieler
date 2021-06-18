import os
import csv

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from flask_table import Table, Col, create_table, OptCol, ButtonCol
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, getRole, getResults

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
#app.config["SESSION_FILE_DIR"] = mkdtemp()
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
    # Get all active competitions for registration
    comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop FROM competitions WHERE reg_active = 'on' AND strftime('%s', reg_stop) > strftime('%s', 'now') ")
    if comps:
        # render the page passing the competition to the page
        return render_template("index.html", role=role, comps=comps)
    # Get all active competitions after registration
    comps2 = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays FROM competitions WHERE reg_active = 'on' AND strftime('%s', reg_stop) < strftime('%s', 'now') ")
    if comps2:

        # get all the data for the current competition
        allteams, standingscomplete, chartTotals, chartCumulatives = getResults(comps2)[0:4]
        
        # render the page passing the competition and teams to the page
        return render_template("index.html", role=role, comps2=comps2, allteams=allteams, standings=standingscomplete, chartTotals=chartTotals, chartCumulatives=chartCumulatives)
    # in all other cases show the list of winners
    else:
        winTDF = db.execute("SELECT c.year, u.username FROM users u INNER JOIN team t ON u.id = t.user_id INNER JOIN medals m ON t.id = m.team_id INNER JOIN competitions c ON c.id = m.comp_id WHERE m.medal = 1 AND c.racetype_id = 1 ORDER BY c.year")
        winGDI = db.execute("SELECT c.year, u.username FROM users u INNER JOIN team t ON u.id = t.user_id INNER JOIN medals m ON t.id = m.team_id INNER JOIN competitions c ON c.id = m.comp_id WHERE m.medal = 1 AND c.racetype_id = 2 ORDER BY c.year")
        winVE = db.execute("SELECT c.year, u.username FROM users u INNER JOIN team t ON u.id = t.user_id INNER JOIN medals m ON t.id = m.team_id INNER JOIN competitions c ON c.id = m.comp_id WHERE m.medal = 1 AND c.racetype_id = 3 ORDER BY c.year")
        # Prepare a table to hold the winners
        class Winners(Table):
            year = Col('Year', column_html_attrs={'class': 'year'})
            username = Col('Winner', column_html_attrs={'class': 'winner'})
            classes = ['winner', 'table', 'table-lg']   
        # add the winners to tables
        winnersTDF = Winners(winTDF)
        winnersGDI = Winners(winGDI)
        winnersVE = Winners(winVE)
        # render the page passing the winners of previous competitions
        return render_template("index.html", role=role, winnersTDF=winnersTDF, winnersGDI=winnersGDI, winnersVE=winnersVE)

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
        # Check if user is approved
        if rows[0]["approved"] != 1:
            return apology("Your account is not approved yet", 400)
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

@app.route("/rules")
@login_required
def rules():
    """Show rules of the current race (hard coded for now)"""
    # Direct user to rules page
    return render_template("rules.html") 


@app.route("/history")
@login_required
def history():
    """Show results from past competitons"""
    role = getRole()
    # Get all competitions and sort by startdate
    comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop FROM competitions WHERE reg_active = 'off' ORDER BY startdate DESC")
    winners = db.execute("SELECT m.comp_id, u.username FROM medals m INNER JOIN team t ON m.team_id = t.id INNER JOIN users u ON t.user_id = u.id WHERE m.medal=1")
    print(winners)
    # Direct user to history page
    return render_template("history.html", role=role, comps=comps, winners=winners)  


@app.route("/archive")
@login_required
def archive():
    """Show results from selected competiton"""
    role = getRole()
    compid = request.args.get('activecomp', None)
    comps2 = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays FROM competitions WHERE id = :compid", compid=compid)
    # get all the data for the chosen competition
    allteams, standingscomplete, chartTotals, chartCumulatives = getResults(comps2)[0:4]      
    # render the page passing the competition and teams to the page
    return render_template("archive.html", role=role, comps2=comps2, allteams=allteams, standings=standingscomplete, chartTotals=chartTotals, chartCumulatives=chartCumulatives)


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
        if activecomps:
            canRegisterOrEdit = db.execute("SELECT id FROM competitions WHERE reg_active = 'on' AND strftime('%s', reg_stop) > strftime('%s', 'now') ")
            riders = db.execute("SELECT r.rider, r.nationality, r.rides_for, tm.team_id, r.price, t.comp_id \
                                        FROM riders AS r \
                                        INNER JOIN team_member AS tm ON r.id = tm.rider_id \
                                        INNER JOIN team AS t ON t.id = tm.team_id \
                                            WHERE t.user_id = :user_id \
                                            AND t.comp_id = :activecomps \
                                        ORDER BY tm.rank ASC" , user_id=user_id, activecomps=activecomps[0]["id"])
            # Direct user to my team page
            return render_template("myteam.html", activecomps = activecomps, riders=riders, canRegisterOrEdit=canRegisterOrEdit)  
        else:
            # Direct user to my team page without a team
            noteam = 1
            return render_template("myteam.html", noteam=noteam)


@app.route("/editteam", methods=["GET", "POST"])
@login_required
def editteam():
    """Show the editteam page of the current race"""
    if request.method == "GET":
        # Get the user_id to find his/her team for the current race
        user_id = session.get("user_id")
        # Get the current team_id and competition_id
        editTeamID = db.execute("SELECT c.id, c.total_price, t.id AS team_id \
                                        FROM competitions AS c \
                                        INNER JOIN racetypes AS r ON c.racetype_id = r.id\
                                        INNER JOIN team AS t ON c.id = t.comp_id \
                                            WHERE t.user_id = :user_id \
                                            AND c.reg_active = 'on'", user_id = user_id)
        if editTeamID:
            team_id = editTeamID[0]["team_id"]        
        else:
            team_id = None
        # Get the ID and total price for active competition
        activecomp = db.execute("SELECT ID, total_price FROM competitions WHERE reg_active = 'on'")
        activecomp_ID = activecomp[0]["id"]
        total_price = activecomp[0]["total_price"]
        # Get all the riders of the competition
        allRiders = db.execute("Select id, comp_id, rider, nationality, rides_for, price, comp_id \
                                    FROM riders \
                                    WHERE comp_id = :activecomp_ID \
                                    Order by rides_for ASC, rider ASC", activecomp_ID=activecomp_ID)
        # Get the riders with info of the users team
        teamRiders = db.execute("SELECT r.rider, r.nationality, r.rides_for, tm.rank, tm.team_id, t.comp_id \
                                    FROM riders AS r \
                                    INNER JOIN team_member AS tm ON r.id = tm.rider_id \
                                    INNER JOIN team AS t ON t.id = tm.team_id \
                                        WHERE t.user_id = :user_id \
                                        AND t.comp_id = :activecomp_ID \
                                    ORDER BY tm.rank ASC" , user_id=user_id, activecomp_ID=activecomp_ID)
        # Gather the prices of all riders
        rider_price = {}
        for rider in allRiders:
            rider_price[rider["rider"]] = rider["price"]
        jsonify(rider_price)
        # Send team riders and competition riders to the html template
        return render_template("editteam.html", teamRiders=teamRiders, allRiders = allRiders, activecomp_ID=activecomp_ID, team_id=team_id, total_price=total_price, rider_price=rider_price)
    """Edit/update/insert the current team"""
    if request.method == "POST":
        user = session.get("user_id")
        compid = request.form.get("comp")
        team_id = request.form.get("team_id")
        # Update the current team
        if team_id.isnumeric():
            # Ensure that a competition is selected
            if not compid:
                return apology("Please select a competition before registering a team", 400)
            else:
                # update riders in team
                for k,v in request.form.items():
                    if k.isdigit():
                        if v.isdigit():
                            f = int(v)
                            if f > 0: 
                                db.execute("UPDATE team_member SET rider_id = :rider_id WHERE team_id = :team_id AND rank = :rank", rider_id=k, team_id=team_id, rank=f)
                return redirect("/myteam")
        # Insert a new team
        else:
            # insert competion in competition table
            db.execute("INSERT INTO team (user_id, comp_id) VALUES (:user, :compid)", user=user, compid=compid)
            teamid = db.execute("SELECT id FROM team WHERE user_id = :user AND comp_id = :compid", user=user, compid=compid)
            team_id = teamid[0]["id"]
            for k,v in request.form.items():
                if k.isdigit():
                    if v.isdigit():
                        f = int(v)
                        if f > 0: 
                            db.execute("INSERT INTO team_member (team_id, rider_id, rank) VALUES (:team_id, :rider_id, :rank)", team_id=team_id, rider_id=k, rank=f)
            return redirect("/myteam")


@app.route("/addTeamAdmin", methods=["GET", "POST"])
@login_required
def addTeamAdmin():
    """Show page for adding teams to users with proper credentials"""
    #if someone requests access to the admin page
    if request.method == "GET":
        #Get the role of the user from de DB
        role = getRole()
        #if the role equals 2 than grant access
        if role==2:
            compid = request.args.get('activecomp', None)
            comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays, reg_active, total_price FROM competitions WHERE id = :compid", compid=compid)
            currentTeams = db.execute("SELECT users.username \
                                        FROM users      \
                                        INNER JOIN team ON users.id = team.user_id \
                                        WHERE comp_id = :compid \
                                        ORDER BY users.username ASC", compid=compid)
            newTeamUser = db.execute("SELECT users.username, users.id \
                                        FROM users      \
                                        WHERE users.id NOT IN (SELECT team.user_id \
                                                                FROM team \
                                                                WHERE team.comp_id = :compid)    \
                                        ORDER BY users.username ASC", compid=compid)
            allRiders = db.execute("Select id, comp_id, rider, nationality, price, rides_for \
                                    FROM riders \
                                    WHERE comp_id = :activecomp_ID \
                                    Order by rides_for ASC, rider ASC", activecomp_ID=compid)
            # Gather the prices of all riders
            rider_price = {}
            for rider in allRiders:
                rider_price[rider["rider"]] = rider["price"]
            jsonify(rider_price)
            return render_template("addTeamAdmin.html", comps=comps, role=role, currentTeams=currentTeams, newTeamUser=newTeamUser, allRiders=allRiders, rider_price=rider_price)
        #else deny access
        else: 
            return apology("access denied", 400)

    if request.method == "POST":
        user = request.form.get("user_id")
        compid = request.form.get("comp")
        # Insert a new team
        # insert competion in competition table
        # db.execute("INSERT INTO team (user_id, comp_id) VALUES (:user, :compid)", user=user, compid=compid)
        # teamid = db.execute("SELECT id FROM team WHERE user_id = :user AND comp_id = :compid", user=user, compid=compid)
        # team_id = teamid[0]["id"]
        # for k,v in request.form.items():
        #     if k.isdigit():
        #         if v.isdigit():
        #             f = int(v)
        #             if f > 0: 
        #                 db.execute("INSERT INTO team_member (team_id, rider_id, rank) VALUES (:team_id, :rider_id, :rank)", team_id=team_id, rider_id=k, rank=f)
        return redirect("/addTeamAdmin")

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


@app.route("/addteam")
@login_required
# TODO @admin_required
def addteam():
    """Show page for adding teams to users with proper credentials"""
    #if someone requests access to the admin page
    if request.method == "GET":
        #Get the role of the user from de DB
        role = getRole()
        #if the role equals 2 than grant access
        if role==2:
            return render_template("addteam.html", role=role) 
        #else deny access
        else: 
            return apology("access denied", 400)


@app.route("/newComp", methods=["GET", "POST"])
@login_required
# TODO @admin_required
def newComp():
    """Show new competition page"""
    if request.method == "GET":
        #Get the role of the user from de DB
        role = getRole()
        return render_template("newcomp.html", role=role)
    """register a new competition in the database"""
    if request.method == "POST":
        #Get the role of the user from de DB
        role = getRole()
        # insert competion in competition table
        active = request.form.get("reg_active")
        if active != "on":
            active = "off"
        db.execute("INSERT INTO competitions (racetype_id, year, startdate, reg_active, reg_stop, racedays, total_price) VALUES (:racetype, :year, :startdate, :reg_active, :reg_stop, :racedays, :total_price)",
                   racetype=request.form.get("racetype"), year=request.form.get("year"), startdate=request.form.get("startdate"), reg_active=active,
                   reg_stop=request.form.get("reg_stop"), racedays=request.form.get("racedays"), total_price=request.form.get("total_price"))
        # Redirect user to home page
        return render_template("admin.html", role=role)

@app.route("/editComp", methods=["GET", "POST"])
@login_required
#TODO @admin_required
def editComp():
    """Show page to edit competitions"""
    if request.method == "GET":
        #Get the role of the user from de DB
        role = getRole()
        compid = request.args.get('activecomp', None)
        comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays, reg_active, total_price FROM competitions WHERE id = :compid", compid=compid)
        return render_template("editComp.html", comps=comps, role=role)
    """register a new competition in the database"""
    if request.method == "POST":
        #Get the role of the user from de DB
        role = getRole()
        compid = request.form.get('compid')
        active = request.form.get("reg_active")
        if active != "on":
            active = "off"
        db.execute("UPDATE competitions SET startdate = :startdate, reg_active = :reg_active, reg_stop = :reg_stop, racedays = :racedays, total_price = :total_price WHERE id = :compid",
                   startdate=request.form.get("startdate"), reg_active=active, total_price=request.form.get("total_price"),
                   reg_stop=request.form.get("reg_stop"), racedays=request.form.get("racedays"), compid=compid)
        # Redirect user to admin page
        return render_template("admin.html", role=role)

@app.route("/uploadRiders", methods=["GET", "POST"])
@login_required
#TODO @admin_required
def uploadRiders():
    """show page to upload riders file"""
    if request.method == "GET":
        #Get the role of the user from de DB
        role = getRole()
        compid = request.args.get('activecomp', None)
        comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays, reg_active FROM competitions WHERE id = :compid", compid=compid)
        riders = db.execute("SELECT id, rider, nationality, rides_for, price FROM riders WHERE comp_id = :compid", compid=compid)
        return render_template("uploadRiders.html", comps=comps, role=role, riders=riders)
    """process the uploaded file"""
    if request.method == "POST":
        compid = request.form.get("compid")
        file = request.files['file']
        str_file_value = file.read().decode('utf-8')
        file_t = str_file_value.splitlines()
        csv_reader = csv.reader(file_t, delimiter=',')
        for row in csv_reader:
            rowRider = db.execute("SELECT id FROM riders WHERE rider = :rider AND comp_id = :compid", rider=row[0], compid=compid)
            if rowRider:
                db.execute("UPDATE riders SET rider = :rider, nationality = :nationality, rides_for = :rides_for WHERE id = :id", rider=row[0], nationality=row[1], rides_for=row[2], id=rowRider[0]["id"])
            else:
                db.execute("INSERT INTO riders (rider, comp_id, nationality, rides_for) VALUES (:rider, :compid, :nationality, :rides_for)", rider=row[0], nationality=row[1], rides_for=row[2], compid=compid)
        return redirect(url_for('uploadRiders', activecomp=compid))

@app.route("/newRider", methods=["POST"])
@login_required
#TODO @admin_required
def newRider():
    """insert a new rider for the competition"""
    db.execute("INSERT INTO riders (rider, comp_id, nationality, rides_for, price) VALUES (:rider, :compid, :nationality, :rides_for, :price)", rider=request.form.get("rider"), nationality=request.form.get("nationality"), rides_for=request.form.get("rides_for"), price=request.form.get("price"), compid=request.form.get("compid"))    # reload new user screen
    compid = request.form.get("compid")
    return redirect(url_for('uploadRiders', activecomp=compid))

@app.route("/updateRider", methods=["POST"])
@login_required
#TODO @admin_required
def updateRider():
    """update the rider for the competition"""
    db.execute("UPDATE riders SET rider = :rider, nationality = :nationality, rides_for = :rides_for, price = :price WHERE id = :id", rider=request.form.get("rider"), id=request.form.get("rider_id"), nationality=request.form.get("nationality"), rides_for=request.form.get("rides_for"), price=request.form.get("price"))
    compid = request.form.get("compid")
    # reload new user screen
    return redirect(url_for('uploadRiders', activecomp=compid))

@app.route("/winners", methods=["GET"])
@login_required
#TODO @admin_required
def winners():
    """show a page to display the current winners of the competition"""
    if request.method == "GET":
        #Get the role of the user from de DB
        role = getRole()
        compid = request.args.get('activecomp', None)
        comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays, reg_active FROM competitions WHERE id = :compid", compid=compid)        
        winQuery = db.execute("SELECT u.username, m.medal FROM users u INNER JOIN team t ON u.id = t.user_id INNER JOIN medals m ON t.id = m.team_id WHERE t.comp_id = :compid", compid=compid)
        class Winners(Table):
            username = Col('Username', column_html_attrs={'class': 'user'})
            medal = Col('Medal', column_html_attrs={'class': 'medal'})
            classes = ['medals', 'table', 'table-lg']   

        winners = Winners(winQuery)
        return render_template("winners.html", comps=comps, role=role, winners=winners)

@app.route("/calcWin", methods=["POST"])
@login_required
#TODO @admin_required
def calcWin():
    """insert the medaling teams in the medals table"""
    compid = request.form.get("compid")
    medals = db.execute("SELECT id FROM medals WHERE comp_id = :compid", compid=compid)
    if not medals:
        comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays, reg_active FROM competitions WHERE id = :compid", compid=compid)
        standingslist = getResults(comps)[4]
        print(standingslist)
        team1 = db.execute("SELECT t.id FROM team t INNER JOIN users u ON t.user_id = u.id WHERE u.username = :username AND t.comp_id = :compid", username=standingslist[0]["user"], compid=compid) 
        db.execute("INSERT INTO medals (team_id, medal, comp_id) VALUES (:team, :medal, :compid)", team=team1[0]["id"], medal=1, compid=compid)
        team2 = db.execute("SELECT t.id FROM team t INNER JOIN users u ON t.user_id = u.id WHERE u.username = :username AND t.comp_id = :compid", username=standingslist[1]["user"], compid=compid) 
        db.execute("INSERT INTO medals (team_id, medal, comp_id) VALUES (:team, :medal, :compid)", team=team2[0]["id"], medal=2, compid=compid)
        team3 = db.execute("SELECT t.id FROM team t INNER JOIN users u ON t.user_id = u.id WHERE u.username = :username AND t.comp_id = :compid", username=standingslist[2]["user"], compid=compid) 
        db.execute("INSERT INTO medals (team_id, medal, comp_id) VALUES (:team, :medal, :compid)", team=team3[0]["id"], medal=3, compid=compid)    
    return redirect(url_for('winners', activecomp=compid))

@app.route("/delWin", methods=["POST"])
@login_required
#TODO @admin_required
def delWin():
    """delete the medaling teams form the medal tabel"""
    compid = request.form.get("compid")
    db.execute("DELETE FROM medals WHERE comp_id = :compid", compid=compid)
    # reload new user screen
    return redirect(url_for('winners', activecomp=compid))


@app.route("/editDetails")
@login_required
#TODO @admin_required
def editDetails():
    """Show available competitions for editing points"""
    role = getRole()
    # Get all competitions and sort by startdate
    comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop FROM competitions ORDER BY startdate DESC")
    # render the page passing the information to the page
    return render_template("editDetails.html", role=role, comps=comps)

@app.route("/points")
@login_required
#TODO @admin_required
def points():
    """Show all riders and their points per day"""
    role = getRole()
    compid = request.args.get('activecomp', None)
    comps = db.execute("SELECT id, racetype_id, year FROM competitions WHERE id = :compid", compid=compid)
    # Get all the riders of the competition with their points per day
    riderpoints = db.execute("SELECT ri.id, ri.rider, po.day1, po.day2, po.day3, po.day4, po.day5, po.day6, po.day7, po.day8, po.day9, po.day10, po.day11, po.day12, po.day13, po.day14, po.day15, po.day16, po.day17, po.day18, po.day19, po.day20, po.day21, po.day22, po.day23, po.day24, po.day25, po.day26, po.day27, po.day28, po.day29, po.day30, po.final FROM riders ri LEFT JOIN points po ON po.rider_id = ri.id WHERE ri.comp_id = :compid ORDER BY ri.rider ASC", compid=compid)
    # Get the number of days for the competition
    daysInComp = db.execute("SELECT racedays FROM competitions WHERE id = :compid", compid=compid)
    # render the page passing the information to the page
    return render_template("points.html", role=role, riderpoints=riderpoints, daysInComp=daysInComp, compid=compid, comps=comps)    

@app.route("/points2")
@login_required
#TODO @admin_required
def points2():
    """provide all riders of the comp and their points per day to the page"""
    if request.method == "GET":
        role = getRole()
        compid = request.args.get('activecomp', None)
        comps = db.execute("SELECT id, racetype_id, year FROM competitions WHERE id = :compid", compid=compid)
        # Get all the riders of the competition with their DNF status
        riderpoints = db.execute("SELECT ri.id, ri.rider, po.day1, po.day2, po.day3, po.day4, po.day5, po.day6, po.day7, po.day8, po.day9, po.day10, po.day11, po.day12, po.day13, po.day14, po.day15, po.day16, po.day17, po.day18, po.day19, po.day20, po.day21, po.day22, po.day23, po.day24, po.day25, po.day26, po.day27, po.day28, po.day29, po.day30, po.final FROM riders ri LEFT JOIN points po ON po.rider_id = ri.id WHERE ri.comp_id = :compid ORDER BY ri.rider ASC", compid=compid)
        # Get the number of days for the competition
        daysInComp = db.execute("SELECT racedays FROM competitions WHERE id = :compid", compid=compid)
        # render the page passing the information to the page
        return render_template("points2.html", role=role, riderpoints=riderpoints, daysInComp=daysInComp, compid=compid, comps=comps)  
    """Update the points for the selected rider"""
    if request.method == "POST":  
        role = getRole()
        compid = request.form.get('compid')
        comps = db.execute("SELECT id, racetype_id, year FROM competitions WHERE id = :compid", compid=compid)
        # for selected rider update the points per day
        for riders in request.form.keys():
            if riders.isdigit():
                riderinpoints = db.execute("SELECT rider_id FROM points WHERE rider_id = :rider", rider=riders)
                rider = str(riders)
                if riderinpoints:
                    db.execute("UPDATE points \
                                SET day1 = :day1, day2 = :day2, day3 = :day3, day4 = :day4, day5 = :day5, day6 = :day6, day7 = :day7, \
                                    day8 = :day8, day9 = :day9, day10 = :day10, day11 = :day11, day12 = :day12, day13 = :day13, day14 = :day14, \
                                    day15 = :day15, day16 = :day16, day17 = :day17, day18 = :day18, day19 = :day19, day20 = :day20, day21 = :day21, \
                                    day22 = :day22, day23 = :day23, day24 = :day24, day25 = :day25, day26 = :day26, day27 = :day27, day28 = :day28, \
                                    day29 = :day29, day30 = :day30, final = :final \
                                WHERE rider_id = :rider", rider=riders
                                    , day1=request.form.get(rider + " 1"), day2=request.form.get(rider + " 2"), day3=request.form.get(rider + " 3")
                                    , day4=request.form.get(rider + " 4"), day5=request.form.get(rider + " 5"), day6=request.form.get(rider + " 6")
                                    , day7=request.form.get(rider + " 7"), day8=request.form.get(rider + " 8"), day9=request.form.get(rider + " 9")
                                    , day10=request.form.get(rider + " 10"), day11=request.form.get(rider + " 11"), day12=request.form.get(rider + " 12")
                                    , day13=request.form.get(rider + " 13"), day14=request.form.get(rider + " 14"), day15=request.form.get(rider + " 15")
                                    , day16=request.form.get(rider + " 16"), day17=request.form.get(rider + " 17"), day18=request.form.get(rider + " 18")
                                    , day19=request.form.get(rider + " 19"), day20=request.form.get(rider + " 20"), day21=request.form.get(rider + " 21")
                                    , day22=request.form.get(rider + " 22"), day23=request.form.get(rider + " 23"), day24=request.form.get(rider + " 24")
                                    , day25=request.form.get(rider + " 25"), day26=request.form.get(rider + " 26"), day27=request.form.get(rider + " 27")
                                    , day28=request.form.get(rider + " 28"), day29=request.form.get(rider + " 29"), day30=request.form.get(rider + " 30")
                                  , final=request.form.get(rider + "final")) 
                else:
                    db.execute("INSERT INTO points (rider_id, day1, day2, day3, day4, day5, day6, day7, day8, day9, day10, day11, \
                                    day12, day13, day14, day15, day16, day17, day18, day19, day20, day21, day22, day23, day24, day25, \
                                    day26, day27, day28, day29, day30, final) \
                                VALUES (:rider, :day1, :day2, :day3, :day4, :day5, :day6, :day7, :day8, :day9, :day10, :day11, :day12, \
                                    :day13, :day14, :day15, :day16, :day17, :day18, :day19, :day20, :day21, :day22, :day23, :day24,\
                                    :day25, :day26, :day27, :day28, :day29, :day30, :final)", rider=riders 
                                    , day1=request.form.get(rider + " 1"), day2=request.form.get(rider + " 2"), day3=request.form.get(rider + " 3")
                                    , day4=request.form.get(rider + " 4"), day5=request.form.get(rider + " 5"), day6=request.form.get(rider + " 6")
                                    , day7=request.form.get(rider + " 7"), day8=request.form.get(rider + " 8"), day9=request.form.get(rider + " 9")
                                    , day10=request.form.get(rider + " 10"), day11=request.form.get(rider + " 11"), day12=request.form.get(rider + " 12")
                                    , day13=request.form.get(rider + " 13"), day14=request.form.get(rider + " 14"), day15=request.form.get(rider + " 15")
                                    , day16=request.form.get(rider + " 16"), day17=request.form.get(rider + " 17"), day18=request.form.get(rider + " 18")
                                    , day19=request.form.get(rider + " 19"), day20=request.form.get(rider + " 20"), day21=request.form.get(rider + " 21")
                                    , day22=request.form.get(rider + " 22"), day23=request.form.get(rider + " 23"), day24=request.form.get(rider + " 24")
                                    , day25=request.form.get(rider + " 25"), day26=request.form.get(rider + " 26"), day27=request.form.get(rider + " 27")
                                    , day28=request.form.get(rider + " 28"), day29=request.form.get(rider + " 29"), day30=request.form.get(rider + " 30")
                                    , final=request.form.get(rider + "final"))
        compid=request.form.get("compid")
        return redirect(url_for('points', activecomp=compid))

@app.route("/DNF", methods=["GET", "POST"])
@login_required
#TODO @admin_required
def DNF():
    """provide all riders of the comp and their DNF status to the page"""
    if request.method == "GET":
        role = getRole()
        compid = request.args.get('activecomp', None)
        comps = db.execute("SELECT id, racetype_id, year FROM competitions WHERE id = :compid", compid=compid)
        # Get all the riders of the competition with their DNF status
        riders = db.execute("SELECT ri.id, ri.rider, ri.DNF FROM riders ri WHERE ri.comp_id = :compid ORDER BY ri.rider ASC", compid=compid)
        # render the page passing the information to the page
        return render_template("DNF.html", role=role, riders=riders, compid=compid, comps=comps)  
    """Update the DNF status for the selected rider"""
    if request.method == "POST":  
        role = getRole()
        compid = request.form.get('compid')
        comps = db.execute("SELECT id, racetype_id, year FROM competitions WHERE id = :compid", compid=compid)
        # save the updated status for the rider
        check = request.form.get("riderDNF")
        if check != '1':
            check = "0"
        print(check)
        db.execute("UPDATE riders SET DNF = :DNF WHERE id = :rider", DNF=check, rider=request.form.get("rider"))
        # Get all the riders of the competition with their DNF status
        riders = db.execute("SELECT ri.id, ri.rider, ri.DNF FROM riders ri WHERE ri.comp_id = :compid ORDER BY ri.rider ASC", compid=compid)
        # render the page passing the information to the page
        return render_template("DNF.html", role=role, riders=riders, compid=compid, comps=comps)  


@app.route("/editUser", methods=["GET", "POST"])
@login_required
#TODO @admin_required
def editUser():
    """Show page to approve users"""
    if request.method == "GET":
        role = getRole()
        # get all not approved users
        applicants = db.execute("SELECT id, username FROM users WHERE approved = 0")
        # get all approved users
        users = db.execute("SELECT id, username, role, approved FROM users WHERE approved = 1")
        # load edit user screen
        return render_template("editUser.html", role=role, users=users, applicants=applicants)      
    """Set user to approved or delete user"""
    if request.method == "POST": 
        role = getRole()
        db.execute("UPDATE users SET username = :username, role = :role WHERE id = :id", id=request.form.get("userid"), username=request.form.get("username"), role=request.form.get("role"))
        # reload new user screen
        return redirect('/editUser') 

@app.route("/deleteUser", methods=["POST"])
@login_required
#TODO @admin_required
def deleteUser():
    """Delete the selected user"""
    db.execute("DELETE FROM users WHERE id = :id", id=request.form.get("userid"))
    # reload new user screen
    return redirect('/editUser')

@app.route("/approveUser", methods=["POST"])
@login_required
#TODO @admin_required
def approveUser():
    """Approve the selected user"""
    db.execute("UPDATE users SET approved = 1 WHERE id = :id", id=request.form.get("userid"))
    # reload new user screen
    return redirect('/editUser')
     

@app.route("/updatePoints", methods=["POST"])
@login_required
#TODO @admin_required
def updatePoints():
    """Save the updated points"""
    # for each rider in the table update the points per day
    for riders in request.form.keys():
        if riders.isdigit():
            riderinpoints = db.execute("SELECT rider_id FROM points WHERE rider_id = :rider", rider=riders)
            rider = str(riders)
            if riderinpoints:
                db.execute("UPDATE points \
                            SET day1 = :day1, day2 = :day2, day3 = :day3, day4 = :day4, day5 = :day5, day6 = :day6, day7 = :day7, \
                                day8 = :day8, day9 = :day9, day10 = :day10, day11 = :day11, day12 = :day12, day13 = :day13, day14 = :day14, \
                                day15 = :day15, day16 = :day16, day17 = :day17, day18 = :day18, day19 = :day19, day20 = :day20, day21 = :day21, \
                                day22 = :day22, day23 = :day23, day24 = :day24, day25 = :day25, day26 = :day26, day27 = :day27, day28 = :day28, \
                                day29 = :day29, day30 = :day30, final = :final \
                            WHERE rider_id = :rider", rider=riders
                                , day1=request.form.get(rider + " 1"), day2=request.form.get(rider + " 2"), day3=request.form.get(rider + " 3")
                                , day4=request.form.get(rider + " 4"), day5=request.form.get(rider + " 5"), day6=request.form.get(rider + " 6")
                                , day7=request.form.get(rider + " 7"), day8=request.form.get(rider + " 8"), day9=request.form.get(rider + " 9")
                                , day10=request.form.get(rider + " 10"), day11=request.form.get(rider + " 11"), day12=request.form.get(rider + " 12")
                                , day13=request.form.get(rider + " 13"), day14=request.form.get(rider + " 14"), day15=request.form.get(rider + " 15")
                                , day16=request.form.get(rider + " 16"), day17=request.form.get(rider + " 17"), day18=request.form.get(rider + " 18")
                                , day19=request.form.get(rider + " 19"), day20=request.form.get(rider + " 20"), day21=request.form.get(rider + " 21")
                                , day22=request.form.get(rider + " 22"), day23=request.form.get(rider + " 23"), day24=request.form.get(rider + " 24")
                                , day25=request.form.get(rider + " 25"), day26=request.form.get(rider + " 26"), day27=request.form.get(rider + " 27")
                                , day28=request.form.get(rider + " 28"), day29=request.form.get(rider + " 29"), day30=request.form.get(rider + " 30")
                                , final=request.form.get(rider + "final")) 
            else:
                db.execute("INSERT INTO points (rider_id, day1, day2, day3, day4, day5, day6, day7, day8, day9, day10, day11, \
                                day12, day13, day14, day15, day16, day17, day18, day19, day20, day21, day22, day23, day24, day25, \
                                day26, day27, day28, day29, day30, final) \
                            VALUES (:rider, :day1, :day2, :day3, :day4, :day5, :day6, :day7, :day8, :day9, :day10, :day11, :day12, \
                                :day13, :day14, :day15, :day16, :day17, :day18, :day19, :day20, :day21, :day22, :day23, :day24,\
                                :day25, :day26, :day27, :day28, :day29, :day30, :final)", rider=riders 
                                , day1=request.form.get(rider + " 1"), day2=request.form.get(rider + " 2"), day3=request.form.get(rider + " 3")
                                , day4=request.form.get(rider + " 4"), day5=request.form.get(rider + " 5"), day6=request.form.get(rider + " 6")
                                , day7=request.form.get(rider + " 7"), day8=request.form.get(rider + " 8"), day9=request.form.get(rider + " 9")
                                , day10=request.form.get(rider + " 10"), day11=request.form.get(rider + " 11"), day12=request.form.get(rider + " 12")
                                , day13=request.form.get(rider + " 13"), day14=request.form.get(rider + " 14"), day15=request.form.get(rider + " 15")
                                , day16=request.form.get(rider + " 16"), day17=request.form.get(rider + " 17"), day18=request.form.get(rider + " 18")
                                , day19=request.form.get(rider + " 19"), day20=request.form.get(rider + " 20"), day21=request.form.get(rider + " 21")
                                , day22=request.form.get(rider + " 22"), day23=request.form.get(rider + " 23"), day24=request.form.get(rider + " 24")
                                , day25=request.form.get(rider + " 25"), day26=request.form.get(rider + " 26"), day27=request.form.get(rider + " 27")
                                , day28=request.form.get(rider + " 28"), day29=request.form.get(rider + " 29"), day30=request.form.get(rider + " 30")
                                , final=request.form.get(rider + "final"))
    compid=request.form.get("compid")
    return redirect(url_for('points', activecomp=compid))

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == "__main__":
    app.run(host='0.0.0.0')
