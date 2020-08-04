import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from flask_table import Table, Col, create_table, OptCol, ButtonCol
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
    # Get all active competitions for registration
    comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop FROM competitions WHERE reg_active = 'on' AND strftime('%s', reg_stop) > strftime('%s', 'now') ")
    if comps:
        # render the page passing the competition to the page
        return render_template("index.html", role=role, comps=comps)
    # Get all active competitions after registration
    comps2 = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays FROM competitions WHERE reg_active = 'on' AND strftime('%s', reg_stop) < strftime('%s', 'now') ")
    if comps2:
        # Get the teams for the active competition
        teamusers = db.execute("SELECT t.id, u.username FROM team t INNER JOIN users u ON t.user_id = u.id WHERE t.comp_id = :compid", compid=comps2[0]["id"])
        tbl_options = dict(
            classes=['table', 'table-sm', 'DNF'],
            no_items='Empty')
        #create table template to hold the data per team
        teams = create_table('teams', options=tbl_options)\
            .add_column('DNF', Col('DNF', column_html_attrs={'class': 'DNF'}))\
            .add_column('rank', Col('Rank', column_html_attrs={'class': 'rank'}))\
            .add_column('rider', Col('Rider', column_html_attrs={'class': 'rider'}))
        for i in range(comps2[0]["racedays"]):
            teams.add_column(str(i + 1), Col(str(i + 1), column_html_attrs={'class': 'day'}))
        teams.add_column('total', Col('TOTAL', column_html_attrs={'class': 'total'}))
        # Create a table template to hold the current standing
        class Standings(Table):
            rank = Col('Rank')
            user = Col('Team', column_html_attrs={'class': 'team'})
            points = Col('Points')
            classes = ['score', 'table', 'table-lg']        
        #initialize list to hold all the teams
        allteams=[]
        #initialize list to hold the standings
        standingslist=[]
        # instantiate tabel per team
        for team in teamusers:
            # initialize a dict to hold all the information for the team
            userteam={}
            # initialize a dict to hold all the current total points for the team
            standingsteam={'rank': 0, 'user': '', 'points': 0}
            # Select all riders on the team
            riders = db.execute("SELECT r.DNF, tm.rank, r.rider, p.day1 AS '1', p.day2 AS '2', p.day3 AS '3', p.day4 AS '4', p.day5 AS '5', p.day6 AS '6', p.day7 AS '7', p.day8 AS '8', p.day9 AS '9', p.day10 AS '10', p.day11 AS '11', \
                                p.day12 AS '12', p.day13 AS '13', p.day14 AS '14', p.day15 AS '15', p.day16 AS '16', p.day17 AS '17', p.day18 AS '18', p.day19 AS '19', p.day20 AS '20', p.day21 AS '21', p.day22 AS '22', p.day23 AS '23', p.day24 AS '24', p.day25 AS '25', \
                                p.day26 AS '26', p.day27 AS '27', p.day28 AS '28', p.day29 AS '29', p.day30 AS '30'   \
                                    FROM riders r \
                                    INNER JOIN team_member tm ON r.id = tm.rider_id \
                                    INNER JOIN team t ON t.id = tm.team_id \
                                    INNER JOIN points p ON r.id = p.rider_id \
                                        WHERE t.id = :team_id \
                                    ORDER BY tm.rank ASC", team_id=team["id"])
            # initialize a dict to hold the total per day
            totalday = {'DNF':0, 'rank':'', 'rider':'TOTAL', '1':0, '2':0, '3':0, '4':0, '5':0, '6':0, '7':0, '8':0, '9':0, '10':0, '11':0, '12':0, '13':0, '14':0, '15':0, '16':0, '17':0, '18':0, '19':0, '20':0, '21':0, '22':0, '23':0, '24':0, '25':0, '26':0, '27':0, '28':0, '29':0, '30':0, 'total':0}
            captainDef = 0
            # Select the points per day per rider
            for rider in riders:
                total = 0
                if rider['DNF'] == 0 and rider["rank"] == 1 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1
                elif rider['DNF'] == 0 and rider["rank"] == 2 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1   
                elif rider['DNF'] == 0 and rider["rank"] == 3 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1 
                elif rider['DNF'] == 0 and rider["rank"] == 4 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1  
                elif rider['DNF'] == 0 and rider["rank"] == 5 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1  
                elif rider['DNF'] == 0 and rider["rank"] == 6 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1 
                elif rider['DNF'] == 0 and rider["rank"] == 7 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1
                elif rider['DNF'] == 0 and rider["rank"] == 8 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1  
                elif rider['DNF'] == 0 and rider["rank"] == 9 and captainDef == 0:
                    rider['DNF'] = 2 
                    captainDef = 1 
                for i in range(comps2[0]["racedays"]): 
                    if rider[str(i + 1)]:
                        if rider['DNF'] == 2:
                            rider[str(i + 1)] = rider[str(i + 1)] * 2
                            total = total + rider[str(i + 1)]
                            totalday[str(i + 1)] = totalday[str(i + 1)] + rider[str(i + 1)]
                        else:
                            total = total + rider[str(i + 1)]
                            totalday[str(i + 1)] = totalday[str(i + 1)] + rider[str(i + 1)]                  
                rider["total"] = total
                totalday["total"] = totalday["total"] + total
            # add the totalday values to the rider dict
            riders.append(totalday)
            # populate the table for the team
            teamcomplete = teams(riders)
            # add the name and the table for the team to the userteam dict
            userteam['username'] = team['username']
            userteam['table'] = teamcomplete
            # add the team to the list of teams
            allteams.append(userteam)
            # add username and current points to the standing team dict
            standingsteam['user'] = team['username']
            standingsteam['points'] = totalday['total']
            # add the standing of the team to the list of standings
            standingslist.append(standingsteam)
        # sort the standingslist and add the rank to each dict
        standingslist = sorted(standingslist, key = lambda item: item['points'], reverse=True)
        # iterate over the dicts in standingslist to add the rank
        rankraised = 1
        for rank in standingslist:
            rank['rank'] = rankraised
            rankraised = rankraised + 1
        # format the standingslist into a table
        standingscomplete = Standings(standingslist)
        
        # render the page passing the competition and teams to the page
        return render_template("index.html", role=role, comps2=comps2, allteams=allteams, standings=standingscomplete)
    else:
        # render the page passing only the role to the page
        return render_template("index.html", role=role)

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
    role = getRole()
    # Get all competitions and sort by startdate
    comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop FROM competitions ORDER BY startdate DESC")
    # Direct user to history page
    return render_template("history.html", role=role, comps=comps)  

@app.route("/archive")
@login_required
def archive():
    """Show results from selected competiton"""
    role = getRole()
    compid = request.args.get('activecomp', None)
    comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays FROM competitions WHERE id = :compid", compid=compid)
    # Get the teams for the active competition
    teamusers = db.execute("SELECT t.id, u.username FROM team t INNER JOIN users u ON t.user_id = u.id WHERE t.comp_id = :compid", compid=compid)
    tbl_options = dict(
        classes=['table', 'table-sm', 'DNF'],
        no_items='Empty')
    #create table template to hold the data per team
    teams = create_table('teams', options=tbl_options)\
        .add_column('DNF', Col('DNF', column_html_attrs={'class': 'DNF'}))\
        .add_column('rank', Col('Rank', column_html_attrs={'class': 'rank'}))\
        .add_column('rider', Col('Rider', column_html_attrs={'class': 'rider'}))
    for i in range(comps[0]["racedays"]):
        teams.add_column(str(i + 1), Col(str(i + 1), column_html_attrs={'class': 'day'}))
    teams.add_column('total', Col('TOTAL', column_html_attrs={'class': 'total'}))
    # Create a table template to hold the current standing
    class Standings(Table):
        rank = Col('Rank')
        user = Col('Team', column_html_attrs={'class': 'team'})
        points = Col('Points')
        classes = ['score', 'table', 'table-lg']        
    #initialize list to hold all the teams
    allteams=[]
    #initialize list to hold the standings
    standingslist=[]
    # instantiate tabel per team
    for team in teamusers:
        # initialize a dict to hold all the information for the team
        userteam={}
        # initialize a dict to hold all the current total points for the team
        standingsteam={'rank': 0, 'user': '', 'points': 0}
        # Select all riders on the team
        riders = db.execute("SELECT r.DNF, tm.rank, r.rider, p.day1 AS '1', p.day2 AS '2', p.day3 AS '3', p.day4 AS '4', p.day5 AS '5', p.day6 AS '6', p.day7 AS '7', p.day8 AS '8', p.day9 AS '9', p.day10 AS '10', p.day11 AS '11', \
                            p.day12 AS '12', p.day13 AS '13', p.day14 AS '14', p.day15 AS '15', p.day16 AS '16', p.day17 AS '17', p.day18 AS '18', p.day19 AS '19', p.day20 AS '20', p.day21 AS '21', p.day22 AS '22', p.day23 AS '23', p.day24 AS '24', p.day25 AS '25', \
                            p.day26 AS '26', p.day27 AS '27', p.day28 AS '28', p.day29 AS '29', p.day30 AS '30'   \
                                FROM riders r \
                                INNER JOIN team_member tm ON r.id = tm.rider_id \
                                INNER JOIN team t ON t.id = tm.team_id \
                                INNER JOIN points p ON r.id = p.rider_id \
                                    WHERE t.id = :team_id \
                                ORDER BY tm.rank ASC", team_id=team["id"])
        # initialize a dict to hold the total per day
        totalday = {'DNF':0, 'rank':'', 'rider':'TOTAL', '1':0, '2':0, '3':0, '4':0, '5':0, '6':0, '7':0, '8':0, '9':0, '10':0, '11':0, '12':0, '13':0, '14':0, '15':0, '16':0, '17':0, '18':0, '19':0, '20':0, '21':0, '22':0, '23':0, '24':0, '25':0, '26':0, '27':0, '28':0, '29':0, '30':0, 'total':0}
        captainDef = 0
        # Select the points per day per rider
        for rider in riders:
            total = 0
            if rider['DNF'] == 0 and rider["rank"] == 1 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1
            elif rider['DNF'] == 0 and rider["rank"] == 2 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1   
            elif rider['DNF'] == 0 and rider["rank"] == 3 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1 
            elif rider['DNF'] == 0 and rider["rank"] == 4 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1  
            elif rider['DNF'] == 0 and rider["rank"] == 5 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1  
            elif rider['DNF'] == 0 and rider["rank"] == 6 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1 
            elif rider['DNF'] == 0 and rider["rank"] == 7 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1
            elif rider['DNF'] == 0 and rider["rank"] == 8 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1  
            elif rider['DNF'] == 0 and rider["rank"] == 9 and captainDef == 0:
                rider['DNF'] = 2 
                captainDef = 1 
            for i in range(comps[0]["racedays"]): 
                if rider[str(i + 1)]:
                    if rider['DNF'] == 2:
                        rider[str(i + 1)] = rider[str(i + 1)] * 2
                        total = total + rider[str(i + 1)]
                        totalday[str(i + 1)] = totalday[str(i + 1)] + rider[str(i + 1)]
                    else:
                        total = total + rider[str(i + 1)]
                        totalday[str(i + 1)] = totalday[str(i + 1)] + rider[str(i + 1)]                  
            rider["total"] = total
            totalday["total"] = totalday["total"] + total
        # add the totalday values to the rider dict
        riders.append(totalday)
        # populate the table for the team
        teamcomplete = teams(riders)
        # add the name and the table for the team to the userteam dict
        userteam['username'] = team['username']
        userteam['table'] = teamcomplete
        # add the team to the list of teams
        allteams.append(userteam)
        # add username and current points to the standing team dict
        standingsteam['user'] = team['username']
        standingsteam['points'] = totalday['total']
        # add the standing of the team to the list of standings
        standingslist.append(standingsteam)
    # sort the standingslist and add the rank to each dict
    standingslist = sorted(standingslist, key = lambda item: item['points'], reverse=True)
    # iterate over the dicts in standingslist to add the rank
    rankraised = 1
    for rank in standingslist:
        rank['rank'] = rankraised
        rankraised = rankraised + 1
    # format the standingslist into a table
    standingscomplete = Standings(standingslist)        
    # render the page passing the competition and teams to the page
    return render_template("archive.html", role=role, comps=comps, allteams=allteams, standings=standingscomplete)



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
        canRegisterOrEdit = db.execute("SELECT id FROM competitions WHERE reg_active = 'on' AND strftime('%s', reg_stop) > strftime('%s', 'now') ")
        riders = db.execute("SELECT r.rider, r.nationality, r.rides_for, tm.team_id, t.comp_id \
                                    FROM riders AS r \
                                    INNER JOIN team_member AS tm ON r.id = tm.rider_id \
                                    INNER JOIN team AS t ON t.id = tm.team_id \
                                        WHERE t.user_id = :user_id \
                                        AND t.comp_id = :activecomps \
                                    ORDER BY tm.rank ASC" , user_id=user_id, activecomps=activecomps[0]["id"])

    # Direct user to my team page
        return render_template("myteam.html", activecomps = activecomps, riders=riders, canRegisterOrEdit=canRegisterOrEdit)  


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
            for k,v in request.form.items():
                if k.isdigit():
                    if v.isdigit():
                        f = int(v)
                        if f > 0: 
                            db.execute("INSERT INTO team_member (team_id, rider_id, rank) VALUES (:team_id, :rider_id, :rank)", team_id=team_id, rider_id=k, rank=f)
            return redirect("/myteam")

@app.route("/editteam", methods=["GET", "POST"])
@login_required
def editteam():
    """Show the editteam page of the current race"""
    if request.method == "GET":
        # Get the user_id to find his/her team for the current race
        user_id = session.get("user_id")
        # Get the current team_id and competition_id
        editTeamID = db.execute("SELECT c.id, t.id AS team_id \
                                        FROM competitions AS c \
                                        INNER JOIN racetypes AS r ON c.racetype_id = r.id\
                                        INNER JOIN team AS t ON c.id = t.comp_id \
                                            WHERE t.user_id = :user_id \
                                            AND c.reg_active = 'on'", user_id = user_id)
        activecomp = editTeamID[0]["id"]
        team_id = editTeamID[0]["team_id"]
        # Get the riders with info of the users team
        teamRiders = db.execute("SELECT r.rider, r.nationality, r.rides_for, tm.rank, tm.team_id, t.comp_id \
                                    FROM riders AS r \
                                    INNER JOIN team_member AS tm ON r.id = tm.rider_id \
                                    INNER JOIN team AS t ON t.id = tm.team_id \
                                        WHERE t.user_id = :user_id \
                                        AND t.comp_id = :activecomp \
                                    ORDER BY tm.rank ASC" , user_id=user_id, activecomp=activecomp)
        # Get all the riders of the competition
        allRiders = db.execute("Select id, comp_id, rider, nationality, rides_for, contraint_id, comp_id \
                                    FROM riders \
                                    WHERE comp_id = :activecomp \
                                    Order by rides_for ASC, rider ASC", activecomp=activecomp)
        # Send team riders and competition riders to the html template
        return render_template("editteam.html", teamRiders=teamRiders, allRiders = allRiders, activecomp=activecomp, team_id=team_id)
    """Edit/update the current team"""
    if request.method == "POST":
        #user = session.get("user_id")
        compid = request.form.get("comp")
        team_id = request.form.get("team_id")
        # Ensure that a competition is selected
        if not compid:
            return apology("Please select a competition before registering a team", 400)
        # Ensure that users doesn't already have a team
        elif not team_id:
            return apology("Please create a team before editing", 400)
        else:
            # update riders in team
            for k,v in request.form.items():
                if k.isdigit():
                    if v.isdigit():
                        f = int(v)
                        if f > 0: 
                            db.execute("UPDATE team_member SET rider_id = :rider_id WHERE team_id = :team_id AND rank = :rank", rider_id=k, team_id=team_id, rank=f)
            return redirect("/myteam")


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
        db.execute("INSERT INTO competitions (racetype_id, year, startdate, reg_active, reg_stop, racedays) VALUES (:racetype, :year, :startdate, :reg_active, :reg_stop, :racedays)",
                   racetype=request.form.get("racetype"), year=request.form.get("year"), startdate=request.form.get("startdate"), reg_active=active,
                   reg_stop=request.form.get("reg_stop"), racedays=request.form.get("racedays"))
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
        comps = db.execute("SELECT id, racetype_id, year, startdate, reg_stop, racedays, reg_active FROM competitions WHERE id = :compid", compid=compid)
        return render_template("editcomp.html", comps=comps, role=role)
    """register a new competition in the database"""
    if request.method == "POST":
        #Get the role of the user from de DB
        role = getRole()
        compid = request.form.get('compid')
        active = request.form.get("reg_active")
        if active != "on":
            active = "off"
        db.execute("UPDATE competitions SET startdate = :startdate, reg_active = :reg_active, reg_stop = :reg_stop, racedays = :racedays WHERE id = :compid",
                   startdate=request.form.get("startdate"), reg_active=active,
                   reg_stop=request.form.get("reg_stop"), racedays=request.form.get("racedays"), compid=compid)
        # Redirect user to home page
        return render_template("admin.html", role=role)

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
    riderpoints = db.execute("SELECT ri.id, ri.rider, po.day1, po.day2, po.day3, po.day4, po.day5, po.day6, po.day7, po.day8, po.day9, po.day10, po.day11, po.day12, po.day13, po.day14, po.day15, po.day16, po.day17, po.day18, po.day19, po.day20, po.day21, po.day22, po.day23, po.day24, po.day25, po.day26, po.day27, po.day28, po.day29, po.day30 FROM riders ri LEFT JOIN points po ON po.rider_id = ri.id WHERE ri.comp_id = :compid ORDER BY ri.rider ASC", compid=compid)
    # Get the number of days for the competition
    daysInComp = db.execute("SELECT racedays FROM competitions WHERE id = :compid", compid=compid)
    # render the page passing the information to the page
    return render_template("points.html", role=role, riderpoints=riderpoints, daysInComp=daysInComp, compid=compid, comps=comps)    

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


@app.route("/editBlog")
#TODO @admin_required
@login_required
def editBlog():
    """Show page to edit and add blog posts"""
    #TODO
    # Redirect user to login form
    return render_template("editblog.html")

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
                                day29 = :day29, day30 = :day30 \
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
                                , day28=request.form.get(rider + " 28"), day29=request.form.get(rider + " 29"), day30=request.form.get(rider + " 30")) 
            else:
                db.execute("INSERT INTO points (rider_id, day1, day2, day3, day4, day5, day6, day7, day8, day9, day10, day11, \
                                day12, day13, day14, day15, day16, day17, day18, day19, day20, day21, day22, day23, day24, day25, \
                                day26, day27, day28, day29, day30) \
                            VALUES (:rider, :day1, :day2, :day3, :day4, :day5, :day6, :day7, :day8, :day9, :day10, :day11, :day12, \
                                :day13, :day14, :day15, :day16, :day17, :day18, :day19, :day20, :day21, :day22, :day23, :day24,\
                                :day25, :day26, :day27, :day28, :day29, :day30)", rider=riders 
                                , day1=request.form.get(rider + " 1"), day2=request.form.get(rider + " 2"), day3=request.form.get(rider + " 3")
                                , day4=request.form.get(rider + " 4"), day5=request.form.get(rider + " 5"), day6=request.form.get(rider + " 6")
                                , day7=request.form.get(rider + " 7"), day8=request.form.get(rider + " 8"), day9=request.form.get(rider + " 9")
                                , day10=request.form.get(rider + " 10"), day11=request.form.get(rider + " 11"), day12=request.form.get(rider + " 12")
                                , day13=request.form.get(rider + " 13"), day14=request.form.get(rider + " 14"), day15=request.form.get(rider + " 15")
                                , day16=request.form.get(rider + " 16"), day17=request.form.get(rider + " 17"), day18=request.form.get(rider + " 18")
                                , day19=request.form.get(rider + " 19"), day20=request.form.get(rider + " 20"), day21=request.form.get(rider + " 21")
                                , day22=request.form.get(rider + " 22"), day23=request.form.get(rider + " 23"), day24=request.form.get(rider + " 24")
                                , day25=request.form.get(rider + " 25"), day26=request.form.get(rider + " 26"), day27=request.form.get(rider + " 27")
                                , day28=request.form.get(rider + " 28"), day29=request.form.get(rider + " 29"), day30=request.form.get(rider + " 30"))
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
