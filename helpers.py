import os
import requests
import urllib.parse


from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_table import Table, Col, create_table, OptCol, ButtonCol
from functools import wraps
from cs50 import SQL

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///rw.db")
db.execute("PRAGMA foreign_keys = ON")

def apology(message, code=400):
    """Render message as an apology to user."""
    return render_template("apology.html", top=code, bottom=message), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def getRole():
    """
    Find the role of the user
    """
    #Get the role of the user from de DB
    role = db.execute("SELECT role FROM users WHERE id = :userid", userid=session["user_id"])
    role2 = role[0]["role"]
    return role2


# TODO @admin_required

def getResults(comps2):
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
        teams.add_column('final', Col('Final', column_html_attrs={'class': 'day'}))
        teams.add_column('total', Col('TOTAL', column_html_attrs={'class': 'total day'}))
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
        chartTotals=[]
        chartCumulatives=[]
        # instantiate tabel per team
        for team in teamusers:
            # initialize a dict to hold all the information for the team
            userteam={}
            # initialize a dict to hold all the current total points for the team
            standingsteam={'rank': 0, 'user': '', 'points': 0}
            # Select all riders on the team
            riders = db.execute("SELECT r.DNF, tm.rank, r.rider, p.day1 AS '1', p.day2 AS '2', p.day3 AS '3', p.day4 AS '4', p.day5 AS '5', p.day6 AS '6', p.day7 AS '7', p.day8 AS '8', p.day9 AS '9', p.day10 AS '10', p.day11 AS '11', \
                                p.day12 AS '12', p.day13 AS '13', p.day14 AS '14', p.day15 AS '15', p.day16 AS '16', p.day17 AS '17', p.day18 AS '18', p.day19 AS '19', p.day20 AS '20', p.day21 AS '21', p.day22 AS '22', p.day23 AS '23', p.day24 AS '24', p.day25 AS '25', \
                                p.day26 AS '26', p.day27 AS '27', p.day28 AS '28', p.day29 AS '29', p.day30 AS '30', p.final   \
                                    FROM riders r \
                                    INNER JOIN team_member tm ON r.id = tm.rider_id \
                                    INNER JOIN team t ON t.id = tm.team_id \
                                    INNER JOIN points p ON r.id = p.rider_id \
                                        WHERE t.id = :team_id \
                                    ORDER BY tm.rank ASC", team_id=team["id"])
            # initialize a dict to hold the total per day
            totalday = {'DNF':0, 'rank':'', 'rider':'TOTAL', '1':0, '2':0, '3':0, '4':0, '5':0, '6':0, '7':0, '8':0, '9':0, '10':0, '11':0, '12':0, '13':0, '14':0, '15':0, '16':0, '17':0, '18':0, '19':0, '20':0, '21':0, '22':0, '23':0, '24':0, '25':0, '26':0, '27':0, '28':0, '29':0, '30':0, 'final':0, 'total':0}
            cumulativeday = {'DNF':0, 'rank':'', 'rider':'CUMULATIVE', '1':0, '2':0, '3':0, '4':0, '5':0, '6':0, '7':0, '8':0, '9':0, '10':0, '11':0, '12':0, '13':0, '14':0, '15':0, '16':0, '17':0, '18':0, '19':0, '20':0, '21':0, '22':0, '23':0, '24':0, '25':0, '26':0, '27':0, '28':0, '29':0, '30':0, 'final':0, 'total':0}
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
                cumulativeTemp = 0
                for i in range(comps2[0]["racedays"]): 
                    if rider[str(i + 1)]:
                        if i != 0:
                            cumulativeday[str(i + 1)] = cumulativeday[str(i)]
                        else:
                            cumulativeday["1"] = 0
                        if rider['DNF'] == 2:
                            rider[str(i + 1)] = rider[str(i + 1)] * 2
                            total = total + rider[str(i + 1)]
                            totalday[str(i + 1)] = totalday[str(i + 1)] + rider[str(i + 1)]
                            cumulativeday[str(i + 1)] = cumulativeday[str(i + 1)] + totalday[str(i + 1)]
                            cumulativeTemp = cumulativeday[str(i + 1)]
                        else:
                            total = total + rider[str(i + 1)]
                            totalday[str(i + 1)] = totalday[str(i + 1)] + rider[str(i + 1)]                  
                            cumulativeday[str(i + 1)] = cumulativeday[str(i + 1)] + totalday[str(i + 1)]
                            cumulativeTemp = cumulativeday[str(i + 1)]
                    else:
                        if i != 0:
                            cumulativeday[str(i + 1)] = cumulativeday[str(i)] + totalday[str(i + 1)]
                        else:
                            cumulativeday["1"] = totalday["1"]
                        cumulativeTemp = cumulativeday[str(i + 1)]
                if rider['DNF'] == 2:
                    rider["final"] = rider["final"] * 2
                rider["total"] = total + rider["final"]
                totalday["final"] = totalday["final"] + rider["final"]
                totalday["total"] = totalday["total"] + rider["total"]
                cumulativeday["final"] = cumulativeTemp + totalday["final"]
                #cumulativeday["total"] = cumulativeday["final"] 
            # add the totalday values to the rider dict
            riders.append(totalday)
            riders.append(cumulativeday)
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
            # Create dicts to hold the data to be used by the charts
            totals = {}
            totals['user'] = team['username']
            totals['points'] = totalday
            chartTotals.append(totals)
            cumulatives = {}
            cumulatives['user'] = team['username']
            cumulatives['points'] = cumulativeday
            chartCumulatives.append(cumulatives)
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
        return allteams, standingscomplete, chartTotals, chartCumulatives, standingslist