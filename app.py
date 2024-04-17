# Import Python library
import re
import os
from flask import Flask
from flask import request
from flask import url_for
from flask import redirect
from flask import render_template
from pysafebrowsing import SafeBrowsing


# Flask definition
app = Flask(__name__)

# Google SafeBrowsing API key
# DO NOT DISCLOSE
API_KEY = "AIzaSyCllKcc9yqQR9RMh5Dak7m7VP2TSYQK6cs"
s = SafeBrowsing(API_KEY)


# Main startup screen loader
@app.route("/")
def hello_world():
    return render_template("login.html")


# Phishing website detection/prediction screen
@app.route("/predict", methods=["POST","GET"])
def predict():
    url = [str(x) for x in request.form.values()]
    url_lookup = s.lookup_urls(url)

    url_decode = str(url_lookup.values())
    url_safety = bool(re.findall("'malicious': False", url_decode))

    if url_safety:
        return render_template("predict.html", pred="Not a Phishing Website.", url=url, api=API_KEY)
    else:
        return render_template("predict.html", pred="Phishing Website Detected!", url=url, api=API_KEY)


# Awareness screen
@app.route("/awareness", methods=["POST","GET"])
def awareness():
    # Re-direct to awareness webpage
    if request.form['action'] == 'Awareness':
        return render_template("awareness.html")


# Mitigation plan screen
@app.route("/mitigation", methods=["POST","GET"])
def mitigation():
    # Re-direct to Google phishing website reporting webpage
    if request.form['action'] == 'Report':
        return redirect("https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en")

    # Redirect to "About Us" webpage
    elif request.form['action'] == 'About':
        return render_template("about.html")

    # Redirect to "FAQ" webpage
    elif request.form['action'] == 'FAQ':
        return render_template("faq.html")


# Login screen
@app.route("/login", methods=["GET", "POST"])
def login():
    login_status = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if user exists
        account_exist  = os.path.isfile("account/" + username + ".txt")

        account_info   = []
        account_info.append(username)
        account_info.append(password)

        # If user login
        if request.form["two_buttons"] == "Login":
            # If user exists
            if account_exist:
                account_detail = open("account/" + username + ".txt").read().split("\n")

                # Load existing user credentials and perform login
                if username == account_detail[0] and password == account_detail[1]:
                    return render_template("predict.html")

                # If user exists but wrong password
                else:
                    return render_template("login.html", login_status="Wrong username or password. Please try again.")

            # If user not exists
            else:
                return render_template("login.html", login_status="User does not exists. Please register.")

        # If user register
        if request.form["two_buttons"] == "Register":

            # Check if user exists
            account_exist = os.path.isfile("account/" + username + ".txt")

            # If account exists
            if account_exist:
                return render_template("login.html", login_status="Username exists in the system. Please proceed to login.")

            # If new user register
            else:
                # Create new user profile
                filename = "account/" + username + ".txt"
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                file = open(filename, "w")

                for info in account_info:
                    file.write("%s\n" % info)

                file.close()

                return render_template("predict.html")

    else:
        return render_template("login.html")


# Logout to main startup (Login) screen
@app.route("/logout", methods=["GET", "POST"])
def logout():
    return redirect(url_for("login"))


# Python main
if __name__ == "__main__":
    app.run(debug=True)


# EOF