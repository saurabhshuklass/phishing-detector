from flask import Flask, render_template, request
import requests
import base64

app = Flask(__name__)

API_KEY = "f396b31a40028850ef5295beb7a49a5f22a596790015ff0393b02b76118db239"

@app.route("/", methods=["GET", "POST"])
def home():

    result = ""

    if request.method == "POST":

        url = request.form["text"]

        # Encode URL
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {
            "x-apikey": API_KEY
        }

        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:

            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats["malicious"]
            suspicious = stats["suspicious"]

            if malicious > 0:
                result = f"🔴 Dangerous URL\nMalicious Reports: {malicious}"
            elif suspicious > 0:
                result = f"🟠 Suspicious URL\nSuspicious Reports: {suspicious}"
            else:
                result = "🟢 Safe URL"

        else:
            result = "Error checking URL"

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True, port=5001)