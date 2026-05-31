from flask import Flask, render_template, send_file

app = Flask(__name__)

@app.route("/")
def mxmap():
    return render_template("index.html")

@app.route("/data.geojson")
def get_geojson():
    return send_file("ro_mail_map.geojson", mimetype="application/json")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)