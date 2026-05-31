from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def mxmap():
    with open("ro_mail_map.geojson") as f:
        content = f.read()

    return render_template("index.html", geojson_content=content)