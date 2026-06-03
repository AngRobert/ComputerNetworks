from flask import Flask, render_template, request
import os
import client

app = Flask(__name__)

@app.route("/")
def hello():
    files = os.listdir("files") if os.path.exists("files") else []
    downloads = os.listdir("downloads") if os.path.exists("downloads") else []
    return render_template("index.html", files=files, downloads=downloads)

@app.route("/api/download", methods=["POST"])
def download_file():
    filename = request.json.get("filename")
    if not filename:
        return {"error": "Filename is required."}, 400
    
    try:
        client.start_download(filename)
    except Exception as e:
        return {"error": str(e)}, 500
    
    return {"message": "Download initiated"}, 200

@app.route("/api/view/<filename>")
def view_file(filename):
    try:
        with open(f"files/{filename}", "r") as f:
            content = f.read()
        return content
    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)