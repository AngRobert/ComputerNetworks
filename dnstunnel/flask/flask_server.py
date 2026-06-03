from flask import Flask, render_template, Response
import os
import client

app = Flask(__name__)

@app.route("/")
def hello():
    files = os.listdir("/app/files") if os.path.exists("/app/files") else []
    downloads = os.listdir("/app/downloads") if os.path.exists("/app/downloads") else []
    return render_template("index.html", files=files, downloads=downloads)

@app.route("/api/download/<filename>")
def download_file(filename):
    if not filename:
        return {"error": "Filename is required."}, 400
    
    return Response(client.start_download(filename), mimetype='text/event-stream')

@app.route("/api/view/<filename>")
def view_file(filename):
    try:
        with open(f"/app/files/{filename}", "r") as f:
            content = f.read()
        return content
    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5001, debug=True)