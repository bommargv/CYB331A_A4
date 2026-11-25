import hashlib
import pickle
import sqlite3
import subprocess
import os
from flask import Flask, request

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

DB_PATH = "inventory.db"

def get_db():
	return sqlite3.connect(DB_PATH)

@app.route("/item")
def item():
	name = request.args.get("name", "")
	cur = get_db().cursor()
	cur.execute(
		"SELECT id, name, qty FROM items WHERE name = ?",
		(name,)
	)
	return {"rows": cur.fetchall()}

@app.route("/backup")
def backup():
	folder = request.args.get("folder", "data")
	subprocess.run("tar czf backup.tgz " + folder, shell=True)
	return "Backup created"

@app.route("/import", methods=["POST"])
def import_items():
	items = pickle.loads(request.data)
	return {"imported": len(items)}

@app.route("/report")
def report():
	filename = request.args.get("file", "")
	with open("reports/" + filename) as f:
		return f.read()

def hash_password(password):
	return hashlib.md5(password.encode()).hexdigest()

if __name__ == "__main__":
    app.run(debug=True)