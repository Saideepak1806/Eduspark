from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, send_from_directory
import os, json, hashlib, io, datetime
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "polished_demo_secret_key"

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
UPLOAD_DIR = os.path.join(BASE, "uploads")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
REQUESTS_FILE = os.path.join(DATA_DIR, "requests.json")
LOG_FILE = os.path.join(DATA_DIR, "blockchain_log.json")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

def load_json(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f, indent=2)
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

# default users (Indian names)
default_users = {
  "patients": [
    {"username":"rajeev","password":"pass123","name":"Rajeev Kumar","id":"p1","key":""},
    {"username":"anita","password":"pass123","name":"Anita Singh","id":"p2","key":""},
    {"username":"suresh","password":"pass123","name":"Suresh Patel","id":"p3","key":""}
  ],
  "doctors": [
    {"username":"dr_rahul","password":"pass123","name":"Dr. Rahul Mehra","id":"d1"},
    {"username":"dr_neha","password":"pass123","name":"Dr. Neha Gupta","id":"d2"},
    {"username":"dr_amit","password":"pass123","name":"Dr. Amit Sharma","id":"d3"}
  ],
  "hospitals": [
    {"username":"apollo","password":"pass123","name":"Apollo Hospitals","id":"h1"},
    {"username":"aiims","password":"pass123","name":"AIIMS Delhi","id":"h2"}
  ]
}

users = load_json(USERS_FILE, default_users)

# ensure patient keys exist
for p in users["patients"]:
    if not p.get("key"):
        p["key"] = Fernet.generate_key().decode()
save_json(USERS_FILE, users)

requests = load_json(REQUESTS_FILE, [])
logs = load_json(LOG_FILE, [])

def log_action(action, user):
    entry = {"time": datetime.datetime.utcnow().isoformat()+"Z", "action": action, "by": user}
    logs.append(entry)
    save_json(LOG_FILE, logs)

def find_user(username):
    for role in ["patients","doctors","hospitals"]:
        for u in users.get(role,[]):
            if u["username"]==username:
                u_copy = u.copy()
                u_copy["role"] = role[:-1]  # patient/doctor/hospital
                return u_copy
    return None

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method=="POST":
        role = request.form["role"]
        username = request.form["username"].strip()
        password = request.form["password"]
        name = request.form.get("name","").strip() or username
        if find_user(username):
            flash("Username already exists", "danger")
            return redirect(url_for("signup"))
        if role=="patient":
            pid = f"p{len(users['patients'])+1}"
            key = Fernet.generate_key().decode()
            users["patients"].append({"username":username, "password":password, "name":name, "id":pid, "key":key})
        elif role=="doctor":
            did = f"d{len(users['doctors'])+1}"
            users["doctors"].append({"username":username, "password":password, "name":name, "id":did})
        else:
            hid = f"h{len(users['hospitals'])+1}"
            users["hospitals"].append({"username":username, "password":password, "name":name, "id":hid})
        save_json(USERS_FILE, users)
        flash("Signup successful. Please login.", "success")
        return redirect(url_for("index"))
    return render_template("signup.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"].strip()
    password = request.form["password"]
    role = request.form.get("role")
    user = find_user(username)
    if not user or user.get("password")!=password:
        flash("Invalid credentials", "danger")
        return redirect(url_for("index"))
    if user["role"] != role:
        flash("Role mismatch. Use the correct role card to login.", "warning")
        return redirect(url_for("index"))
    session["username"] = username
    session["role"] = role
    flash("Login successful", "success")
    return redirect(url_for(f"{role}_dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# Patient
@app.route("/patient/dashboard", methods=["GET","POST"])
def patient_dashboard():
    if session.get("role")!="patient":
        return redirect(url_for("index"))
    current = find_user(session["username"])
    if request.method=="POST":
        f = request.files.get("file")
        if f:
            filename = f.filename
            patient = next(p for p in users["patients"] if p["username"]==current["username"])
            key = patient["key"].encode()
            fernet = Fernet(key)
            data = f.read()
            enc = fernet.encrypt(data)
            save_path = os.path.join(UPLOAD_DIR, filename + ".enc")
            with open(save_path, "wb") as fh:
                fh.write(enc)
            h = hashlib.sha256(enc).hexdigest()
            log_action(f"Uploaded {filename} (hash {h[:16]})", current["username"])
            flash(f"Uploaded and encrypted {filename}", "success")
    # list files
    files = [fn[:-4] for fn in os.listdir(UPLOAD_DIR) if fn.endswith(".enc")]
    # patient-specific requests
    patient = next(p for p in users["patients"] if p["username"]==current["username"])
    patient_requests = [r for r in requests if r["patient_id"]==patient["id"]]
    return render_template("patient_dashboard.html", files=files, requests=patient_requests, username=current["username"])

@app.route("/patient/approve/<req_id>")
def patient_approve(req_id):
    if session.get("role")!="patient":
        return redirect(url_for("index"))
    for r in requests:
        if r["id"]==req_id:
            r["status"]="Approved"
            save_json(REQUESTS_FILE, requests)
            log_action(f"Approved request {req_id} for file {r['file']}", session["username"])
            break
    return redirect(url_for("patient_dashboard"))

@app.route("/patient/reject/<req_id>")
def patient_reject(req_id):
    if session.get("role")!="patient":
        return redirect(url_for("index"))
    for r in requests:
        if r["id"]==req_id:
            r["status"]="Rejected"
            save_json(REQUESTS_FILE, requests)
            log_action(f"Rejected request {req_id} for file {r['file']}", session["username"])
            break
    return redirect(url_for("patient_dashboard"))

# Doctor
@app.route("/doctor/dashboard")
def doctor_dashboard():
    if session.get("role")!="doctor":
        return redirect(url_for("index"))
    current = find_user(session["username"])
    files = [fn[:-4] for fn in os.listdir(UPLOAD_DIR) if fn.endswith(".enc")]
    patient_list = [{ "id": p["id"], "name": p["name"], "username": p["username"] } for p in users["patients"]]
    return render_template("doctor_dashboard.html", files=files, patients=patient_list, username=current["username"], requests=requests)

@app.route("/doctor/request/<patient_id>/<filename>")
def doctor_request(patient_id, filename):
    if session.get("role")!="doctor":
        return redirect(url_for("index"))
    did = next(d for d in users["doctors"] if d["username"]==session["username"])["id"]
    req_id = f"req{len(requests)+1}"
    requests.append({"id": req_id, "doctor_id": did, "doctor_username": session["username"], "patient_id": patient_id, "file": filename, "status": "Pending"})
    save_json(REQUESTS_FILE, requests)
    log_action(f"Doctor {session['username']} requested {filename} of patient {patient_id}", session["username"])
    flash("Access request submitted", "info")
    return redirect(url_for("doctor_dashboard"))

@app.route("/doctor/download/<req_id>")
def doctor_download(req_id):
    if session.get("role")!="doctor":
        return redirect(url_for("index"))
    req = next((r for r in requests if r["id"]==req_id and r["doctor_username"]==session["username"] and r["status"]=="Approved"), None)
    if not req:
        flash("No approved access for this request", "danger")
        return redirect(url_for("doctor_dashboard"))
    patient = next((p for p in users["patients"] if p["id"]==req["patient_id"]), None)
    enc_path = os.path.join(UPLOAD_DIR, req["file"] + ".enc")
    if not os.path.exists(enc_path):
        flash("File not found", "danger")
        return redirect(url_for("doctor_dashboard"))
    fernet = Fernet(patient["key"].encode())
    with open(enc_path, "rb") as fh:
        enc = fh.read()
    data = fernet.decrypt(enc)
    log_action(f"Doctor {session['username']} downloaded {req['file']}", session["username"])
    return send_file(io.BytesIO(data), as_attachment=True, download_name=req["file"])

# Hospital
@app.route("/hospital/dashboard")
def hospital_dashboard():
    if session.get("role")!="hospital":
        return redirect(url_for("index"))
    return render_template("hospital_dashboard.html", logs=logs, requests=requests, users=users)

if __name__ == "__main__":
    app.run(debug=True)
