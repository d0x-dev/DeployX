import os
import json
import time
import socket
import shutil
import signal
import subprocess
import threading
import queue
from pathlib import Path
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for, flash, Response,
    render_template, jsonify, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests

# ---------- Paths & constants ----------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPO_DIR = BASE_DIR / "repos"
DATA_DIR.mkdir(exist_ok=True)
REPO_DIR.mkdir(exist_ok=True)

USERS_JSON = DATA_DIR / "users.json"
PROJECTS_JSON = DATA_DIR / "projects.json"

ALLOWED_PORTS = [5000, 8000]
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:3000")

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

STATE = {}  # key = owner:project

# ---------- Utilities ----------
def load_json(path, default):
    if not path.exists():
        save_json(path, default)
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def is_port_open(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        try:
            s.connect((host, port))
            return True
        except Exception:
            return False

def kill_process(pid):
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass

def enqueue_output(pipe, q, tag):
    for raw in iter(pipe.readline, b""):
        try:
            line = raw.decode(errors="replace").rstrip("\n")
        except Exception:
            line = str(raw)
        q.put(f"[{tag}] {line}")
    try:
        pipe.close()
    except Exception:
        pass

# ---------- Auth ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    users = load_json(USERS_JSON, {})
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("signup.html")
        if username in users:
            flash("Username already exists.", "danger")
            return render_template("signup.html")
        users[username] = {
            "password_hash": generate_password_hash(password),
            "created_at": int(time.time()),
        }
        save_json(USERS_JSON, users)
        flash("Signup successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    users = load_json(USERS_JSON, {})
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if username in users and check_password_hash(users[username]["password_hash"], password):
            session["user"] = username
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.pop("user", None)
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ---------- Dashboard & Projects ----------
@app.route("/")
@login_required
def dashboard():
    projects = load_json(PROJECTS_JSON, {})
    my = [p for p in projects.values() if p["owner"] == session["user"]]
    return render_template("dashboard.html", projects=my)

@app.route("/projects")
@login_required
def projects():
    projects = load_json(PROJECTS_JSON, {})
    my = [p for p in projects.values() if p["owner"] == session["user"]]
    return render_template("projects.html", projects=my)

@app.post("/projects/stop/<project_name>")
@login_required
def stop_project(project_name):
    projects = load_json(PROJECTS_JSON, {})
    key = f"{session['user']}:{project_name}"
    if key in projects:
        pid = projects[key].get("pid")
        if pid:
            kill_process(pid)
        repo_dir = projects[key].get("repo_dir")
        if repo_dir:
            shutil.rmtree(repo_dir, ignore_errors=True)
        del projects[key]
        save_json(PROJECTS_JSON, projects)
        STATE.pop(key, None)
        flash("Project stopped and removed.", "info")
    return redirect(url_for("projects"))

# ---------- Deploy + Live Logs ----------
def start_pipeline(owner, project, repo_url, build_cmd, run_cmd):
    key = f"{owner}:{project}"
    old = STATE.get(key)
    if old and old.get("proc"):
        try:
            old["proc"].kill()
        except Exception:
            pass

    proj_dir = REPO_DIR / owner / project
    if proj_dir.exists():
        shutil.rmtree(proj_dir, ignore_errors=True)
    proj_dir.parent.mkdir(parents=True, exist_ok=True)

    log_q = queue.Queue()
    STATE[key] = {"proc": None, "port": None, "repo_dir": str(proj_dir),
                  "log_q": log_q, "status": "starting", "url": None}

    def log(msg): log_q.put(msg)

    def run():
        try:
            # Clone
            log(f"Cloning {repo_url} into {proj_dir} ...")
            clone = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(proj_dir)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            log(clone.stdout)
            if clone.returncode != 0:
                STATE[key]["status"] = "error"
                return

            # Build
            if build_cmd:
                log(f"Running build: {build_cmd}")
                build = subprocess.Popen(build_cmd, cwd=str(proj_dir), shell=True,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                t_build = threading.Thread(target=enqueue_output, args=(build.stdout, log_q, "build"), daemon=True)
                t_build.start()
                code = build.wait()
                if code != 0:
                    log(f"Build failed with exit code {code}")
                    STATE[key]["status"] = "error"
                    return

            # Run
            env = os.environ.copy()
            env["HOST"] = "0.0.0.0"
            env.setdefault("PORT", str(ALLOWED_PORTS[0]))
            log(f"Starting app: {run_cmd} (PORT={env['PORT']})")
            proc = subprocess.Popen(run_cmd, cwd=str(proj_dir), shell=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
            STATE[key]["proc"] = proc
            t_run = threading.Thread(target=enqueue_output, args=(proc.stdout, log_q, "run"), daemon=True)
            t_run.start()

            # Detect port
            detected_port = None
            deadline = time.time() + 60
            while time.time() < deadline and detected_port is None and proc.poll() is None:
                for p in ALLOWED_PORTS + [int(env["PORT"])]:
                    try:
                        r = requests.get(f"http://127.0.0.1:{p}", timeout=1)
                        if r.status_code < 500:
                            detected_port = p
                            break
                    except Exception:
                        pass
                if detected_port: break
                time.sleep(1)

            if not detected_port:
                log("ERROR: Could not detect your app. Make sure it binds to 0.0.0.0.")
                STATE[key]["status"] = "error"
                return

            # Save metadata
            projects = load_json(PROJECTS_JSON, {})
            projects[key] = {
                "owner": owner,
                "name": project,
                "repo_url": repo_url,
                "build_cmd": build_cmd,
                "run_cmd": run_cmd,
                "pid": proc.pid,
                "port": detected_port,
                "repo_dir": str(proj_dir),
                "created_at": int(time.time()),
            }
            save_json(PROJECTS_JSON, projects)

            STATE[key]["port"] = detected_port
            STATE[key]["status"] = "running"
            STATE[key]["url"] = f"{APP_BASE_URL}/{project}"
            log(f"App detected on port {detected_port}. Public URL: {STATE[key]['url']}")

        except Exception as e:
            log(f"Exception: {e}")
            STATE[key]["status"] = "error"

    threading.Thread(target=run, daemon=True).start()

@app.route("/deploy", methods=["GET", "POST"])
@login_required
def deploy():
    if request.method == "POST":
        owner = session["user"]
        project = request.form.get("project_name", "").strip().lower()
        repo_url = request.form.get("repo_url", "").strip()
        build_cmd = request.form.get("build_cmd", "").strip()
        run_cmd = request.form.get("run_cmd", "").strip()
        if not project or not repo_url:
            flash("Project name and GitHub URL are required.", "danger")
            return render_template("deploy.html")
        start_pipeline(owner, project, repo_url, build_cmd, run_cmd)
        flash("Deployment started. View live logs.", "info")
        return redirect(url_for("view_logs", project_name=project))
    return render_template("deploy.html")

@app.route("/logs/<project_name>")
@login_required
def view_logs(project_name):
    return render_template("logs.html", project_name=project_name)

@app.route("/logs/<project_name>/stream")
@login_required
def logs_stream(project_name):
    key = f"{session['user']}:{project_name}"
    if key not in STATE:
        return "unknown project", 404
    q = STATE[key]["log_q"]

    def gen():
        yield "retry: 1000\n\n"
        while True:
            try:
                line = q.get(timeout=1)
                yield f"data: {line}\n\n"
            except queue.Empty:
                status = STATE.get(key, {}).get("status", "?")
                yield f"event: status\ndata: {status}\n\n"
                proc = STATE.get(key, {}).get("proc")
                if proc is not None and proc.poll() is not None and q.empty():
                    break
    return Response(gen(), mimetype="text/event-stream")

# ---------- Proxy ----------
def _proxy_request(port, subpath):
    method = request.method
    url = f"http://127.0.0.1:{port}/{subpath}" if subpath else f"http://127.0.0.1:{port}/"
    headers = {k: v for k, v in request.headers if k.lower() not in ["host", "content-length"]}
    try:
        resp = requests.request(method, url, headers=headers, data=request.get_data(),
                                cookies=request.cookies, stream=True, allow_redirects=False)
    except requests.RequestException as e:
        return f"Upstream error: {e}", 502
    excluded = ["content-encoding", "content-length", "transfer-encoding", "connection"]
    response_headers = [(name, value) for (name, value) in resp.raw.headers.items()
                        if name.lower() not in excluded]
    def generate():
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                yield chunk
    return Response(generate(), status=resp.status_code, headers=response_headers)

@app.route("/<project_name>/")
@app.route("/<project_name>/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def proxy_path(project_name, subpath=""):
    projects = load_json(PROJECTS_JSON, {})
    candidates = [p for p in projects.values() if p["name"] == project_name]
    if not candidates:
        return "Project not found.", 404
    port = candidates[0]["port"]
    return _proxy_request(port, subpath)

# ---------- Run ----------
if __name__ == "__main__":
    load_json(USERS_JSON, {})
    load_json(PROJECTS_JSON, {})
    app.run(host="0.0.0.0", port=3000, debug=True)
