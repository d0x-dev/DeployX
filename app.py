import os
import json
import time
import socket
import shutil
import signal
import subprocess
from pathlib import Path
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, Response
from werkzeug.security import generate_password_hash, check_password_hash
import requests

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
REPO_DIR = BASE_DIR / 'repos'
DATA_DIR.mkdir(exist_ok=True)
REPO_DIR.mkdir(exist_ok=True)

USERS_JSON = DATA_DIR / 'users.json'
PROJECTS_JSON = DATA_DIR / 'projects.json'

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-me')

ALLOWED_PORTS = [5000, 8000]  # we auto-detect these

# ---------------- Utilities ----------------

def load_json(path, default):
    if not path.exists():
        save_json(path, default)
        return default
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def is_port_open(port, host='127.0.0.1'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        try:
            s.connect((host, port))
            return True
        except Exception:
            return False


def kill_process(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass


# ---------------- Auth ----------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    users = load_json(USERS_JSON, {})
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('signup.html')
        if username in users:
            flash('Username already exists.', 'danger')
            return render_template('signup.html')
        users[username] = {
            'password_hash': generate_password_hash(password),
            'created_at': int(time.time())
        }
        save_json(USERS_JSON, users)
        flash('Signup successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    users = load_json(USERS_JSON, {})
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        if username in users and check_password_hash(users[username]['password_hash'], password):
            session['user'] = username
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('user', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


# ---------------- Dashboard & Deploy ----------------
@app.route('/')
@login_required
def dashboard():
    projects = load_json(PROJECTS_JSON, {})
    my = [p for p in projects.values() if p['owner'] == session['user']]
    return render_template('dashboard.html', projects=my)


@app.route('/deploy', methods=['GET', 'POST'])
@login_required
def deploy():
    if request.method == 'POST':
        projects = load_json(PROJECTS_JSON, {})
        owner = session['user']
        project_name = request.form.get('project_name', '').strip().lower()
        repo_url = request.form.get('repo_url', '').strip()
        build_cmd = request.form.get('build_cmd', '').strip() or 'pip install -r requirements.txt'
        run_cmd = request.form.get('run_cmd', '').strip() or 'python3 app.py'

        if not project_name or not repo_url:
            flash('Project name and GitHub URL are required.', 'danger')
            return render_template('deploy.html')
        if '/' in project_name or ' ' in project_name:
            flash('Project name must be a simple slug (no spaces or /).', 'danger')
            return render_template('deploy.html')

        # prepare paths
        proj_key = f"{owner}:{project_name}"
        proj_dir = REPO_DIR / owner / project_name
        if proj_dir.exists():
            shutil.rmtree(proj_dir)
        proj_dir.parent.mkdir(parents=True, exist_ok=True)

        # clone
        try:
            subprocess.check_call(['git', 'clone', '--depth', '1', repo_url, str(proj_dir)])
        except subprocess.CalledProcessError:
            flash('Failed to clone repo. Make sure the URL is public and valid.', 'danger')
            return render_template('deploy.html')

        # build (optional)
        if build_cmd:
            try:
                subprocess.check_call(build_cmd, cwd=str(proj_dir), shell=True)
            except subprocess.CalledProcessError:
                flash('Build step failed. Check your build command/output.', 'danger')
                return render_template('deploy.html')

        # run user app
        try:
            proc = subprocess.Popen(run_cmd, cwd=str(proj_dir), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception:
            flash('Failed to start app. Check your run command.', 'danger')
            return render_template('deploy.html')

        # wait a bit then detect port
        detected_port = None
        started_at = time.time()
        output_snippet = b''
        while time.time() - started_at < 25:
            # collect some logs for UX
            try:
                output_snippet += proc.stdout.read1(2048) if proc.stdout else b''
            except Exception:
                pass
            for p in ALLOWED_PORTS:
                if is_port_open(p):
                    detected_port = p
                    break
            if detected_port:
                break
            time.sleep(0.5)

        if not detected_port:
            kill_process(proc.pid)
            flash('Could not detect your app on port 5000 or 8000. Make sure it binds to 0.0.0.0.', 'danger')
            return render_template('deploy.html')

        # save project metadata
        projects[proj_key] = {
            'owner': owner,
            'name': project_name,
            'repo_url': repo_url,
            'build_cmd': build_cmd,
            'run_cmd': run_cmd,
            'pid': proc.pid,
            'port': detected_port,
            'created_at': int(time.time()),
            'base_path': f"/{project_name}",
        }
        save_json(PROJECTS_JSON, projects)
        flash(f'App is live at {request.host}/{project_name}', 'success')
        return redirect(url_for('projects'))

    return render_template('deploy.html')


@app.route('/projects')
@login_required
def projects():
    projects = load_json(PROJECTS_JSON, {})
    my = [p for p in projects.values() if p['owner'] == session['user']]
    return render_template('projects.html', projects=my)


@app.route('/projects/stop/<project_name>', methods=['POST'])
@login_required
def stop_project(project_name):
    projects = load_json(PROJECTS_JSON, {})
    key = f"{session['user']}:{project_name}"
    if key in projects:
        pid = projects[key].get('pid')
        if pid:
            kill_process(pid)
        del projects[key]
        save_json(PROJECTS_JSON, projects)
        flash('Project stopped and removed.', 'info')
    return redirect(url_for('projects'))


# ---------------- Path-based Reverse Proxy ----------------
# Public route: proxy /<projectname>/... to the user's running app on localhost:detected_port

def _proxy_request(port, subpath):
    method = request.method
    url = f"http://127.0.0.1:{port}/{subpath}" if subpath else f"http://127.0.0.1:{port}/"

    headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'content-length']}
    try:
        resp = requests.request(method, url, headers=headers, data=request.get_data(), cookies=request.cookies, stream=True, allow_redirects=False)
    except requests.RequestException as e:
        return (f"Upstream error: {e}", 502)

    excluded = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    response_headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded]
    def generate():
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                yield chunk
    return Response(generate(), status=resp.status_code, headers=response_headers)


@app.route('/<project_name>/')
def proxy_root(project_name):
    projects = load_json(PROJECTS_JSON, {})
    candidates = [p for p in projects.values() if p['name'] == project_name]
    if not candidates:
        return 'Project not found.', 404
    port = candidates[0]['port']
    return _proxy_request(port, '')


@app.route('/<project_name>/<path:subpath>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
def proxy_path(project_name, subpath):
    projects = load_json(PROJECTS_JSON, {})
    candidates = [p for p in projects.values() if p['name'] == project_name]
    if not candidates:
        return 'Project not found.', 404
    port = candidates[0]['port']
    return _proxy_request(port, subpath)


# ---------------- Static (for any assets you add) ----------------
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(BASE_DIR / 'static', filename)


# ---------------- CLI ----------------
if __name__ == '__main__':
    # Ensure JSON stores exist
    load_json(USERS_JSON, {})
    load_json(PROJECTS_JSON, {})
    app.run(host='0.0.0.0', port=3000, debug=True)
