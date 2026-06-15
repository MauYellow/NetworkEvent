import json
import os
import urllib3
import requests
from datetime import timedelta
from functools import wraps
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

AIRTABLE_TOKEN = os.getenv("AIRTABLE_TOKEN")
BASE_ID        = os.getenv("AIRTABLE_BASE_ID")
USERS_TABLE    = os.getenv("AIRTABLE_TABLE", "Users")
EVENTS_TABLE   = os.getenv("AIRTABLE_EVENTS_TABLE", "Events")

PROFILE_FILE = os.path.join(os.path.dirname(__file__), "profile.json")
AUTH_FILE    = os.path.join(os.path.dirname(__file__), "users_auth.json")

app = Flask(__name__, static_folder="assets", static_url_path="/assets")
app.secret_key                 = os.getenv("SECRET_KEY", "eventnetwork-dev-key-change-this")
app.permanent_session_lifetime = timedelta(days=30)


# ── Auth helpers ──────────────────────────────────────────────────────────────

def load_auth():
    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_auth(data):
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_email" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login_page", next=request.path))
        return f(*args, **kwargs)
    return decorated


# ── Airtable helpers ──────────────────────────────────────────────────────────

def fetch_airtable_records(table):
    url     = f"https://api.airtable.com/v0/{BASE_ID}/{table}"
    headers = {"Authorization": f"Bearer {AIRTABLE_TOKEN}"}
    records = []
    offset  = None

    while True:
        params = {}
        if offset:
            params["offset"] = offset
        r = requests.get(url, headers=headers, params=params, timeout=20, verify=False)
        r.raise_for_status()
        data = r.json()
        records.extend(data["records"])
        offset = data.get("offset")
        if not offset:
            break

    return records


def find_user_by_email(email):
    """Return the first Airtable Users record matching the given email, or None.
    Returns None (instead of raising) when the Email column doesn't exist yet (422)."""
    url     = f"https://api.airtable.com/v0/{BASE_ID}/{USERS_TABLE}"
    headers = {"Authorization": f"Bearer {AIRTABLE_TOKEN}"}
    safe    = email.replace('"', '\\"')
    r = requests.get(url, headers=headers,
                     params={"filterByFormula": f'{{Email}}="{safe}"'},
                     timeout=20, verify=False)
    if r.status_code == 422:
        return None  # Email column not yet created in Airtable
    r.raise_for_status()
    records = r.json().get("records", [])
    return records[0] if records else None


def get_airtable_record(record_id):
    """Fetch a single Airtable Users record by its ID."""
    url     = f"https://api.airtable.com/v0/{BASE_ID}/{USERS_TABLE}/{record_id}"
    headers = {"Authorization": f"Bearer {AIRTABLE_TOKEN}"}
    r = requests.get(url, headers=headers, timeout=20, verify=False)
    return r.json() if r.ok else None


def update_airtable_record(record_id, fields):
    url     = f"https://api.airtable.com/v0/{BASE_ID}/{USERS_TABLE}/{record_id}"
    headers = {"Authorization": f"Bearer {AIRTABLE_TOKEN}", "Content-Type": "application/json"}
    r = requests.patch(url, headers=headers, json={"fields": fields}, timeout=20, verify=False)
    r.raise_for_status()
    return r.json()


def delete_airtable_record(record_id):
    url     = f"https://api.airtable.com/v0/{BASE_ID}/{USERS_TABLE}/{record_id}"
    headers = {"Authorization": f"Bearer {AIRTABLE_TOKEN}"}
    r = requests.delete(url, headers=headers, timeout=20, verify=False)
    r.raise_for_status()


def parse_users(records):
    rows = []
    for record in records:
        fields = record.get("fields", {})
        coords = fields.get("Coordinates")
        lat = lon = None

        if isinstance(coords, dict):
            lat = coords.get("latitude")
            lon = coords.get("longitude")
        elif isinstance(coords, str) and "," in coords:
            try:
                lat, lon = coords.split(",")
                lat = float(lat.strip())
                lon = float(lon.strip())
            except Exception:
                pass

        rows.append({
            "name":          fields.get("Name"),
            "event":         fields.get("Event"),
            "linkedin":      fields.get("Linkedin"),
            "role":          fields.get("Role"),
            "area":          fields.get("Functional Area"),
            "lat":           lat,
            "lon":           lon,
            "record_id":     record.get("id"),
            "flags":         int(fields.get("flags") or 0),
            "working_event": (fields.get("Working_event") or "").strip().lower() == "yes",
        })
    return rows


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if "user_email" in session:
        return redirect("/")

    error = None
    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        authenticated = False
        user_name     = email

        # Primary: check Airtable Users table
        try:
            record = find_user_by_email(email)
            if record:
                fields   = record.get("fields", {})
                pwd_hash = fields.get("Password_hash", "")
                if pwd_hash and check_password_hash(pwd_hash, password):
                    user_name     = fields.get("Name", email)
                    authenticated = True
                    # Sync to local cache so future logins skip Airtable when possible
                    auth = load_auth()
                    auth[email] = {"name": user_name, "password_hash": pwd_hash}
                    save_auth(auth)
        except Exception:
            pass

        # Fallback: local auth file (handles users registered before Airtable sync)
        if not authenticated:
            auth = load_auth()
            user = auth.get(email)
            if user and check_password_hash(user.get("password_hash", ""), password):
                user_name     = user.get("name", email)
                authenticated = True

        if authenticated:
            session.clear()
            session["user_email"] = email
            session["user_name"]  = user_name
            if remember:
                session.permanent = True
            return redirect(request.args.get("next") or "/")

        error = "Incorrect email or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def home():
    return render_template("map.html", active_page="map")


@app.route("/events")
@login_required
def events():
    return render_template("events.html", active_page="events")


@app.route("/register")
def register():
    if "user_email" in session:
        return redirect("/profile")
    return render_template("register.html", active_page=None)


@app.route("/colleagues")
@login_required
def colleagues():
    return render_template("colleagues.html", active_page="colleagues")


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", active_page="profile")


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/points")
@login_required
def api_points():
    records = fetch_airtable_records(USERS_TABLE)
    return jsonify(parse_users(records))


@app.route("/api/events")
def api_events():
    records = fetch_airtable_records(EVENTS_TABLE)
    def _event_date_key(r):
        raw = r.get("fields", {}).get("Event_starting_date") or ""
        return raw[:10] if raw else "9999-99-99"

    records.sort(key=_event_date_key)
    return jsonify([{"id": r["id"], "fields": r.get("fields", {})} for r in records])


@app.route("/api/profile", methods=["GET", "POST"])
@login_required
def api_profile():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        # Save locally
        with open(PROFILE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Sync to Airtable using stored airtable_id
        email      = session.get("user_email", "").lower()
        airtable_warning = None
        if email:
            auth      = load_auth()
            user_auth = auth.get(email, {})
            airtable_id = user_auth.get("airtable_id")

            try:
                if not airtable_id:
                    record = find_user_by_email(email)
                    if record:
                        airtable_id = record["id"]
                        user_auth["airtable_id"] = airtable_id
                        auth[email] = user_auth
                        save_auth(auth)

                if airtable_id:
                    fname  = data.get("fname", "").strip()
                    lname  = data.get("lname", "").strip()
                    fields = {}
                    if fname or lname:
                        fields["Name"] = f"{fname} {lname}".strip()
                    for payload_key, at_key in [
                        ("role",     "Role"),
                        ("area",     "Functional Area"),
                        ("linkedin", "Linkedin"),
                    ]:
                        val = data.get(payload_key, "").strip()
                        if val:
                            fields[at_key] = val
                    lat = data.get("lat", "")
                    lon = data.get("lon", "")
                    if lat and lon:
                        fields["Coordinates"] = f"{lat}, {lon}"
                    events = data.get("sport_events_selected", [])
                    if events:
                        fields["Event"] = ", ".join(events)
                    fields["Working_event"] = "Yes" if data.get("sport_events_active") else "No"
                    if fields:
                        update_airtable_record(airtable_id, fields)
                else:
                    airtable_warning = "No Airtable record found for this account."
            except Exception as e:
                airtable_warning = str(e)

        resp = {"ok": True}
        if airtable_warning:
            resp["warning"] = airtable_warning
        return jsonify(resp)

    # Load local data (gdpr_consent and other non-Airtable fields)
    local = {}
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            local = json.load(f)

    # Fetch authoritative data from Airtable
    email     = session.get("user_email", "").lower()
    if email:
        auth      = load_auth()
        user_auth = auth.get(email, {})
        airtable_id = user_auth.get("airtable_id")
        try:
            record = get_airtable_record(airtable_id) if airtable_id else None
            if not record:
                record = find_user_by_email(email)
                if record:
                    user_auth["airtable_id"] = record["id"]
                    auth[email] = user_auth
                    save_auth(auth)

            if record:
                f = record.get("fields", {})

                name_parts = (f.get("Name") or "").split(" ", 1)
                fname = name_parts[0]
                lname = name_parts[1] if len(name_parts) > 1 else ""

                lat = lon = ""
                coords = f.get("Coordinates") or ""
                if "," in coords:
                    lat, lon = [p.strip() for p in coords.split(",", 1)]

                event_str = f.get("Event") or ""
                events    = [e.strip() for e in event_str.split(",") if e.strip()]

                airtable_data = {
                    "fname":                 fname,
                    "lname":                 lname,
                    "email":                 email,
                    "role":                  f.get("Role", ""),
                    "area":                  f.get("Functional Area", ""),
                    "linkedin":              f.get("Linkedin", ""),
                    "lat":                   lat,
                    "lon":                   lon,
                    "sport_events_active":   (f.get("Working_event") or "").strip().lower() == "yes",
                    "sport_events_selected": events,
                }
                # Airtable is source of truth; local fills non-Airtable fields
                return jsonify({**local, **airtable_data})
        except Exception:
            pass

    return jsonify(local)


@app.route("/api/profile/password", methods=["POST"])
def api_profile_password():
    data         = request.get_json(silent=True) or {}
    new_password = data.get("new_password", "")

    if not new_password or len(new_password) < 6:
        return jsonify({"ok": False, "error": "Password too short (min 6 characters)"}), 400

    profile = {}
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            profile = json.load(f)

    pwd_hash             = generate_password_hash(new_password)
    profile["password_hash"] = pwd_hash

    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2, ensure_ascii=False)

    email = profile.get("email", "").strip().lower()
    if email:
        name = f"{profile.get('fname', '')} {profile.get('lname', '')}".strip() or email

        # Update local cache
        auth = load_auth()
        auth[email] = {"name": name, "password_hash": pwd_hash}
        save_auth(auth)

        # Update Airtable record
        try:
            record = find_user_by_email(email)
            if record:
                update_airtable_record(record["id"], {"Password_hash": pwd_hash})
        except Exception:
            pass

        return jsonify({"ok": True, "email": email})

    return jsonify({"ok": True, "warning": "No email set in profile — credentials not saved for login."})


@app.route("/api/save-job", methods=["POST"])
def api_save_job():
    data     = request.get_json(silent=True) or {}
    fname    = data.get("fname", "").strip()
    lname    = data.get("lname", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    events   = data.get("events", [])
    lat      = data.get("lat", "")
    lon      = data.get("lon", "")

    if not fname or not lname:
        return jsonify({"ok": False, "error": "Please fill in your first and last name before saving."}), 400
    if not email:
        return jsonify({"ok": False, "error": "Please fill in your email address — it will be used to sign in."}), 400
    if not password or len(password) < 8:
        return jsonify({"ok": False, "error": "Please set a password of at least 8 characters."}), 400
    # Check for duplicate email (Airtable first, then local cache)
    try:
        if find_user_by_email(email):
            return jsonify({"ok": False, "error": f'An account with email "{email}" already exists.'}), 409
    except Exception:
        pass  # Airtable unreachable — fall through to local check
    if email in load_auth():
        return jsonify({"ok": False, "error": f'An account with email "{email}" already exists.'}), 409

    full_name = f"{fname} {lname}"
    url       = f"https://api.airtable.com/v0/{BASE_ID}/{USERS_TABLE}"
    headers   = {"Authorization": f"Bearer {AIRTABLE_TOKEN}"}
    safe_name = full_name.replace('"', '\\"')

    check = requests.get(url, headers=headers,
                         params={"filterByFormula": f'{{Name}}="{safe_name}"'},
                         timeout=20, verify=False)
    check.raise_for_status()

    if check.json().get("records"):
        return jsonify({"ok": False, "error": f'"{full_name}" is already registered in the database.'}), 409

    pwd_hash   = generate_password_hash(password)
    sport_active = data.get("sport_active", False)
    new_fields = {
        "Name":            full_name,
        "Email":           email,
        "Password_hash":   pwd_hash,
        "Event":           ", ".join(events),
        "Coordinates":     f"{lat}, {lon}",
        "Role":            data.get("role", ""),
        "Functional Area": data.get("area", ""),
        "Linkedin":        data.get("linkedin", ""),
        "Working_event":   "Yes" if sport_active else "No",
    }
    new_fields = {k: v for k, v in new_fields.items() if v}

    create = requests.post(url,
                           headers={**headers, "Content-Type": "application/json"},
                           json={"fields": new_fields},
                           timeout=20, verify=False)
    if create.status_code == 422:
        # Email / Password_hash columns don't exist yet — retry without them
        fallback_fields = {k: v for k, v in new_fields.items()
                           if k not in ("Email", "Password_hash")}
        create = requests.post(url,
                               headers={**headers, "Content-Type": "application/json"},
                               json={"fields": fallback_fields},
                               timeout=20, verify=False)
    create.raise_for_status()

    # Save to local auth cache, storing the Airtable record ID for future updates
    airtable_id = create.json().get("id")
    auth = load_auth()
    auth[email] = {"name": full_name, "password_hash": pwd_hash, "airtable_id": airtable_id}
    save_auth(auth)

    return jsonify({"ok": True, "id": airtable_id, "name": full_name})


@app.route("/api/flag-user", methods=["POST"])
@login_required
def api_flag_user():
    data      = request.get_json(silent=True) or {}
    record_id = data.get("record_id", "").strip()
    if not record_id:
        return jsonify({"ok": False, "error": "Missing record_id"}), 400

    record = get_airtable_record(record_id)
    if not record:
        return jsonify({"ok": False, "error": "User not found"}), 404

    new_flags = int(record.get("fields", {}).get("flags") or 0) + 1
    update_airtable_record(record_id, {"flags": new_flags})
    return jsonify({"ok": True, "flags": new_flags})


@app.route("/api/delete-account", methods=["POST"])
@login_required
def api_delete_account():
    email       = session.get("user_email", "").lower().strip()
    airtable_id = session.get("airtable_id")

    # 1. Delete from Airtable
    if airtable_id:
        try:
            delete_airtable_record(airtable_id)
        except Exception:
            pass  # Best-effort; proceed with local cleanup regardless
    else:
        # Fallback: find by email
        try:
            record = find_user_by_email(email)
            if record:
                delete_airtable_record(record["id"])
        except Exception:
            pass

    # 2. Remove from local auth cache
    auth = load_auth()
    if email in auth:
        del auth[email]
        save_auth(auth)

    # 3. Clear session
    session.clear()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True)
