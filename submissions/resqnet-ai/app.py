from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    send_from_directory
) 

from db2_database import save_incident_to_db2
from functools import wraps
from database import get_connection
from ai_engine import analyze_incident

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from datetime import datetime
import os
import re
import uuid
from werkzeug.utils import secure_filename


# =====================================================
# APPLICATION CONFIGURATION
# =====================================================

app = Flask(__name__) 
import requests

def calculate_rescue_eta(
    user_lat,
    user_lon,
    responder_lat,
    responder_lon
):
    try:
        url = (
            "https://router.project-osrm.org/route/v1/driving/"
            f"{responder_lon},{responder_lat};"
            f"{user_lon},{user_lat}"
        )

        response = requests.get(
            url,
            params={"overview": "false"},
            timeout=8
        )

        response.raise_for_status()
        data = response.json()

        if data.get("code") != "Ok" or not data.get("routes"):
            return None

        seconds = data["routes"][0]["duration"]
        return round(seconds / 60)

    except (requests.RequestException, ValueError, TypeError, KeyError):
        return None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PHOTO_UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "static",
    "uploads",
    "emergency_photos"
)

os.makedirs(PHOTO_UPLOAD_FOLDER, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {
    "jpg",
    "jpeg",
    "png",
    "webp"
}




# =========================================
# ANONYMOUS CRIME REPORTER CONFIGURATION
# =========================================

ANONYMOUS_UPLOAD_FOLDER = os.path.join(
    app.root_path,
    "uploads",
    "anonymous_evidence"
)

ANONYMOUS_ALLOWED_EXTENSIONS = {
    "mp4",
    "webm",
    "mov"
}

ANONYMOUS_MAX_VIDEO_SIZE = 50 * 1024 * 1024

os.makedirs(
    ANONYMOUS_UPLOAD_FOLDER,
    exist_ok=True
)

app.secret_key = os.environ.get(
    "RESQNET_SECRET_KEY",
    "resqnet-development-key-change-before-deployment"
)


# =====================================================
# AUTHENTICATION DECORATORS
# =====================================================

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("user_id"):
            flash("Please login to access this page.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("user_id"):
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        if session.get("user_role") != "admin":
            flash(
                "Admin permission required. Please use an admin account.",
                "error"
            )
            return redirect(url_for("dashboard"))

        return function(*args, **kwargs)

    return wrapper


# =====================================================
# DATABASE HELPER
# =====================================================

def close_database(cursor=None, connection=None):

    if cursor:
        cursor.close()

    if connection and connection.is_connected():
        connection.close()


# =====================================================
# HOME PAGE
# =====================================================

@app.route("/")
def home():

    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# =====================================================
# REGISTER
# =====================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get(
            "full_name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not full_name or not email or not password:
            flash("Please fill all required fields.", "error")
            return redirect(url_for("register"))

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        connection = None
        cursor = None

        try:

            connection = get_connection()
            cursor = connection.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,)
            )

            if cursor.fetchone():

                flash(
                    "This email is already registered. Please login.",
                    "error"
                )

                return redirect(url_for("login"))

            password_hash = generate_password_hash(password)

            # Public registration always creates a normal user.
            cursor.execute(
                """
                INSERT INTO users
                    (full_name, email, password_hash, role)
                VALUES
                    (%s, %s, %s, 'user')
                """,
                (full_name, email, password_hash)
            )

            connection.commit()

            flash(
                "Registration successful. Please login.",
                "success"
            )

            return redirect(url_for("login"))

        except Exception:

            if connection:
                connection.rollback()

            app.logger.exception("Registration failed.")

            flash(
                "Registration failed. Check the VS Code terminal.",
                "error"
            )

        finally:
            close_database(cursor, connection)

    return render_template("register.html")


# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        connection = None
        cursor = None

        try:

            connection = get_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT
                    id,
                    full_name,
                    email,
                    password_hash,
                    role
                FROM users
                WHERE email = %s
                """,
                (email,)
            )

            user = cursor.fetchone()

            if (
                user
                and check_password_hash(
                    user["password_hash"],
                    password
                )
            ):

                session.clear()

                session["user_id"] = user["id"]
                session["user_name"] = user["full_name"]
                session["user_role"] = user["role"]

                flash("Login successful.", "success")

                return redirect(url_for("dashboard"))

            flash("Invalid email or password.", "error")

        except Exception:

            app.logger.exception("Login failed.")

            flash(
                "Login failed. Check the VS Code terminal.",
                "error"
            )

        finally:
            close_database(cursor, connection)

    return render_template("login.html")


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# =====================================================
# REPORT EMERGENCY PAGE
# =====================================================

@app.route("/report")
@login_required
def report():

    return render_template("report.html")


# =====================================================
# SUBMIT EMERGENCY REPORT - MYSQL + IBM DB2
# =====================================================

@app.route("/submit-report", methods=["POST"])
@login_required
def submit_report():

    emergency_type = request.form.get(
        "emergency_type", ""
    ).strip()

    description = request.form.get(
        "description", ""
    ).strip()

    latitude = request.form.get("latitude") or None
    longitude = request.form.get("longitude") or None

    if not emergency_type or not description:
        flash(
            "Please enter emergency type and description.",
            "error"
        )
        return redirect(url_for("report"))

    try:

        if latitude is not None:
            latitude = float(latitude)

            if not -90 <= latitude <= 90:
                raise ValueError

        if longitude is not None:
            longitude = float(longitude)

            if not -180 <= longitude <= 180:
                raise ValueError

    except (ValueError, TypeError):

        flash("Invalid location coordinates.", "error")
        return redirect(url_for("report"))

    connection = None
    cursor = None

    try:

        result = analyze_incident(
            emergency_type,
            description
        )

        # STEP 1: SAVE REPORT IN MYSQL

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO incidents
            (
                emergency_type,
                description,
                latitude,
                longitude,
                severity,
                priority,
                recommended_resources,
                ai_reason
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                emergency_type,
                description,
                latitude,
                longitude,
                result["severity"],
                result["priority"],
                result["resources"],
                result["reason"]
            )
        )

        # Get MySQL incident ID
        mysql_incident_id = cursor.lastrowid

        # Commit MySQL first
        connection.commit()

        # STEP 2: SEND SAME REPORT TO IBM DB2

        incident_data = {
            "id": mysql_incident_id,
            "emergency_type": emergency_type,
            "description": description,
            "latitude": latitude,
            "longitude": longitude,
            "severity": result["severity"],
            "priority": result["priority"],
            "ai_reason": result["reason"]
        }

        try:

            save_incident_to_db2(incident_data)

            app.logger.info(
                "Incident %s successfully synced to IBM Db2.",
                mysql_incident_id
            )

            flash(
                "Emergency report saved successfully in MySQL and IBM Db2.",
                "success"
            )

        except Exception:

            app.logger.exception(
                "IBM Db2 synchronization failed for incident %s.",
                mysql_incident_id
            )

            flash(
                "Report saved in MySQL, but IBM Db2 synchronization failed.",
                "warning"
            )

    except Exception:

        if connection:
            connection.rollback()

        app.logger.exception(
            "Emergency report submission failed."
        )

        flash(
            "Could not save the report. Check the terminal.",
            "error"
        )

    finally:

        close_database(cursor, connection)

    return redirect(url_for("dashboard")) 


# =====================================================
# COMMAND CENTER DASHBOARD
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY created_at DESC
            """
        )

        incidents = cursor.fetchall()

        total = len(incidents)

        pending = sum(
            1 for item in incidents
            if (item.get("status") or "Pending").lower() == "pending"
        )

        in_progress = sum(
            1 for item in incidents
            if (item.get("status") or "").lower() == "in progress"
        )

        resolved = sum(
            1 for item in incidents
            if (item.get("status") or "").lower() == "resolved"
        )

        critical = sum(
            1 for item in incidents
            if (item.get("severity") or "").lower() == "critical"
        )

        priority_p1 = sum(
            1 for item in incidents
            if (item.get("priority") or "").upper() == "P1"
        )

        return render_template(
            "dashboard.html",
            incidents=incidents,
            total_incidents=total,
            pending_count=pending,
            in_progress_count=in_progress,
            resolved_count=resolved,
            critical_count=critical,
            priority_p1_count=priority_p1
        )

    finally:
        close_database(cursor, connection)


# =====================================================
# EMERGENCY MAP - ADMIN ONLY
# =====================================================

@app.route("/map")
@admin_required
def emergency_map():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                id,
                emergency_type,
                description,
                latitude,
                longitude,
                status,
                severity,
                priority
            FROM incidents
            ORDER BY created_at DESC
            """
        )

        rows = cursor.fetchall()
        incidents = []

        for row in rows:

            if row["latitude"] is None or row["longitude"] is None:
                continue

            incidents.append({
                "id": row["id"],
                "type": row["emergency_type"],
                "description": row["description"] or "",
                "latitude": float(row["latitude"]),
                "longitude": float(row["longitude"]),
                "status": row["status"] or "Pending",
                "severity": row["severity"] or "Not Analyzed",
                "priority": row["priority"] or "P3"
            })

        return render_template(
            "map.html",
            incidents=incidents,
            total_reports=len(rows)
        )

    finally:
        close_database(cursor, connection)


# =====================================================
# RESPONDER MANAGEMENT - ADMIN ONLY
# =====================================================

@app.route("/responders")
@admin_required
def responders():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT *
            FROM responders
            ORDER BY id DESC
            """
        )

        responder_list = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                i.*,
                r.name AS responder_name,
                r.role AS responder_role
            FROM incidents i
            LEFT JOIN responders r
                ON i.responder_id = r.id
            ORDER BY i.created_at DESC
            """
        )

        incidents = cursor.fetchall()

        return render_template(
            "responders.html",
            responders=responder_list,
            incidents=incidents
        )

    finally:
        close_database(cursor, connection)


# =====================================================
# ADD RESPONDER
# =====================================================

@app.route("/add-responder", methods=["POST"])
@admin_required
def add_responder():

    name = request.form.get("name", "").strip()
    role = request.form.get("role", "").strip()
    phone = request.form.get("phone", "").strip()

    if not name or not role:

        flash("Name and role are required.", "error")

        return redirect(url_for("responders"))

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO responders (name, role, phone)
            VALUES (%s, %s, %s)
            """,
            (name, role, phone or None)
        )

        connection.commit()

        flash("Responder added successfully.", "success")

    except Exception:

        if connection:
            connection.rollback()

        app.logger.exception("Could not add responder.")

        flash("Could not add responder.", "error")

    finally:
        close_database(cursor, connection)

    return redirect(url_for("responders"))


# =====================================================
# ASSIGN RESPONDER TO INCIDENT
# =====================================================

@app.route("/assign-responder", methods=["POST"])
@admin_required
def assign_responder():

    incident_id = request.form.get("incident_id", "")
    responder_id = request.form.get("responder_id", "")

    if not incident_id.isdigit() or not responder_id.isdigit():

        flash("Select a valid incident and responder.", "error")

        return redirect(url_for("responders"))

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute(
            "SELECT id FROM incidents WHERE id = %s FOR UPDATE",
            (int(incident_id),)
        )

        incident = cursor.fetchone()

        cursor.execute(
            """
            SELECT id, availability
            FROM responders
            WHERE id = %s
            FOR UPDATE
            """,
            (int(responder_id),)
        )

        responder = cursor.fetchone()

        if not incident or not responder:

            connection.rollback()

            flash("Incident or responder not found.", "error")

            return redirect(url_for("responders"))

        if responder["availability"] != "Available":

            connection.rollback()

            flash("This responder is not available.", "error")

            return redirect(url_for("responders"))

        cursor.execute(
            """
            UPDATE incidents
            SET responder_id = %s,
                assigned_at = CURRENT_TIMESTAMP,
                status = 'In Progress'
            WHERE id = %s
            """,
            (int(responder_id), int(incident_id))
        )

        cursor.execute(
            """
            UPDATE responders
            SET availability = 'Busy'
            WHERE id = %s
            """,
            (int(responder_id),)
        )

        connection.commit()

        flash("Responder assigned successfully.", "success")

    except Exception:

        if connection:
            connection.rollback()

        app.logger.exception("Responder assignment failed.")

        flash(
            "Assignment failed. Check the terminal.",
            "error"
        )

    finally:
        close_database(cursor, connection)

    return redirect(url_for("responders"))


# =====================================================
# UPDATE INCIDENT STATUS
# =====================================================

@app.route("/update-status", methods=["POST"])
@admin_required
def update_status():

    incident_id = request.form.get("incident_id", "")
    new_status = request.form.get("status", "")

    allowed_statuses = {
        "Pending",
        "In Progress",
        "Resolved"
    }

    if not incident_id.isdigit() or new_status not in allowed_statuses:

        flash("Invalid incident or status.", "error")

        return redirect(url_for("responders"))

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        connection.start_transaction()

        cursor.execute(
            """
            SELECT responder_id
            FROM incidents
            WHERE id = %s
            FOR UPDATE
            """,
            (int(incident_id),)
        )

        incident = cursor.fetchone()

        if not incident:

            connection.rollback()

            flash("Incident not found.", "error")

            return redirect(url_for("responders"))

        responder_id = incident["responder_id"]

        cursor.execute(
            """
            UPDATE incidents
            SET status = %s
            WHERE id = %s
            """,
            (new_status, int(incident_id))
        )

        if responder_id is not None:

            if new_status == "Resolved":

                cursor.execute(
                    """
                    UPDATE responders
                    SET availability = 'Available'
                    WHERE id = %s
                    """,
                    (responder_id,)
                )

            elif new_status == "In Progress":

                cursor.execute(
                    """
                    UPDATE responders
                    SET availability = 'Busy'
                    WHERE id = %s
                    """,
                    (responder_id,)
                )

        connection.commit()

        flash("Incident status updated.", "success")

    except Exception:

        if connection:
            connection.rollback()

        app.logger.exception("Status update failed.")

        flash("Could not update status.", "error")

    finally:
        close_database(cursor, connection)

    return redirect(url_for("responders"))


# =====================================================
# ANALYTICS DASHBOARD - ADMIN ONLY
# =====================================================

@app.route("/analytics")
@admin_required
def analytics():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY created_at DESC
            """
        )

        all_incidents = cursor.fetchall()

        cursor.execute(
            "SELECT COUNT(*) AS total FROM responders"
        )

        responder_result = cursor.fetchone()

        status_counts = {}
        severity_counts = {}
        type_counts = {}
        daily_counts = {}

        for incident in all_incidents:

            status = incident.get("status") or "Pending"
            status_counts[status] = status_counts.get(status, 0) + 1

            severity = incident.get("severity") or "Not Analyzed"
            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )

            emergency_type = incident.get("emergency_type") or "Other"
            type_counts[emergency_type] = (
                type_counts.get(emergency_type, 0) + 1
            )

            created_at = incident.get("created_at")

            if created_at:

                day = created_at.strftime("%d-%m-%Y")

                daily_counts[day] = daily_counts.get(day, 0) + 1

        sorted_days = sorted(
            daily_counts.keys(),
            key=lambda day: datetime.strptime(day, "%d-%m-%Y")
        )[-14:]

        stats = {
            "total": len(all_incidents),

            "pending": sum(
                1 for item in all_incidents
                if (item.get("status") or "Pending").lower() == "pending"
            ),

            "in_progress": sum(
                1 for item in all_incidents
                if (item.get("status") or "").lower() == "in progress"
            ),

            "resolved": sum(
                1 for item in all_incidents
                if (item.get("status") or "").lower() == "resolved"
            ),

            "critical": sum(
                1 for item in all_incidents
                if (item.get("severity") or "").lower() == "critical"
            ),

            "responders": responder_result["total"]
        }

        return render_template(
            "analytics.html",
            stats=stats,
            recent_incidents=all_incidents[:15],
            status_labels=list(status_counts.keys()),
            status_values=list(status_counts.values()),
            severity_labels=list(severity_counts.keys()),
            severity_values=list(severity_counts.values()),
            type_labels=list(type_counts.keys()),
            type_values=list(type_counts.values()),
            trend_labels=sorted_days,
            trend_values=[
                daily_counts[day] for day in sorted_days
            ]
        )

    finally:
        close_database(cursor, connection)


# =====================================================
# WOMEN SAFETY DASHBOARD - LOGIN REQUIRED
# =====================================================

@app.route("/women-safety")
@login_required
def women_safety():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT *
            FROM women_safety_reports
            ORDER BY created_at DESC
            LIMIT 100
            """
        )

        reports = cursor.fetchall()

        stats = {
            "total": len(reports),
            "pending": sum(
                1 for item in reports
                if (item.get("status") or "Pending").lower() == "pending"
            ),
            "resolved": sum(
                1 for item in reports
                if (item.get("status") or "").lower() == "resolved"
            )
        }

        return render_template(
            "women_safety.html",
            reports=reports,
            stats=stats,
            total_reports=stats["total"],
            pending_reports=stats["pending"],
            resolved_reports=stats["resolved"]
        )

    except Exception:

        app.logger.exception("Women Safety dashboard failed.")

        return (
            "Women Safety dashboard could not load. "
            "Check the VS Code terminal.",
            500
        )

    finally:
        close_database(cursor, connection)

@app.route("/api/rescue-eta", methods=["POST"])
def rescue_eta_api():
    data = request.get_json(silent=True) or {}

    required_fields = [
        "user_lat",
        "user_lon",
        "responder_lat",
        "responder_lon"
    ]

    if not all(field in data for field in required_fields):
        return jsonify({
            "success": False,
            "message": "All four coordinates are required",
            "eta_minutes": None
        }), 400

    result = calculate_rescue_eta(
        data["user_lat"],
        data["user_lon"],
        data["responder_lat"],
        data["responder_lon"]
    )

    status_code = 200 if result["success"] else 503

    return jsonify(result), status_code


# =====================================================
# SUBMIT WOMEN SAFETY REPORT
# =====================================================

@app.route("/submit-women-safety-report", methods=["POST"])
@login_required
def submit_women_safety_report():

    incident_type = request.form.get(
        "incident_type", "Other"
    ).strip()

    description = request.form.get(
        "description", ""
    ).strip()

    contact_name = request.form.get(
        "contact_name", ""
    ).strip()

    contact_phone = request.form.get(
        "contact_phone", ""
    ).strip()

    latitude = request.form.get("latitude", "").strip()
    longitude = request.form.get("longitude", "").strip()

    if not incident_type:

        flash("Please select an incident type.", "error")

        return redirect(url_for("women_safety"))

    try:

        latitude = float(latitude) if latitude else None
        longitude = float(longitude) if longitude else None

        if latitude is not None and not -90 <= latitude <= 90:
            raise ValueError

        if longitude is not None and not -180 <= longitude <= 180:
            raise ValueError

    except (ValueError, TypeError):

        flash("Invalid location coordinates.", "error")

        return redirect(url_for("women_safety"))

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO women_safety_reports
            (
                incident_type,
                description,
                latitude,
                longitude,
                contact_name,
                contact_phone,
                status,
                priority
            )
            VALUES (%s, %s, %s, %s, %s, %s, 'Pending', 'High')
            """,
            (
                incident_type,
                description,
                latitude,
                longitude,
                contact_name,
                contact_phone
            )
        )

        connection.commit()

        flash(
            "Safety report saved. This prototype has not contacted "
            "emergency services.",
            "success"
        )

    except Exception:

        if connection:
            connection.rollback()

        app.logger.exception("Women Safety report submission failed.")

        flash("Unable to save safety report.", "error")

    finally:
        close_database(cursor, connection)

    return redirect(url_for("women_safety"))


# =====================================================
# UPDATE WOMEN SAFETY REPORT STATUS - ADMIN ONLY
# =====================================================

@app.route("/update-women-safety-status", methods=["POST"])
@admin_required
def update_women_safety_status():

    report_id = request.form.get("report_id", "").strip()
    new_status = request.form.get("status", "").strip()

    allowed_statuses = {
        "Pending",
        "In Progress",
        "Resolved"
    }

    if not report_id.isdigit() or new_status not in allowed_statuses:

        flash("Invalid report or status.", "error")

        return redirect(url_for("women_safety"))

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE women_safety_reports
            SET status = %s
            WHERE id = %s
            """,
            (new_status, int(report_id))
        )

        connection.commit()

        flash("Women Safety report status updated.", "success")

    except Exception:

        if connection:
            connection.rollback()

        app.logger.exception("Women Safety status update failed.")

        flash("Unable to update report status.", "error")

    finally:
        close_database(cursor, connection)

    return redirect(url_for("women_safety"))


# =====================================================
# WOMEN SAFETY MAP - ADMIN ONLY
# =====================================================

@app.route("/women-safety-map")
@admin_required
def women_safety_map():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                id,
                incident_type,
                description,
                latitude,
                longitude,
                status,
                priority,
                created_at
            FROM women_safety_reports
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
            ORDER BY created_at DESC
            """
        )

        reports = cursor.fetchall()

        for item in reports:

            item["latitude"] = float(item["latitude"])
            item["longitude"] = float(item["longitude"])

            if item.get("created_at"):
                item["created_at"] = item["created_at"].isoformat()

        return render_template(
            "women_safety_map.html",
            reports=reports
        )

    except Exception:

        app.logger.exception("Women Safety Map failed.")

        return (
            "Unable to load Women Safety Map. "
            "Check the VS Code terminal.",
            500
        )

    finally:
        close_database(cursor, connection)


# =====================================================
# SOS EMERGENCY PAGE
# =====================================================

@app.route("/sos", methods=["GET", "POST"])
@login_required
def sos():

    if request.method == "GET":
        return render_template("sos.html")

    emergency_type = request.form.get(
        "emergency_type",
        request.form.get("incident_type", "Personal Emergency")
    ).strip()

    description = request.form.get(
        "description", ""
    ).strip()

    contact_name = request.form.get(
        "contact_name", ""
    ).strip()

    contact_phone = request.form.get(
        "contact_phone", ""
    ).strip()

    latitude = request.form.get("latitude", "").strip()
    longitude = request.form.get("longitude", "").strip()

    try:

        latitude = float(latitude) if latitude else None
        longitude = float(longitude) if longitude else None

        if latitude is not None and not -90 <= latitude <= 90:
            raise ValueError

        if longitude is not None and not -180 <= longitude <= 180:
            raise ValueError

    except (ValueError, TypeError):

        flash("Invalid location coordinates.", "error")

        return redirect(url_for("sos"))

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO women_safety_reports
            (
                incident_type,
                description,
                latitude,
                longitude,
                contact_name,
                contact_phone,
                status,
                priority
            )
            VALUES (%s, %s, %s, %s, %s, %s, 'Pending', 'High')
            """,
            (
                emergency_type or "Personal Emergency",
                description,
                latitude,
                longitude,
                contact_name,
                contact_phone
            )
        )

        connection.commit()

        flash(
            "SOS report saved. No emergency call or SMS was sent "
            "automatically by this prototype.",
            "success"
        )

        return redirect(url_for("sos"))

    except Exception:

        if connection:
            connection.rollback()

        app.logger.exception("SOS report submission failed.")

        flash("Unable to save SOS report.", "error")

    finally:
        close_database(cursor, connection)

    return redirect(url_for("sos"))


# =====================================================
# ERROR HANDLERS
# =====================================================

@app.errorhandler(404)
def page_not_found(error):

    return (
        render_template("index.html"),
        404
    )


# =====================================================
# RUN APPLICATION
# Keep app.run at the VERY END of this file.
# =====================================================



# =====================================================
# VIDEO EVIDENCE UPLOAD AND ADMIN REVIEW
# Requires the evidence_reports MySQL table and templates:
# evidence_upload.html, evidence_success.html, admin_evidence.html
# =====================================================

EVIDENCE_FOLDER = os.path.join(app.root_path, "uploads", "evidence")
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm", "mov"}
MAX_EVIDENCE_SIZE = 100 * 1024 * 1024  # 100 MB
os.makedirs(EVIDENCE_FOLDER, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = MAX_EVIDENCE_SIZE


def allowed_evidence_video(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS


@app.route("/evidence/upload", methods=["GET", "POST"])
@login_required
def upload_evidence():
    if request.method == "GET":
        return render_template("evidence_upload.html")

    incident_type = request.form.get("incident_type", "").strip()
    description = request.form.get("description", "").strip()
    incident_datetime_text = request.form.get("incident_datetime", "").strip()
    latitude_text = request.form.get("latitude", "").strip()
    longitude_text = request.form.get("longitude", "").strip()
    contact_name = request.form.get("contact_name", "").strip()
    contact_phone = request.form.get("contact_phone", "").strip()

    if request.form.get("privacy_consent") != "yes":
        flash("Please confirm the evidence privacy acknowledgement.", "error")
        return redirect(url_for("upload_evidence"))
    if not incident_type or not description:
        flash("Please enter incident type and description.", "error")
        return redirect(url_for("upload_evidence"))

    video = request.files.get("video")
    if not video or not video.filename:
        flash("Please choose a video file.", "error")
        return redirect(url_for("upload_evidence"))

    original_filename = secure_filename(video.filename)
    if not original_filename or not allowed_evidence_video(original_filename):
        flash("Allowed video formats: MP4, WEBM, MOV.", "error")
        return redirect(url_for("upload_evidence"))

    try:
        latitude = float(latitude_text) if latitude_text else None
        longitude = float(longitude_text) if longitude_text else None
        if latitude is not None and not -90 <= latitude <= 90:
            raise ValueError
        if longitude is not None and not -180 <= longitude <= 180:
            raise ValueError
    except (ValueError, TypeError):
        flash("Please enter valid latitude and longitude.", "error")
        return redirect(url_for("upload_evidence"))

    incident_datetime = None
    if incident_datetime_text:
        try:
            incident_datetime = datetime.fromisoformat(incident_datetime_text)
        except ValueError:
            flash("Please enter a valid incident date and time.", "error")
            return redirect(url_for("upload_evidence"))

    extension = original_filename.rsplit(".", 1)[1].lower()
    saved_filename = f"{uuid.uuid4().hex}.{extension}"
    saved_path = os.path.join(EVIDENCE_FOLDER, saved_filename)
    connection = None
    cursor = None
    file_saved = False
    try:
        video.save(saved_path)
        file_saved = True
        video_size = os.path.getsize(saved_path)
        if video_size <= 0 or video_size > MAX_EVIDENCE_SIZE:
            flash("Video must be larger than 0 bytes and no more than 100 MB.", "error")
            return redirect(url_for("upload_evidence"))

        with open(saved_path, "rb") as video_file:
            header = video_file.read(32)
        signature_ok = (
            (extension in {"mp4", "mov"} and len(header) >= 8 and header[4:8] == b"ftyp")
            or (extension == "webm" and header.startswith(b"\x1a\x45\xdf\xa3"))
        )
        if not signature_ok:
            flash("The file does not appear to be a supported video.", "error")
            return redirect(url_for("upload_evidence"))

        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """INSERT INTO evidence_reports
            (incident_type, description, incident_datetime, latitude, longitude,
             contact_name, contact_phone, video_filename, original_filename,
             video_mimetype, video_size, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'Submitted')""",
            (incident_type, description, incident_datetime, latitude, longitude,
             contact_name or None, contact_phone or None, saved_filename,
             original_filename, video.mimetype or "application/octet-stream", video_size)
        )
        connection.commit()
        evidence_id = cursor.lastrowid
        file_saved = False  # Keep the video after successful database insert.
        flash(f"Evidence submitted. Reference number: {evidence_id}", "success")
        return redirect(url_for("evidence_success", evidence_id=evidence_id))
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Evidence upload failed.")
        flash("Evidence could not be saved. Check the server terminal and database table.", "error")
        return redirect(url_for("upload_evidence"))
    finally:
        if file_saved and os.path.exists(saved_path):
            try:
                os.remove(saved_path)
            except OSError:
                app.logger.exception("Could not remove failed evidence upload.")
        close_database(cursor, connection)


@app.route("/evidence/success/<int:evidence_id>")
@login_required
def evidence_success(evidence_id):
    return render_template("evidence_success.html", evidence_id=evidence_id)


@app.route("/admin/evidence")
@admin_required
def admin_evidence():
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM evidence_reports ORDER BY created_at DESC")
        reports = cursor.fetchall()
        return render_template("admin_evidence.html", reports=reports)
    except Exception:
        app.logger.exception("Could not load evidence reports.")
        flash("Evidence reports could not be loaded. Check the database table.", "error")
        return redirect(url_for("dashboard"))
    finally:
        close_database(cursor, connection)


@app.route("/admin/evidence/<int:evidence_id>/video")
@admin_required
def view_evidence_video(evidence_id):
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT video_filename FROM evidence_reports WHERE id = %s", (evidence_id,))
        report = cursor.fetchone()
        if not report:
            abort(404)
        response = send_from_directory(EVIDENCE_FOLDER, report["video_filename"], as_attachment=False)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    except Exception:
        app.logger.exception("Could not open evidence video.")
        abort(404)
    finally:
        close_database(cursor, connection)


@app.route("/admin/evidence/<int:evidence_id>/status", methods=["POST"])
@admin_required
def update_evidence_status(evidence_id):
    new_status = request.form.get("status", "").strip()
    admin_notes = request.form.get("admin_notes", "").strip()
    if new_status not in {"Submitted", "Under Review", "Verified", "Rejected"}:
        flash("Invalid evidence status.", "error")
        return redirect(url_for("admin_evidence"))

    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE evidence_reports SET status = %s, admin_notes = %s WHERE id = %s",
            (new_status, admin_notes or None, evidence_id)
        )
        connection.commit()
        flash("Evidence status updated.", "success")
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Could not update evidence status.")
        flash("Could not update evidence status.", "error")
    finally:
        close_database(cursor, connection)
    return redirect(url_for("admin_evidence"))


@app.errorhandler(413)
def evidence_file_too_large(error):
    flash("The uploaded file is too large. Maximum size is 100 MB.", "error")
    return redirect(url_for("upload_evidence"))

# =========================================
# ANONYMOUS CRIME REPORTER
# =========================================

def anonymous_allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ANONYMOUS_ALLOWED_EXTENSIONS
    )


def generate_tracking_id():
    """
    Generates a random reference ID.
    Database UNIQUE constraint protects against duplicates.
    """
    return "RQN-" + secrets.token_hex(8).upper()


def parse_incident_datetime(value):
    if not value:
        return None

    try:
        return datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M"
        )
    except ValueError:
        return None


def parse_optional_coordinate(value, minimum, maximum):
    if value is None or value.strip() == "":
        return None

    try:
        number = float(value)

        if not minimum <= number <= maximum:
            raise ValueError

        return number

    except (ValueError, TypeError):
        raise ValueError("Invalid incident coordinates.")


@app.route(
    "/anonymous-crime-report",
    methods=["GET", "POST"]
)
def anonymous_crime_report():

    if request.method == "GET":
        return render_template(
            "anonymous_crime_report.html"
        )

    crime_type = request.form.get(
        "crime_type", ""
    ).strip()

    description = request.form.get(
        "description", ""
    ).strip()

    incident_datetime = parse_incident_datetime(
        request.form.get("incident_datetime", "")
    )

    privacy_consent = request.form.get(
        "privacy_consent"
    )

    video = request.files.get("video")

    if privacy_consent != "yes":
        flash(
            "Please confirm the evidence submission notice.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    allowed_crime_types = {
        "Robbery / Theft",
        "Assault / Violence",
        "Harassment",
        "Suspicious Activity",
        "Vandalism",
        "Other"
    }

    if crime_type not in allowed_crime_types:
        flash(
            "Please select a valid crime category.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    if not description or len(description) > 3000:
        flash(
            "Description is required and must be under 3000 characters.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    if video is None or not video.filename:
        flash(
            "Please select a video.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    if not anonymous_allowed_file(video.filename):
        flash(
            "Only MP4, WEBM and MOV videos are supported.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    try:
        latitude = parse_optional_coordinate(
            request.form.get("latitude", ""),
            -90,
            90
        )

        longitude = parse_optional_coordinate(
            request.form.get("longitude", ""),
            -180,
            180
        )

    except ValueError:
        flash(
            "Please enter valid latitude and longitude.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    # Read at most 50 MB + 1 byte to enforce the limit.
    video_bytes = video.stream.read(
        ANONYMOUS_MAX_VIDEO_SIZE + 1
    )

    if not video_bytes:
        flash("The selected video is empty.", "error")

        return redirect(
            url_for("anonymous_crime_report")
        )

    if len(video_bytes) > ANONYMOUS_MAX_VIDEO_SIZE:
        flash(
            "Video size must not exceed 50 MB.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    # Validate common video signatures.
    # This is only a basic check, not malware scanning.
    extension = video.filename.rsplit(
        ".", 1
    )[1].lower()

    valid_signature = False

    if extension == "mp4" or extension == "mov":
        valid_signature = (
            len(video_bytes) >= 12
            and video_bytes[4:8] == b"ftyp"
        )

    elif extension == "webm":
        valid_signature = (
            video_bytes.startswith(b"\x1a\x45\xdf\xa3")
        )

    if not valid_signature:
        flash(
            "The file does not look like a valid supported video.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    # Use a random server-side filename.
    # Never use the user's original filename as the storage path.
    tracking_id = generate_tracking_id()

    stored_filename = (
        uuid.uuid4().hex + "." + extension
    )

    save_path = os.path.join(
        ANONYMOUS_UPLOAD_FOLDER,
        stored_filename
    )

    original_filename = secure_filename(
        video.filename
    )[:255]

    connection = None
    cursor = None
    file_saved = False

    try:
        # Save the file before inserting the DB record.
        with open(save_path, "xb") as output_file:
            output_file.write(video_bytes)

        file_saved = True

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO anonymous_crime_reports (
                tracking_id,
                crime_type,
                description,
                incident_datetime,
                latitude,
                longitude,
                video_filename,
                original_filename,
                video_size,
                status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                tracking_id,
                crime_type,
                description,
                incident_datetime,
                latitude,
                longitude,
                stored_filename,
                original_filename,
                len(video_bytes),
                "Submitted"
            )
        )

        connection.commit()

        return render_template(
            "anonymous_report_success.html",
            tracking_id=tracking_id
        )

    except Exception:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass

        if file_saved:
            try:
                os.remove(save_path)
            except OSError:
                pass

        app.logger.exception(
            "Anonymous crime report submission failed."
        )

        flash(
            "Report could not be saved. Please try again.",
            "error"
        )

        return redirect(
            url_for("anonymous_crime_report")
        )

    finally:
        if cursor:
            try:
                cursor.close()
            except Exception:
                pass

        if connection:
            try:
                connection.close()
            except Exception:
                pass


# =========================================
# ANONYMOUS REPORT STATUS TRACKING
# =========================================

@app.route(
    "/anonymous-crime-track",
    methods=["GET", "POST"]
)
def anonymous_crime_track():

    report = None

    if request.method == "POST":
        tracking_id = request.form.get(
            "tracking_id", ""
        ).strip().upper()

        # Do not show arbitrary database errors to users.
        if not re.fullmatch(
            r"RQN-[A-F0-9]{16}",
            tracking_id
        ):
            flash(
                "Enter a valid tracking ID.",
                "error"
            )

            return redirect(
                url_for("anonymous_crime_track")
            )

        connection = None
        cursor = None

        try:
            connection = get_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT tracking_id, crime_type, status, created_at
                FROM anonymous_crime_reports
                WHERE tracking_id = %s
                """,
                (tracking_id,)
            )

            report = cursor.fetchone()

        except Exception:
            app.logger.exception(
                "Anonymous report tracking failed."
            )

            flash(
                "Unable to check report status right now.",
                "error"
            )

        finally:
            if cursor:
                cursor.close()

            if connection:
                connection.close()

    return render_template(
        "anonymous_report_success.html",
        tracking_id=None,
        report=report,
        tracking_page=True
    )


# =========================================
# ADMIN: ANONYMOUS REPORTS
# =========================================

@app.route("/admin/anonymous-crime-reports")
@admin_required
def admin_anonymous_crime_reports():

    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                id,
                tracking_id,
                crime_type,
                description,
                incident_datetime,
                latitude,
                longitude,
                original_filename,
                video_size,
                status,
                admin_notes,
                created_at
            FROM anonymous_crime_reports
            ORDER BY created_at DESC
            """
        )

        reports = cursor.fetchall()

        return render_template(
            "anonymous_reports_admin.html",
            reports=reports
        )

    except Exception:
        app.logger.exception(
            "Could not load anonymous crime reports."
        )

        flash(
            "Unable to load reports.",
            "error"
        )

        return redirect(url_for("dashboard"))

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================
# ADMIN: PRIVATE VIDEO ACCESS
# =========================================

@app.route(
    "/admin/anonymous-crime-video/<int:report_id>"
)
@admin_required
def admin_anonymous_crime_video(report_id):

    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT video_filename
            FROM anonymous_crime_reports
            WHERE id = %s
            """,
            (report_id,)
        )

        row = cursor.fetchone()

        if not row:
            abort(404)

        filename = row[0]

        response = send_from_directory(
            ANONYMOUS_UPLOAD_FOLDER,
            filename,
            as_attachment=True,
            download_name="crime_evidence_" + filename
        )

        response.headers["Cache-Control"] = (
            "no-store, private"
        )

        response.headers["X-Content-Type-Options"] = (
            "nosniff"
        )

        return response

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================
# ADMIN: UPDATE REPORT STATUS
# =========================================

@app.route(
    "/admin/anonymous-crime-status/<int:report_id>",
    methods=["POST"]
)
@admin_required
def admin_update_anonymous_crime_status(report_id):

    allowed_statuses = {
        "Submitted",
        "Under Review",
        "Verified",
        "Rejected"
    }

    status = request.form.get(
        "status", ""
    ).strip()

    notes = request.form.get(
        "admin_notes", ""
    ).strip()[:3000]

    if status not in allowed_statuses:
        flash(
            "Invalid report status.",
            "error"
        )

        return redirect(
            url_for("admin_anonymous_crime_reports")
        )

    connection = None
    cursor = None

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE anonymous_crime_reports
            SET status = %s, admin_notes = %s
            WHERE id = %s
            """,
            (status, notes, report_id)
        )

        connection.commit()

        flash(
            "Anonymous report status updated.",
            "success"
        )

    except Exception:
        if connection:
            connection.rollback()

        app.logger.exception(
            "Anonymous report status update failed."
        )

        flash(
            "Unable to update report status.",
            "error"
        )

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()

    return redirect(
        url_for("admin_anonymous_crime_reports")
    )

@app.route("/photo-analyzer", methods=["GET", "POST"])
@login_required
def photo_analyzer():

    result = None
    photo_url = None

    if request.method == "POST":

        uploaded_file = request.files.get("emergency_photo")

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select an image.", "warning")
            return redirect(url_for("photo_analyzer"))

        original_name = secure_filename(uploaded_file.filename)

        if "." not in original_name:
            flash("Invalid image filename.", "danger")
            return redirect(url_for("photo_analyzer"))

        extension = original_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_IMAGE_EXTENSIONS:
            flash("Only JPG, JPEG, PNG and WEBP images are allowed.", "danger")
            return redirect(url_for("photo_analyzer"))

        unique_name = f"{uuid.uuid4().hex}.{extension}"

        image_path = os.path.join(
            PHOTO_UPLOAD_FOLDER,
            unique_name
        )

        uploaded_file.save(image_path)

        result = analyze_emergency_image(image_path)

        if not result["success"]:
            os.remove(image_path)
            flash("Invalid or unsupported image.", "danger")
            return redirect(url_for("photo_analyzer"))

        photo_url = url_for(
            "static",
            filename=f"uploads/emergency_photos/{unique_name}"
        )

    return render_template(
        "photo_analyzer.html",
        result=result,
        photo_url=photo_url
    )
@app.route("/offline-emergency")
def offline_emergency():
    return render_template("offline_emergency.html")

if __name__ == "__main__":
    app.run(debug=True)
