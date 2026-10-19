from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    send_file
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from database import (
    get_db_connection,
    add_audit_log,
    record_login_attempt
)

from encryption import (
    generate_key,
    encrypt_file,
    decrypt_file
)

from integrity import calculate_sha256

from key_manager import encrypt_key, decrypt_key

import os
import base64


# =========================================================
# FLASK APP CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = "securevault-development-key"


# =========================================================
# FOLDERS
# =========================================================

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted_files"
DECRYPTED_FOLDER = "decrypted_files"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template("index.html")


# =========================================================
# REGISTER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        # Basic validation
        if not name or not email or not password:

            return render_template(
                "register.html",
                error="All fields are required."
            )

        if len(password) < 6:

            return render_template(
                "register.html",
                error="Password must contain at least 6 characters."
            )

        password_hash = generate_password_hash(password)

        connection = None
        cursor = None

        try:

            connection = get_db_connection()
            cursor = connection.cursor()

            query = """
                INSERT INTO users
                (name, email, password_hash)
                VALUES (%s, %s, %s)
            """

            cursor.execute(
                query,
                (name, email, password_hash)
            )

            connection.commit()

            return redirect(url_for("login"))

        except Exception as e:

            return render_template(
                "register.html",
                error=f"Registration failed: {e}"
            )

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

    return render_template("register.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip()
        password = request.form["password"]

        connection = None
        cursor = None

        try:

            connection = get_db_connection()

            cursor = connection.cursor(dictionary=True)

            query = """
                SELECT *
                FROM users
                WHERE email = %s
            """

            cursor.execute(query, (email,))

            user = cursor.fetchone()

        except Exception as e:

            return render_template(
                "login.html",
                error=f"Login error: {e}"
            )

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()


        # =================================================
        # SUCCESSFUL LOGIN
        # =================================================

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            # Check account status
            if user["status"] != "Active":

                record_login_attempt(
                    email,
                    request.remote_addr,
                    "BLOCKED"
                )

                return render_template(
                    "login.html",
                    error=f"Your account is {user['status']}."
                )


            # Create session
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["role"] = user["role"]


            # Record successful login
            record_login_attempt(
                email,
                request.remote_addr,
                "SUCCESS"
            )


            # Audit log
            add_audit_log(
                user["id"],
                "LOGIN",
                "User logged in successfully",
                request.remote_addr
            )


            return redirect(url_for("dashboard"))


        # =================================================
        # FAILED LOGIN
        # =================================================

        record_login_attempt(
            email,
            request.remote_addr,
            "FAILED"
        )


        # Count failed attempts during last 10 minutes
        connection = None
        cursor = None

        try:

            connection = get_db_connection()
            cursor = connection.cursor()

            query = """
                SELECT COUNT(*)
                FROM login_attempts
                WHERE email = %s
                AND status = 'FAILED'
                AND attempt_time >= NOW() - INTERVAL 10 MINUTE
            """

            cursor.execute(query, (email,))

            result = cursor.fetchone()

            failed_count = result[0] if result else 0

        except Exception:

            failed_count = 0

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()


        # =================================================
        # SECURITY ALERT AFTER 3 FAILED ATTEMPTS
        # =================================================

        if failed_count >= 3:

            add_audit_log(
                None,
                "SECURITY_ALERT",
                "Multiple failed login attempts detected.",
                request.remote_addr
            )


        return render_template(
            "login.html",
            error="Invalid email or password."
        )


    return render_template("login.html")


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(url_for("login"))


    return render_template(
        "dashboard.html",
        name=session["user_name"],
        role=session["role"]
    )


# =========================================================
# ENCRYPT FILE
# =========================================================

@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        # Check uploaded file
        if "file" not in request.files:
            return render_template(
                "encrypt.html",
                error="Please select a file."
            )

        file = request.files["file"]

        # Check filename
        if file.filename == "":
            return render_template(
                "encrypt.html",
                error="Please select a file."
            )

        original_filename = file.filename

        # Temporary upload path
        upload_path = os.path.join(
            UPLOAD_FOLDER,
            original_filename
        )

        try:
            # Save original file temporarily
            file.save(upload_path)

            # Generate AES-256 key
            key = generate_key()

            # Encrypted filename
            encrypted_filename = original_filename + ".enc"

            encrypted_path = os.path.join(
                ENCRYPTED_FOLDER,
                encrypted_filename
            )

            # Encrypt file
            encrypt_file(
                upload_path,
                encrypted_path,
                key
            )

            # Calculate SHA-256 hash
            file_hash = calculate_sha256(
                upload_path
            )

            # Get file size
            file_size = os.path.getsize(
                upload_path
            )

            # Store file metadata in database
            connection = get_db_connection()
            cursor = connection.cursor()

            query = """
                INSERT INTO files
                (
                    user_id,
                    original_filename,
                    encrypted_filename,
                    file_size,
                    encryption_algorithm,
                    file_hash
                )
                VALUES (%s, %s, %s, %s, %s, %s)
            """

            cursor.execute(
                query,
                (
                    session["user_id"],
                    original_filename,
                    encrypted_filename,
                    file_size,
                    "AES-256-GCM",
                    file_hash
                )
            )

            connection.commit()

            cursor.close()
            connection.close()

            # Remove temporary original file
            if os.path.exists(upload_path):
                os.remove(upload_path)

            # Add audit log
            add_audit_log(
                session["user_id"],
                "FILE_ENCRYPTED",
                f"File encrypted: {original_filename}",
                request.remote_addr
            )

            # Convert AES key to Base64
            encoded_key = base64.b64encode(key).decode()

            # Show encryption result
            return render_template(
                "encrypt.html",
                success="File encrypted successfully.",
                encrypted_filename=encrypted_filename,
                encryption_key=encoded_key
            )

        except Exception as e:

            # Remove temporary file if an error occurs
            if os.path.exists(upload_path):
                os.remove(upload_path)

            return render_template(
                "encrypt.html",
                error=f"Encryption failed: {str(e)}"
            )

    # GET request
    return render_template("encrypt.html")

# =========================================================
# DECRYPT FILE
# =========================================================

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():

    if "user_id" not in session:
        return redirect(url_for("login"))

    # -----------------------------------------------------
    # Get user's encrypted files
    # -----------------------------------------------------

    connection = get_db_connection()

    # buffered=True fixes:
    # mysql.connector.errors.InternalError: Unread result found
    cursor = connection.cursor(
        dictionary=True,
        buffered=True
    )

    query = """
        SELECT *
        FROM files
        WHERE user_id = %s
        ORDER BY uploaded_at DESC
    """

    cursor.execute(
        query,
        (session["user_id"],)
    )

    files = cursor.fetchall()

    cursor.close()
    connection.close()

    # -----------------------------------------------------
    # Handle decryption
    # -----------------------------------------------------

    if request.method == "POST":

        encrypted_filename = request.form["encrypted_file"]
        encryption_key = request.form["encryption_key"]

        try:

            # ---------------------------------------------
            # Verify that the file belongs to current user
            # ---------------------------------------------

            connection = get_db_connection()

            cursor = connection.cursor(
                dictionary=True,
                buffered=True
            )

            query = """
                SELECT *
                FROM files
                WHERE encrypted_filename = %s
                AND user_id = %s
            """

            cursor.execute(
                query,
                (
                    encrypted_filename,
                    session["user_id"]
                )
            )

            file_record = cursor.fetchone()

            cursor.close()
            connection.close()

            if not file_record:

                return render_template(
                    "decrypt.html",
                    files=files,
                    error="Invalid file or file does not belong to your account."
                )

            # ---------------------------------------------
            # Decode Base64 encryption key
            # ---------------------------------------------

            key = base64.b64decode(
                encryption_key
            )

            # ---------------------------------------------
            # Encrypted file path
            # ---------------------------------------------

            encrypted_path = os.path.join(
                ENCRYPTED_FOLDER,
                encrypted_filename
            )

            if not os.path.exists(encrypted_path):

                return render_template(
                    "decrypt.html",
                    files=files,
                    error="Encrypted file not found."
                )

            # ---------------------------------------------
            # Get original filename from database
            # ---------------------------------------------

            original_filename = file_record[
                "original_filename"
            ]

            # ---------------------------------------------
            # Create decrypted filename
            # ---------------------------------------------

            decrypted_filename = (
                "decrypted_" + original_filename
            )

            decrypted_path = os.path.join(
                DECRYPTED_FOLDER,
                decrypted_filename
            )

            # ---------------------------------------------
            # Decrypt file using AES-256-GCM
            # ---------------------------------------------

            decrypt_file(
                encrypted_path,
                decrypted_path,
                key
            )

            # ---------------------------------------------
            # Success
            # ---------------------------------------------

            return render_template(
                "decrypt.html",
                files=files,
                success="File decrypted successfully!",
                decrypted_filename=decrypted_filename
            )

        except Exception as error:

            print("Decryption error:", error)

            return render_template(
                "decrypt.html",
                files=files,
                error=(
                    "Decryption failed. "
                    "Please check the encrypted file "
                    "and encryption key."
                )
            )

    return render_template(
        "decrypt.html",
        files=files
    )
# =========================================================
# DOWNLOAD DECRYPTED FILE
# =========================================================

@app.route("/download-decrypted/<filename>")
def download_decrypted(filename):

    if "user_id" not in session:

        return redirect(url_for("login"))


    # Security: only allow the generated decrypted_ files
    if not filename.startswith("decrypted_"):

        return "Unauthorized file."


    file_path = os.path.join(
        DECRYPTED_FOLDER,
        filename
    )


    if not os.path.exists(file_path):

        return "File not found."


    return send_file(
        file_path,
        as_attachment=True
    )


# =========================================================
# FILE INTEGRITY
# =========================================================

@app.route("/integrity", methods=["GET", "POST"])
def integrity():

    if "user_id" not in session:

        return redirect(url_for("login"))


    # Get user's files
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT *
        FROM files
        WHERE user_id = %s
        ORDER BY uploaded_at DESC
    """

    cursor.execute(
        query,
        (session["user_id"],)
    )

    files = cursor.fetchall()

    cursor.close()
    connection.close()


    if request.method == "POST":

        file_id = request.form["file_id"]


        # Find user's selected file
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT *
            FROM files
            WHERE id = %s
            AND user_id = %s
        """

        cursor.execute(
            query,
            (
                file_id,
                session["user_id"]
            )
        )

        file_record = cursor.fetchone()

        cursor.close()
        connection.close()


        if not file_record:

            return render_template(
                "integrity.html",
                files=files,
                error="File not found."
            )


        original_filename = file_record[
            "original_filename"
        ]


        decrypted_filename = (
            "decrypted_" + original_filename
        )


        decrypted_path = os.path.join(
            DECRYPTED_FOLDER,
            decrypted_filename
        )


        if not os.path.exists(decrypted_path):

            return render_template(
                "integrity.html",
                files=files,
                error=(
                    "Decrypted file not found. "
                    "Decrypt the file first."
                )
            )


        # Calculate current SHA-256
        current_hash = calculate_sha256(
            decrypted_path
        )


        stored_hash = file_record["file_hash"]


        # Compare hashes
        if current_hash == stored_hash:

            result = (
                "Integrity verified successfully. "
                "The file has not been modified."
            )

            result_type = "success"

            add_audit_log(
                session["user_id"],
                "INTEGRITY_CHECK",
                f"Integrity verified: {original_filename}",
                request.remote_addr
            )

        else:

            result = (
                "WARNING: File integrity check failed. "
                "The file may have been modified."
            )

            result_type = "danger"

            add_audit_log(
                session["user_id"],
                "INTEGRITY_VIOLATION",
                f"Integrity violation detected: {original_filename}",
                request.remote_addr
            )


        return render_template(
            "integrity.html",
            files=files,
            result=result,
            result_type=result_type
        )


    return render_template(
        "integrity.html",
        files=files
    )


@app.route("/activity")
def activity():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access denied. Admin privileges required.", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            audit_logs.id,
            audit_logs.action,
            audit_logs.description,
            audit_logs.ip_address,
            audit_logs.created_at,
            users.name AS user_name
        FROM audit_logs
        LEFT JOIN users
            ON audit_logs.user_id = users.id
        ORDER BY audit_logs.created_at DESC
    """)

    activities = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "activity.html",
        activities=activities
    )
# =========================================================
# SECURITY ALERTS
# =========================================================

@app.route("/security-alerts")
def security_alerts():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access denied. Admin privileges required.", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            audit_logs.id,
            audit_logs.action,
            audit_logs.description,
            audit_logs.ip_address,
            audit_logs.created_at,
            users.name AS user_name
        FROM audit_logs
        LEFT JOIN users
            ON audit_logs.user_id = users.id
        WHERE audit_logs.action = 'SECURITY_ALERT'
        ORDER BY audit_logs.created_at DESC
    """)

    alerts = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "security_alerts.html",
        alerts=alerts
    )

# =========================================================
# ADMIN SECURITY DASHBOARD
# =========================================================

@app.route("/admin")
def admin_dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access denied. Admin privileges required.", 403

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) AS total FROM users")
    total_users = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM files")
    total_files = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM login_attempts
        WHERE status = 'FAILED'
    """)
    failed_logins = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM audit_logs
        WHERE action = 'SECURITY_ALERT'
    """)
    total_alerts = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT
            action,
            description,
            ip_address,
            created_at
        FROM audit_logs
        WHERE action IN (
            'SECURITY_ALERT',
            'FAILED_LOGIN',
            'INTEGRITY_VIOLATION'
        )
        ORDER BY created_at DESC
        LIMIT 10
    """)

    recent_activity = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        total_files=total_files,
        failed_logins=failed_logins,
        total_alerts=total_alerts,
        recent_activity=recent_activity
    )
# =========================================================
# REPORT CYBER INCIDENT
# =========================================================

@app.route("/report-incident", methods=["GET", "POST"])
def report_incident():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        offence_type = request.form["offence_type"].strip()
        description = request.form["description"].strip()
        severity = request.form["severity"]

        # Basic validation
        if not offence_type or not description:

            return render_template(
                "report_incident.html",
                error="Please fill all required fields."
            )

        connection = None
        cursor = None

        try:

            connection = get_db_connection()
            cursor = connection.cursor()

            query = """
                INSERT INTO incidents
                (
                    user_id,
                    offence_type,
                    description,
                    severity,
                    status,
                    ip_address
                )
                VALUES (%s, %s, %s, %s, %s, %s)
            """

            cursor.execute(
                query,
                (
                    session["user_id"],
                    offence_type,
                    description,
                    severity,
                    "Open",
                    request.remote_addr
                )
            )

            connection.commit()

            # Audit log
            add_audit_log(
                session["user_id"],
                "INCIDENT_REPORTED",
                f"Cyber incident reported: {offence_type}",
                request.remote_addr
            )

            return render_template(
                "report_incident.html",
                success="Cyber incident reported successfully."
            )

        except Exception as e:

            return render_template(
                "report_incident.html",
                error=f"Failed to report incident: {e}"
            )

        finally:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

    return render_template("report_incident.html")

# =========================================================
# ADMIN INCIDENT MANAGEMENT
# =========================================================

@app.route("/admin/incidents")
def admin_incidents():

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Only Admin can access
    if session.get("role") != "Admin":
        return "Access denied. Admin privileges required.", 403

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT
                incidents.id,
                incidents.offence_type,
                incidents.description,
                incidents.severity,
                incidents.status,
                incidents.ip_address,
                incidents.reported_at,
                users.name,
                users.email
            FROM incidents
            LEFT JOIN users
                ON incidents.user_id = users.id
            ORDER BY incidents.reported_at DESC
        """

        cursor.execute(query)

        incidents = cursor.fetchall()

        return render_template(
            "admin_incidents.html",
            incidents=incidents
        )

    except Exception as e:

        return f"Incident management error: {e}", 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()

# =========================================================
# UPDATE INCIDENT STATUS
# =========================================================

@app.route("/admin/incidents/update/<int:incident_id>", methods=["POST"])
def update_incident(incident_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "Admin":
        return "Access denied. Admin privileges required.", 403

    status = request.form.get("status")

    if status not in ["Open", "Investigating", "Resolved"]:
        return "Invalid status", 400

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE incidents
        SET status = %s
        WHERE id = %s
    """, (status, incident_id))

    connection.commit()

    cursor.close()
    connection.close()

    add_audit_log(
        session["user_id"],
        "INCIDENT_STATUS_UPDATED",
        f"Incident #{incident_id} status changed to {status}",
        request.remote_addr
    )

    return redirect(url_for("admin_incidents"))

# =========================================================
# MOBILE AND WIRELESS SECURITY
# =========================================================

@app.route("/mobile-security")
def mobile_security():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("mobile_security.html")

@app.route("/cyber-law")
def cyber_law():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("cyber_law.html")
# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    if "user_id" in session:

        add_audit_log(
            session["user_id"],
            "LOGOUT",
            "User logged out",
            request.remote_addr
        )


    session.clear()

    return redirect(url_for("home"))


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )