
import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    connection = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("TrustWatch@26"),
        database=os.getenv("DB_NAME", "securevault")
    )

    return connection


def add_audit_log(user_id, action, description, ip_address=None):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        query = """
            INSERT INTO audit_logs
            (user_id, action, description, ip_address)
            VALUES (%s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (user_id, action, description, ip_address)
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


def record_login_attempt(email, ip_address, status):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        query = """
            INSERT INTO login_attempts
            (email, ip_address, status)
            VALUES (%s, %s, %s)
        """

        cursor.execute(
            query,
            (email, ip_address, status)
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()
