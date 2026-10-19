from database import get_db_connection

try:
    connection = get_db_connection()

    if connection.is_connected():
        print("MySQL connection successful!")
        print("SecureVault database connected.")

    connection.close()

except Exception as e:
    print("MySQL connection failed.")
    print("Error:", e)