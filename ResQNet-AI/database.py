import mysql.connector


def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Shadabkhan@54",
        database="resqnet"
    )