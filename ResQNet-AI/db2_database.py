import os
import ibm_db
from dotenv import load_dotenv

load_dotenv()


# ==========================================
# IBM DB2 CONNECTION
# ==========================================

def get_db2_connection():

    connection_string = (
        f"DATABASE={os.getenv('DB2_DATABASE', 'RESQNET')};"
        f"HOSTNAME={os.getenv('DB2_HOST', '127.0.0.1')};"
        f"PORT={os.getenv('DB2_PORT', '50000')};"
        f"PROTOCOL=TCPIP;"
        f"UID={os.getenv('DB2_USER', 'db2inst1')};"
        f"PWD={os.getenv('DB2_PASSWORD', '')};"
    )

    password = os.getenv("DB2_PASSWORD")

    if not password:
        raise RuntimeError("DB2_PASSWORD is missing.")

    return ibm_db.connect(connection_string, "", "")


# ==========================================
# CREATE DB2 INCIDENT TABLE
# ==========================================

def create_db2_table():

    connection = get_db2_connection()

    try:

        check_sql = """
            SELECT 1
            FROM SYSCAT.TABLES
            WHERE TABSCHEMA = CURRENT SCHEMA
            AND TABNAME = 'RESQNET_INCIDENTS'
        """

        statement = ibm_db.exec_immediate(
            connection,
            check_sql
        )

        if not ibm_db.fetch_assoc(statement):

            create_sql = """
                CREATE TABLE RESQNET_INCIDENTS (

                    ID BIGINT GENERATED ALWAYS AS IDENTITY
                    PRIMARY KEY,

                    SOURCE_MYSQL_ID BIGINT NOT NULL UNIQUE,

                    EMERGENCY_TYPE VARCHAR(100),

                    DESCRIPTION VARCHAR(3000),

                    LATITUDE DECIMAL(10,7),

                    LONGITUDE DECIMAL(10,7),

                    SEVERITY VARCHAR(30),

                    PRIORITY VARCHAR(10),

                    AI_REASON VARCHAR(2000),

                    CREATED_AT TIMESTAMP DEFAULT CURRENT TIMESTAMP
                )
            """

            ibm_db.exec_immediate(
                connection,
                create_sql
            )

        return True

    finally:

        ibm_db.close(connection)


# ==========================================
# SAVE INCIDENT TO IBM DB2
# ==========================================

def save_incident_to_db2(incident):

    connection = get_db2_connection()

    try:

        # Check duplicate incident

        check_sql = """
            SELECT 1
            FROM RESQNET_INCIDENTS
            WHERE SOURCE_MYSQL_ID = ?
        """

        check_statement = ibm_db.prepare(
            connection,
            check_sql
        )

        ibm_db.execute(
            check_statement,
            (incident["id"],)
        )

        if ibm_db.fetch_assoc(check_statement):

            return True

        # Insert new incident

        insert_sql = """
            INSERT INTO RESQNET_INCIDENTS
            (
                SOURCE_MYSQL_ID,
                EMERGENCY_TYPE,
                DESCRIPTION,
                LATITUDE,
                LONGITUDE,
                SEVERITY,
                PRIORITY,
                AI_REASON
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """

        statement = ibm_db.prepare(
            connection,
            insert_sql
        )

        values = (
            incident["id"],
            incident["emergency_type"],
            incident["description"],
            incident.get("latitude"),
            incident.get("longitude"),
            incident.get("severity"),
            incident.get("priority"),
            incident.get("ai_reason")
        )

        ibm_db.execute(statement, values)

        return True

    finally:

        ibm_db.close(connection)


# ==========================================
# CHECK TOTAL DB2 INCIDENTS
# ==========================================

def get_db2_incident_count():

    connection = get_db2_connection()

    try:

        sql = """
            SELECT COUNT(*) AS TOTAL
            FROM RESQNET_INCIDENTS
        """

        statement = ibm_db.exec_immediate(
            connection,
            sql
        )

        result = ibm_db.fetch_assoc(statement)

        return result["TOTAL"]

    finally:

        ibm_db.close(connection)