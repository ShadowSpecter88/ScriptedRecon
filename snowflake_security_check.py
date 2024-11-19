import os
import snowflake.connector
from snowflake.connector import ProgrammingError
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

conn_params = {
    'account': os.getenv('SNOWFLAKE_ACCOUNT'),
    'user': os.getenv('SNOWFLAKE_USER'),
    'password': os.getenv('SNOWFLAKE_PASSWORD'),
    'role': os.getenv('SNOWFLAKE_ROLE', 'ACCOUNTADMIN'),
    'warehouse': os.getenv('SNOWFLAKE_WAREHOUSE'),
    'database': os.getenv('SNOWFLAKE_DATABASE'),
}

def execute_query(cursor, query):
    cursor.execute(query)
    return cursor.fetchall()

def check_permissive_account():
    conn = None
    try:
        conn = snowflake.connector.connect(**conn_params)
        cur = conn.cursor()

        public_roles = execute_query(
            cur,
            """
            SELECT role_name, privilege, granted_by
            FROM snowflake.account_usage.grants_to_roles
            WHERE role_name = 'PUBLIC' AND privilege IN ('CREATE', 'USAGE', 'MODIFY', 'OWNERSHIP');
            """
        )
        if public_roles:
            logging.warning("Excessive permissions found for PUBLIC role:")
            for role, privilege, granted_by in public_roles:
                logging.warning(f"Role: {role}, Privilege: {privilege}, Granted by: {granted_by}")

        user_roles = execute_query(
            cur,
            """
            SELECT user_name, role_name
            FROM snowflake.account_usage.grants_to_users
            WHERE role_name IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN');
            """
        )
        if user_roles:
            logging.info("Users with high-privilege roles:")
            for user, role in user_roles:
                logging.info(f"User: {user}, Role: {role}")

        db_schema_permissions = execute_query(
            cur,
            """
            SELECT database_name, schema_name, privilege, grantee_name
            FROM snowflake.account_usage.grants_to_users
            WHERE privilege IN ('CREATE', 'ALTER', 'DROP', 'OWNERSHIP');
            """
        )
        if db_schema_permissions:
            logging.warning("Potentially excessive database or schema permissions:")
            for db, schema, privilege, grantee in db_schema_permissions:
                logging.warning(f"Database: {db}, Schema: {schema}, Privilege: {privilege}, Granted to: {grantee}")
    except ProgrammingError as e:
        logging.error(f"Query error: {e.msg}")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    check_permissive_account()
