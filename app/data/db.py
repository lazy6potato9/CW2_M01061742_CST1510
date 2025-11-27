import sqlite3
import os

DB_PATH = "DATA/intelligence_platform.db"

def get_connection():
    """
    Opens a connection to the SQLite database.
    If the database file does not exist, it will be created.
    """
    # Make sure the DATA folder exists
    os.makedirs("DATA", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    return conn














'''import sqlite3
import pandas as pd

#---------------------------get data------------------------------
def get_all_cyber_incidents(conn):
    sql = 'SELECT * from cyber_incidents'
    data = pd.read_sql(sql, conn)
    return data 

conn = sqlite3.connect('app/data/cyber_incidents.db')'''