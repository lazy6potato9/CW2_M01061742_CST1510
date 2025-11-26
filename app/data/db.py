import sqlite3
import pandas as pd

#---------------------------get data------------------------------
def get_all_cyber_incidents(conn):
    sql = 'SELECT * from cyber_incidents'
    data = pd.read_sql(sql, conn)
    return data 

conn = sqlite3.connect('app/data/cyber_incidents.db')