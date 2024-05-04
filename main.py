import pymysql

timeout = 10
connection = pymysql.connect(
    charset="utf8mb4",
    connect_timeout=timeout,
    cursorclass=pymysql.cursors.DictCursor,
    db="defaultdb",
    host="my-flask-db-first-flask-db.b.aivencloud.com",
    password="AVNS_h_ZG7r7cVTanjOFgI3P",
    read_timeout=timeout,
    port=25122,
    user="avnadmin",
    write_timeout=timeout,
)

try:
    cursor = connection.cursor()
    cursor.execute("CREATE TABLE mytest (id INTEGER PRIMARY KEY)")
    cursor.execute("INSERT INTO mytest (id) VALUES (1), (2)")
    cursor.execute("SELECT * FROM mytest")
    print(cursor.fetchall())
finally:
    connection.close()


# import mysql.connector
#
# conn = mysql.connector.connect(
# 	host="lgndcraft.mysql.pythonanywhere-services.com",
# 	user="lgndcraft",
# 	password = "Zainab12",
# 	database="lgndcraft$General_Database"
# 	)
#
# my_cursor = conn.cursor()
#
# #my_cursor.execute("CREATE DATABASE our_users")
#
# my_cursor.execute("SHOW DATABASES")
# for db in my_cursor:
# 	print(db)