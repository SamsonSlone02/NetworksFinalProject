import sqlite3
import pymysql
def syncToOffline():
    conn_sqlite = sqlite3.connect("offline.db")
    conn_mariadb = pymysql.connect(host='100.102.124.81',
        user='temp',
        password='Password',
        database='temp',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True)
    conn_mariadb.commit()

    cursor_sqlite = conn_sqlite.cursor()
    cursor_sqlite.execute('SELECT * FROM activeusers')
    results_sqlite = cursor_sqlite.fetchall()
    
    sql = "select * from activeusers"
    cursor_mariadb = conn_mariadb.cursor()
    cursor_mariadb.execute(sql)
    results_mariadb = cursor_mariadb.fetchall()


    #print(results_sqlite)
    #print(results_mariadb)
    

    #updating localdb to include new values
    for x in results_mariadb:
        y = x["uid"]
        z = x["NFCUID"]
        isFound = False
        for a in results_sqlite:
            if a[0] == y:
                isFound = True
        if not isFound:
            sql = "insert into activeusers(uid,NFCUID) values(?,?)"
            print(y," not found in sqlitedb.. . .  adding to local.")
            cursor_sqlite.execute(sql,(y,z))
            conn_sqlite.commit()
        print(y,z)
    print("-----------")
    

    #updating localdb to remove old values
    for x in results_sqlite:
        uid = x[0]
        NFCUID = x[1]
        isFound = False
        for a in results_mariadb:
            if uid == a["uid"]:
                isFound = True
        if not isFound:
            sql = "delete from activeusers where uid = ?"
            print(uid," not found in maindb.. . .  removing.")
            cursor_sqlite.execute(sql,(uid,))
            conn_sqlite.commit()
        print(uid,NFCUID)
    
    #offloading cachedlogs to maindb
    sql = "select * from cachedlogs"
    cursor_sqlite.execute(sql)
    sqlite_result = cursor_sqlite.fetchall()
    count = 0
    for a,b,c in sqlite_result:
        count+= 1
        print(a,b,c)
        sql = "delete from cachedlogs where uid = ? and loginTime = ?"
        cursor_sqlite.execute(sql,(b,c))
        conn_sqlite.commit()
        sql = "insert into logins(uid,loginTime) values(%s,%s)"
        cursor_mariadb.execute(sql,(b,c))
        
    print(f"offloaded {count} logs...")
def main():
    syncToOffline()


if __name__ == '__main__':
    main()
