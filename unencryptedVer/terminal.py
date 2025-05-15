#written by samson

import time
import board
import busio
from digitalio import DigitalInOut
import os
from adafruit_pn532.i2c import PN532_I2C
import pymysql.cursors


from sync import syncToOffline
import sqlite3

# I2C connection:
i2c = busio.I2C(board.SCL, board.SDA)

# Non-hardware
# pn532 = PN532_I2C(i2c, debug=False)

# With I2C, we recommend connecting RSTPD_N (reset) to a digital pin for manual
# harware reset
reset_pin = DigitalInOut(board.D6)
# On Raspberry Pi, you must also connect a pin to P32 "H_Request" for hardware
# wakeup! this means we don't need to do the I2C clock-stretch thing
req_pin = DigitalInOut(board.D12)
pn532 = PN532_I2C(i2c, debug=False, reset=reset_pin, req=req_pin)

ic, ver, rev, support = pn532.firmware_version
print("Found PN532 with firmware version: {0}.{1}".format(ver, rev))

# Configure PN532 to communicate with MiFare cards
pn532.SAM_configuration()

def onlineScanCard(db_conn):
    conn_mariadb = db_conn
    output = ""
    print("now reading . . .")
    print("Waiting for RFID/NFC card...")
    while True:
    # Check if a card is available to read
        uid = pn532.read_passive_target(timeout=0.5)
    
        print(".", end="")
        # Try again if no card is available.
        if uid is None:
            continue
        output = ""
        print("Found card with UID:", [hex(i)[2:] for i in uid])

        for i in uid:
            temp = hex(i)[2:]
            if(len(temp) < 2):
                temp = "0" + temp

            output += temp

        print(output)

        #print("total space on card: " + str(count*4))
        print('****')
        time.sleep(2)
        break;
    print("1")
    query_result = ''
    with conn_mariadb.cursor() as cursor_mariadb:
        # Read a single record
            print("1")
            sql = "SELECT * FROM activeusers WHERE NFCUID = %s"
            cursor_mariadb.execute(sql,output)
            result = cursor_mariadb.fetchone()
            print(result)
            query_result = result


            #if user exists in DB and scans, then log the entry with timestamp in db
           
            if(query_result is not None):
                sql = "insert into logins(uid) values(%s)"
                cursor_mariadb.execute(sql,query_result.get("uid"))
                print(query_result.get("uid"))
    


def offlineScanCard(db_conn):
    conn_sqlite = db_conn
    output = ""
    print("now reading . . .")
    print("Waiting for RFID/NFC card...")
    while True:
    # Check if a card is available to read
        uid = pn532.read_passive_target(timeout=0.5)
    
        print(".", end="")
        # Try again if no card is available.
        if uid is None:
            continue
        output = ""
        print("Found card with UID:", [hex(i)[2:] for i in uid])

        for i in uid:
            temp = hex(i)[2:]
            if(len(temp) < 2):
                temp = "0" + temp

            output += temp

        print(output)

        #print("total space on card: " + str(count*4))
        print('****')
        time.sleep(2)
        break;
    cursor_sqlite = conn_sqlite.cursor()
    # Read a single record
    sql = "SELECT * FROM activeusers WHERE NFCUID = ?"
    cursor_sqlite.execute(sql,(output,))
    result = cursor_sqlite.fetchone()
    #print(result)
    query_result = result


            #if user exists in DB and scans, then log the entry with timestamp in db
    if(query_result is not None):
        sql = "insert into cachedlogs(uid) values(?)"
        cursor_sqlite.execute(sql,(query_result[0],))
        print(query_result[0])
        cursor_sqlite.execute("select * from cachedlogs");
        result = cursor_sqlite.fetchall()
        conn_sqlite.commit()
        for x in result:
            print(x)
    else:
        print("user not found, denied")



def insertCardData():
    output = ""
    print("Waiting for RFID/NFC card...")
    while True:
        # Check if a card is available to read
        uid = pn532.read_passive_target(timeout=0.5)

        print(".", end="")
        # Try again if no card is available.
        if uid is None:
            continue
        output = ""
        print("Found card with UID:", [hex(i)[2:] for i in uid])

        for i in uid:
            temp = hex(i)[2:]
            if(len(temp) < 2):
                temp = "0" + temp

            output += temp

        print(output)

        #print("total space on card: " + str(count*4))
        print('****')
        time.sleep(2)
        break;
    with conn_mariadb.cursor() as cursor:
    # Read a single record
        sql = "SELECT * FROM activeusers WHERE NFCUID =%s"
        cursor.execute(sql, output)
        result = cursor.fetchone()
        print(result)
        query_result = result

        # if user exists in DB and scans, then log the entry with timestamp in db
        if (query_result is None):
            sql = "insert into activeUsers(NFCUID,name) values(%s,%s)"
            cursor.execute(sql,(output, input("enter name of new user")))
            #print(query_result.get("uid"))#
        else:
            print("user already exists")



def main():
    print("connecting . . .")
    online = True

    try:
        #conn_mariadb = pymysql.connect(host='100.102.124.80',user='temp',password='Password',database='temp',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor,autocommit=True)
        conn_mariadb = pymysql.connect(host='100.102.124.81',user='temp',password='Password',database='temp',charset='utf8mb4',cursorclass=pymysql.cursors.DictCursor,autocommit=True)
        conn_mariadb.commit()
        print("work")    
    except:
        #print(a)
        online = False
        print("unable to connect to main, using offline db")
        conn_sqlite = sqlite3.connect("offline.db")
        print("done")


    userIn = ''
    userIn = input("enter char (read(r)/insert(i)): ")
    while True:
        if userIn == 'i':
            #print("inserting data has not been added yet. Quitting...")
            #exit()
            insertCardData()
            break;
        if userIn == 'r':
            if online:
                syncToOffline()
                onlineScanCard(conn_mariadb)
            else:
                offlineScanCard(conn_sqlite)
            #break



if __name__ == '__main__':
    main()
