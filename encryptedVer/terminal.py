import time
import board
import busio
from digitalio import DigitalInOut
import os
import json
import ssl
import base64
import hashlib
import websockets
import asyncio
import logging
import uuid
import sqlite3
import threading
from datetime import datetime
from adafruit_pn532.i2c import PN532_I2C
import pymysql.cursors
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from sync import syncToOffline

# logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("terminal.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('terminal')

# generate a unique terminal ID if not exists
TERMINAL_ID_FILE = "terminal_id.txt"
if os.path.exists(TERMINAL_ID_FILE):
    with open(TERMINAL_ID_FILE, 'r') as f:
        TERMINAL_ID = f.read().strip()
else:
    TERMINAL_ID = str(uuid.uuid4())[:8]
    with open(TERMINAL_ID_FILE, 'w') as f:
        f.write(TERMINAL_ID)

# server config
SERVER_URI = "wss://100.102.124.81:8000"  # use the ip and ports you use 

# encryption config
ENCRYPTION_KEY_FILE = "terminal_key.key"
SALT = b'terminal_salt_value'

# init encryption
def generate_encryption_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        password = f"{TERMINAL_ID}_secure_password".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=50000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        return key

try:
    encryption_key = generate_encryption_key()
    cipher = Fernet(encryption_key)
    ENCRYPTION_ENABLED = True
    logger.info("Data encryption enabled")
except Exception as e:
    logger.error(f"Encryption initialization failed: {e}")
    logger.warning("Data will be stored unencrypted")
    ENCRYPTION_ENABLED = False

# encryption functions
def encrypt_data(data):
    if not ENCRYPTION_ENABLED:
        return data
    if isinstance(data, (int, float)):
        data = str(data)
    if isinstance(data, str):
        return cipher.encrypt(data.encode()).decode()
    return data

def decrypt_data(data):
    if not ENCRYPTION_ENABLED or data is None:
        return data
    if isinstance(data, str):
        try:
            return cipher.decrypt(data.encode()).decode()
        except Exception:
            return data
    return data

i2c = busio.I2C(board.SCL, board.SDA)

reset_pin = DigitalInOut(board.D6)
req_pin = DigitalInOut(board.D12)
pn532 = PN532_I2C(i2c, debug=False, reset=reset_pin, req=req_pin)

ic, ver, rev, support = pn532.firmware_version
print("Found PN532 with firmware version: {0}.{1}".format(ver, rev))

pn532.SAM_configuration()

# db for storing encrypted offline data
def init_sqlite_db():
    conn = sqlite3.connect("offline_secure.db")
    cursor = conn.cursor()
    
    # create tables with TEXT fields for encrypted data
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cached_logs_secure (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid TEXT NOT NULL,
        loginTime TEXT NOT NULL,
        encrypted INTEGER DEFAULT 0,
        synced INTEGER DEFAULT 0
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activeusers_secure (
        uid TEXT PRIMARY KEY,
        NFCUID TEXT NOT NULL,
        name TEXT,
        encrypted INTEGER DEFAULT 0
    )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Secure offline database initialized")

init_sqlite_db()

# WebSocket client for secure server communication
async def connect_to_server():
    # SSL here ignores cert verification
    # in any normal prod, use proper cert validation
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    logger.info(f"Connecting to {SERVER_URI} as Terminal {TERMINAL_ID}")
    
    try:
        async with websockets.connect(SERVER_URI, ssl=ssl_context) as websocket:
            logger.info("Connected to server, authenticating...")
            
            # auth with server
            auth_data = {
                "terminal_id": TERMINAL_ID,
                "auth_key": f"auth_{TERMINAL_ID}_key",  # auth scheme
                "connection_time": datetime.utcnow().isoformat(),
                "device_type": "card_scanner"
            }
            await websocket.send(json.dumps(auth_data))
            
            response = await websocket.recv()
            auth_response = json.loads(response)
            
            if auth_response.get("status") != "authenticated":
                logger.error("Authentication failed")
                return
                
            logger.info("Authentication successful")
            
            # send online status
            await websocket.send(f"scanner_{TERMINAL_ID} online")
            
            async def heartbeat():
                while True:
                    await asyncio.sleep(5)
                    try:
                        await websocket.send("heartbeat")
                        logger.debug("Sent heartbeat")
                    except Exception as e:
                        logger.error(f"Heartbeat failed: {e}")
                        return
            
            async def receive():
                try:
                    while True:
                        message = await websocket.recv()
                        logger.info(f"Received from server: {message}")
                except:
                    logger.warning("Server disconnected")
                    return
            
            # report any pending offline data
            conn = sqlite3.connect("offline_secure.db")
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cached_logs_secure WHERE synced = 0")
            pending_count = cursor.fetchone()[0]
            conn.close()
            
            if pending_count > 0:
                await websocket.send(json.dumps({
                    "type": "pending_sync",
                    "terminal_id": TERMINAL_ID,
                    "count": pending_count
                }))
            
            await asyncio.gather(heartbeat(), receive())
            
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")

# modified functions for secure operation
def onlineScanCard(db_conn):
    conn_mariadb = db_conn
    output = ""
    print("now reading . . .")
    print("Waiting for RFID/NFC card...")
    while True:
        uid = pn532.read_passive_target(timeout=0.5)
        print(".", end="")
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
        print('****')
        time.sleep(2)
        break
    
    query_result = ''
    with conn_mariadb.cursor() as cursor_mariadb:
        sql = "SELECT * FROM activeusers WHERE NFCUID = %s"
        cursor_mariadb.execute(sql, output)
        result = cursor_mariadb.fetchone()
        print(result)
        

        query_result = result
        print(f"\nWelcome {result.get('name')}!\n")
        # if user exists in DB and scans, then securely log the entry
        if query_result is not None:
            # encrypt UID for secure storage
            uid_secure = encrypt_data(str(query_result.get("uid"))) if ENCRYPTION_ENABLED else str(query_result.get("uid"))
            
            sql = "insert into logins(uid) values(%s)"
            cursor_mariadb.execute(sql, query_result.get("uid"))
            print(query_result.get("uid"))
            
            # log the scan event to the secure server
            try:
                # background task to send to websocket
                threading.Thread(
                    target=lambda: asyncio.run(report_scan(output, query_result.get("uid"))),
                    daemon=True
                ).start()
            except Exception as e:
                logger.error(f"Failed to report scan: {e}")

def offlineScanCard(db_conn):
    conn_sqlite = db_conn
    output = ""
    print("now reading . . .")
    print("Waiting for RFID/NFC card...")
    while True:
        uid = pn532.read_passive_target(timeout=0.5)
        print(".", end="")
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
        print('****')
        time.sleep(2)
        break
        
    cursor_sqlite = conn_sqlite.cursor()
    sql = "SELECT * FROM activeusers WHERE NFCUID = ?"
    cursor_sqlite.execute(sql, (output,))
    result = cursor_sqlite.fetchone()
    query_result = result

    if query_result is not None:
        # plaintext cache
        sql = "insert into cachedlogs(uid) values(?)"
        cursor_sqlite.execute(sql, (query_result[0],))
        conn_sqlite.commit()
        
        # encrypted cache
        conn_secure = sqlite3.connect("offline_secure.db")
        cursor_secure = conn_secure.cursor()
        
        # encrypt data if encryption is enabled
        uid_value = encrypt_data(str(query_result[0])) if ENCRYPTION_ENABLED else str(query_result[0])
        timestamp = datetime.now().isoformat()
        timestamp_value = encrypt_data(timestamp) if ENCRYPTION_ENABLED else timestamp
        
        sql_secure = "INSERT INTO cached_logs_secure(uid, loginTime, encrypted) VALUES (?, ?, ?)"
        cursor_secure.execute(sql_secure, (uid_value, timestamp_value, 1 if ENCRYPTION_ENABLED else 0))
        conn_secure.commit()
        conn_secure.close()
        
        print(f"Securely logged offline scan for user {query_result[0]}")
    else:
        print("user not found, denied")

def insertCardData():
    output = ""
    print("Waiting for RFID/NFC card...")
    while True:
        # check if card is available to read
        uid = pn532.read_passive_target(timeout=0.5)

        print(".", end="")
        # try again if no card is available.
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
        print('****')
        time.sleep(2)
        break
        
    try:
        # Try to connect to the online database
        conn_mariadb = pymysql.connect(
            host='100.102.124.81',
            user='temp',
            password='Password',
            database='temp',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
        
        with conn_mariadb.cursor() as cursor:
            # Check if card already exists
            sql = "SELECT * FROM activeusers WHERE NFCUID = %s"
            cursor.execute(sql, output)
            result = cursor.fetchone()
            
            if result is None:
                # card doesn't exist, get name and add it
                user_name = input("Enter name of new user: ")
                
                # Encrypt the name if encryption is enabled
                if ENCRYPTION_ENABLED:
                    secure_name = encrypt_data(user_name)
                    
                    # store in secure offline database
                    conn_secure = sqlite3.connect("offline_secure.db")
                    cursor_secure = conn_secure.cursor()
                    cursor_secure.execute(
                        "CREATE TABLE IF NOT EXISTS new_cards (id INTEGER PRIMARY KEY AUTOINCREMENT, NFCUID TEXT, name TEXT, added_time TEXT, synced INTEGER DEFAULT 0)"
                    )
                    cursor_secure.execute(
                        "INSERT INTO new_cards (NFCUID, name, added_time) VALUES (?, ?, ?)",
                        (encrypt_data(output), secure_name, encrypt_data(datetime.now().isoformat()))
                    )
                    conn_secure.commit()
                    conn_secure.close()
                
                sql = "INSERT INTO activeusers(NFCUID, name) VALUES (%s, %s)"
                cursor.execute(sql, (output, user_name))
                logger.info(f"Added new card {output} for user {user_name}")
                print(f"Successfully registered card for {user_name}")
                
                # report card addition to the server if websocket is up
                try:
                    # start a background thread to report the new card
                    threading.Thread(
                        target=lambda: asyncio.run(report_new_card(output, user_name)),
                        daemon=True
                    ).start()
                except Exception as e:
                    logger.error(f"Failed to report new card: {e}")
            else:
                logger.warning(f"Card {output} already exists for user {result.get('name')}")
                print(f"Card already exists for user: {result.get('name')}")
                
    except Exception as e:
        logger.error(f"Failed to insert card data: {e}")
        print(f"Error: Could not connect to database. {e}")
        
        # store card information locally for later sync
        try:
            conn_sqlite = sqlite3.connect("offline.db")
            cursor_sqlite = conn_sqlite.cursor()
            
            # check if card already exists locally
            cursor_sqlite.execute("SELECT * FROM activeusers WHERE NFCUID = ?", (output,))
            if cursor_sqlite.fetchone() is None:
                user_name = input("Enter name of new user: ")
                
                # store in regular offline DB
                cursor_sqlite.execute(
                    "INSERT INTO activeusers (NFCUID, name) VALUES (?, ?)",
                    (output, user_name)
                )
                conn_sqlite.commit()
                
                # store securely
                if ENCRYPTION_ENABLED:
                    conn_secure = sqlite3.connect("offline_secure.db")
                    cursor_secure = conn_secure.cursor()
                    cursor_secure.execute(
                        "CREATE TABLE IF NOT EXISTS new_cards (id INTEGER PRIMARY KEY AUTOINCREMENT, NFCUID TEXT, name TEXT, added_time TEXT, synced INTEGER DEFAULT 0)"
                    )
                    cursor_secure.execute(
                        "INSERT INTO new_cards (NFCUID, name, added_time) VALUES (?, ?, ?)",
                        (encrypt_data(output), encrypt_data(user_name), encrypt_data(datetime.now().isoformat()))
                    )
                    conn_secure.commit()
                    conn_secure.close()
                
                print(f"Card stored locally for {user_name} and will be synced later")
                logger.info(f"Stored new card {output} for user {user_name} locally")
            else:
                print("Card already exists in local database")
                
            conn_sqlite.close()
        except Exception as e:
            logger.error(f"Failed to store card locally: {e}")
            print(f"Error: Could not store card information. {e}")

# reporting a new card registration to the server
async def report_new_card(card_uid, user_name):
    try:
        # SSL context that ignores cert verification
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with websockets.connect(SERVER_URI, ssl=ssl_context) as websocket:
            # auth first
            auth_data = {
                "terminal_id": TERMINAL_ID,
                "auth_key": f"auth_{TERMINAL_ID}_key",
                "connection_time": datetime.utcnow().isoformat(),
            }
            await websocket.send(json.dumps(auth_data))
            
            response = await websocket.recv()
            auth_response = json.loads(response)
            
            if auth_response.get("status") != "authenticated":
                logger.error("Authentication failed, can't report new card")
                return
            
            # Send the new card data
            card_data = {
                "type": "new_card",
                "terminal_id": TERMINAL_ID,
                "card_uid": card_uid,
                "user_name": encrypt_data(user_name) if ENCRYPTION_ENABLED else user_name,
                "timestamp": datetime.now().isoformat(),
                "encrypted": ENCRYPTION_ENABLED,
                "encrypted_fields": ["user_name"] if ENCRYPTION_ENABLED else []
            }
            
            await websocket.send(json.dumps(card_data))
            logger.info(f"Reported new card registration: {card_uid} for {user_name}")
            
    except Exception as e:
        logger.error(f"Failed to connect and report new card: {e}")


# function to report scans to the websocket server
async def report_scan(card_uid, user_id):
    try:
        # SSL here ignores cert verification
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with websockets.connect(SERVER_URI, ssl=ssl_context) as websocket:
            # auth first
            auth_data = {
                "terminal_id": TERMINAL_ID,
                "auth_key": f"auth_{TERMINAL_ID}_key",
                "connection_time": datetime.utcnow().isoformat(),
            }
            await websocket.send(json.dumps(auth_data))
            
            response = await websocket.recv()
            auth_response = json.loads(response)
            
            if auth_response.get("status") != "authenticated":
                logger.error("Authentication failed, can't report scan")
                return
            
            # send scan data
            timestamp = datetime.now().isoformat()
            
            scan_data = {
                "type": "scan_event",
                "terminal_id": TERMINAL_ID,
                "card_uid": card_uid,
                "user_id": encrypt_data(str(user_id)) if ENCRYPTION_ENABLED else str(user_id),
                "timestamp": timestamp,
                "encrypted": ENCRYPTION_ENABLED,
                "encrypted_fields": ["user_id"] if ENCRYPTION_ENABLED else []
            }
            
            await websocket.send(json.dumps(scan_data))
            logger.info(f"Reported scan for card {card_uid}")
            
    except Exception as e:
        logger.error(f"Failed to connect and report scan: {e}")

# sync function that also syncs secure offline data
def sync_secure_offline_data():
    try:
        # regular sync first
        syncToOffline()
        
        # secure offline data sync second
        conn_sqlite = sqlite3.connect("offline_secure.db")
        conn_mariadb = pymysql.connect(
            host='100.102.124.81',
            user='temp',
            password='Password',
            database='temp',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
        
        cursor_sqlite = conn_sqlite.cursor()
        cursor_mariadb = conn_mariadb.cursor()
        
        # get entries that haven't been synced
        cursor_sqlite.execute("SELECT id, uid, loginTime, encrypted FROM cached_logs_secure WHERE synced = 0")
        logs = cursor_sqlite.fetchall()
        
        sync_count = 0
        for log in logs:
            log_id, uid_encrypted, login_time_encrypted, is_encrypted = log
            
            # decrypt data if it's encrypted
            if is_encrypted:
                uid = decrypt_data(uid_encrypted)
                login_time = decrypt_data(login_time_encrypted)
            else:
                uid = uid_encrypted
                login_time = login_time_encrypted
            
            # put into main DB
            try:
                sql = "INSERT INTO logins(uid, loginTime) VALUES(%s, %s)"
                cursor_mariadb.execute(sql, (uid, login_time))
                
                # mark as synced
                cursor_sqlite.execute("UPDATE cached_logs_secure SET synced = 1 WHERE id = ?", (log_id,))
                conn_sqlite.commit()
                sync_count += 1
            except Exception as e:
                logger.error(f"Error syncing log {log_id}: {e}")
        
        logger.info(f"Synced {sync_count} secure offline logs")
        
        # close connections
        conn_sqlite.close()
        conn_mariadb.close()
        
        return True
    except Exception as e:
        logger.error(f"Secure sync error: {e}")
        return False

def main():
    print("connecting . . .")
    online = True

    
    try:
        conn_mariadb = pymysql.connect(
            host='100.102.124.81',
            user='temp',
            password='Password',
            database='temp',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
        conn_mariadb.commit()
        print("Connected to online database")
        
        # start the secure WebSocket client in a background thread
        threading.Thread(target=lambda: asyncio.run(connect_to_server()), daemon=True).start()
    except:
        online = False
        print("unable to connect to main, using offline db")
        conn_sqlite = sqlite3.connect("offline.db")
        print("Using offline database")
    userIn = ''
    userIn = input("enter char (read(r)/insert(i)/sync(s)): ")

    while True:
    #    if userIn == 'i':
     #       insertCardData()
      #      break
        if userIn == 'r':
            if online:
                print("Performing secure sync")
                sync_secure_offline_data()
                onlineScanCard(conn_mariadb)
            else:
                offlineScanCard(conn_sqlite)
            #break
        if userIn == 'o':
            print("unable to connect to main, using offline db")
            conn_sqlite = sqlite3.connect("offline.db")
            print("Using offline database")
            offlineScanCard(conn_sqlite)

        if userIn == 's':
            print("Performing secure sync")
            if sync_secure_offline_data():
                print("Sync completed successfully")
            else:
                print("Sync encountered errors")
            break

if __name__ == '__main__':
    main()
