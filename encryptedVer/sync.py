import sqlite3
import pymysql
import logging
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime

# setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("sync.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('sync')

# encryption config
ENCRYPTION_KEY_FILE = "sync_key.key"
SALT = b'sync_salt'

def generate_encryption_key():
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as key_file:
            return key_file.read()
    else:
        password = b"sync_secure_password" 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        with open(ENCRYPTION_KEY_FILE, 'wb') as key_file:
            key_file.write(key)
        return key

# init encryption
try:
    encryption_key = generate_encryption_key()
    cipher = Fernet(encryption_key)
    ENCRYPTION_ENABLED = True
    logger.info("Data encryption enabled for sync")
except Exception as e:
    logger.error(f"Encryption initialization failed for sync: {e}")
    logger.warning("Data will be transferred unencrypted")
    ENCRYPTION_ENABLED = False

# encryption functions
def encrypt_data(data):
    if not ENCRYPTION_ENABLED:
        return data
    if data is None:
        return None
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

def syncToOffline():
    logger.info("Starting sync to offline database")
    try:
        conn_sqlite = sqlite3.connect("offline.db")
        conn_mariadb = pymysql.connect(
            host='100.102.124.81',
            user='temp',
            password='Password',
            database='temp',
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )

        # create a secure log entry for the sync
        conn_sqlite_secure = sqlite3.connect("offline_secure.db")
        cursor_sqlite_secure = conn_sqlite_secure.cursor()
        sync_time = datetime.now().isoformat()
        cursor_sqlite_secure.execute(
            "CREATE TABLE IF NOT EXISTS sync_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, status TEXT)"
        )
        cursor_sqlite_secure.execute(
            "INSERT INTO sync_logs (timestamp, status) VALUES (?, ?)",
            (sync_time, "started")
        )
        conn_sqlite_secure.commit()

        # regular sync logic
        cursor_sqlite = conn_sqlite.cursor()
        cursor_sqlite.execute('SELECT * FROM activeusers')
        results_sqlite = cursor_sqlite.fetchall()
        
        sql = "select * from activeusers"
        cursor_mariadb = conn_mariadb.cursor()
        cursor_mariadb.execute(sql)
        results_mariadb = cursor_mariadb.fetchall()

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
                logger.info(f"{y} not found in sqlitedb... adding to local.")
                cursor_sqlite.execute(sql,(y,z))
                conn_sqlite.commit()
                
                # also add to secure storage with encryption
                if ENCRYPTION_ENABLED:
                    # Only encrypt the sensitive data
                    uid_secure = encrypt_data(str(y))
                    nfc_secure = encrypt_data(z)
                    
                    conn_secure = sqlite3.connect("offline_secure.db")
                    cursor_secure = conn_secure.cursor()
                    cursor_secure.execute(
                        "INSERT OR REPLACE INTO activeusers_secure(uid, NFCUID, encrypted) VALUES (?, ?, 1)",
                        (uid_secure, nfc_secure)
                    )
                    conn_secure.commit()
                    conn_secure.close()
            logger.debug(f"User {y}, Card {z}")

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
                logger.info(f"{uid} not found in maindb... removing.")
                cursor_sqlite.execute(sql,(uid,))
                conn_sqlite.commit()
                
                # Also remove from secure storage
                conn_secure = sqlite3.connect("offline_secure.db")
                cursor_secure = conn_secure.cursor()
                # We need to handle both encrypted and unencrypted UIDs
                if ENCRYPTION_ENABLED:
                    uid_secure = encrypt_data(str(uid))
                    cursor_secure.execute("DELETE FROM activeusers_secure WHERE uid = ? OR uid = ?", (uid_secure, str(uid)))
                else:
                    cursor_secure.execute("DELETE FROM activeusers_secure WHERE uid = ?", (str(uid),))
                conn_secure.commit()
                conn_secure.close()
            logger.debug(f"User {uid}, Card {NFCUID}")
        
        #offloading cachedlogs to maindb
        sql = "select * from cachedlogs"
        cursor_sqlite.execute(sql)
        sqlite_result = cursor_sqlite.fetchall()
        count = 0
        for a,b,c in sqlite_result:
            count += 1
            logger.debug(f"Log {a}, User {b}, Time {c}")
            
            sql = "delete from cachedlogs where uid = ? and loginTime = ?"
            cursor_sqlite.execute(sql,(b,c))
            conn_sqlite.commit()
            
            sql = "insert into logins(uid,loginTime) values(%s,%s)"
            cursor_mariadb.execute(sql,(b,c))
            
            # check and clear from secure cache if present
            if ENCRYPTION_ENABLED:
                conn_secure = sqlite3.connect("offline_secure.db")
                cursor_secure = conn_secure.cursor()
                
                # find matching entries by decrypting and comparing
                cursor_secure.execute("SELECT id, uid, loginTime FROM cached_logs_secure WHERE synced = 0")
                secure_logs = cursor_secure.fetchall()
                
                for log_id, uid_encrypted, login_time_encrypted in secure_logs:
                    try:
                        uid_decrypted = decrypt_data(uid_encrypted)
                        login_time_decrypted = decrypt_data(login_time_encrypted)
                        
                        if uid_decrypted == str(b) and login_time_decrypted == str(c):
                            # mark as synced
                            cursor_secure.execute("UPDATE cached_logs_secure SET synced = 1 WHERE id = ?", (log_id,))
                    except Exception as e:
                        logger.error(f"Error processing secure log {log_id}: {e}")
                
                conn_secure.commit()
                conn_secure.close()
        
        # update the sync status in the secure log
        cursor_sqlite_secure.execute(
            "UPDATE sync_logs SET status = ? WHERE timestamp = ?",
            (f"completed - synced {count} logs", sync_time)
        )
        conn_sqlite_secure.commit()
        conn_sqlite_secure.close()
        
        logger.info(f"Offloaded {count} logs...")
        
        return True
    except Exception as e:
        logger.error(f"Sync error: {e}")
        
        # log the error in secure storage
        try:
            conn_sqlite_secure = sqlite3.connect("offline_secure.db")
            cursor_sqlite_secure = conn_sqlite_secure.cursor()
            cursor_sqlite_secure.execute(
                "UPDATE sync_logs SET status = ? WHERE timestamp = ?",
                (f"error - {str(e)}", sync_time)
            )
            conn_sqlite_secure.commit()
            conn_sqlite_secure.close()
        except:
            pass
            
        return False

def main():
    syncToOffline()

if __name__ == '__main__':
    main()
