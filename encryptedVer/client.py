import asyncio
import websockets
import json
import logging
import os
import uuid
import ssl
import base64
import hashlib
import time
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('bus_client')

# config
SERVER_URI = "wss://100.102.124.81:8000"  # replace with your server's IP
TERMINAL_ID = str(uuid.uuid4())[:8]  # make unique terminal ID
ENCRYPTION_KEY_FILE = "terminal_key.key"
SALT = b'bus_client_salt'

# encryption setup
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
            iterations=100000,
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

# encryption util
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

async def connect():
    # SSL context that ignores cert verification
    # in prod, use actual cert validation
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    logger.info(f"Connecting to {SERVER_URI} as Terminal {TERMINAL_ID}")
    
    try:
        async with websockets.connect(SERVER_URI, ssl=ssl_context) as websocket:
            logger.info("Connected to server, authenticating...")
            
            # auth with the server
            auth_data = {
                "terminal_id": TERMINAL_ID,
                "auth_key": f"auth_{TERMINAL_ID}_key",  # auth scheme
                "connection_time": datetime.utcnow().isoformat(),
            }
            await websocket.send(json.dumps(auth_data))
            
            response = await websocket.recv()
            auth_response = json.loads(response)
            
            if auth_response.get("status") != "authenticated":
                logger.error("Authentication failed")
                return
                
            logger.info("Authentication successful")
            await websocket.send(f"scanner_{TERMINAL_ID} online")
            logger.info("Initial message sent")

            async def heartbeat():
                while True:
                    await asyncio.sleep(5)  # send every 5 seconds
                    try:
                        await websocket.send("heartbeat")
                        logger.debug("Sent heartbeat")
                    except Exception as e:
                        logger.error(f"Heartbeat failed: {e}")
                        break

            async def receive():
                try:
                    while True:
                        message = await websocket.recv()
                        try:
                            data = json.loads(message)
                            logger.info(f"Received JSON: {data}")
                        except:
                            logger.info(f"Received text: {message}")
                except websockets.ConnectionClosed:
                    logger.warning("Server disconnected")

            # example of sending encrypted data
            async def send_encrypted_scan():
                while True:
                    await asyncio.sleep(30)  # send every 30 seconds
                    try:
                        # example scan data that would be encrypted
                        card_id = "047919eaee6e80"
                        amount = "2.50"
                        payload = {
                            "type": "scan_report",
                            "terminal_id": TERMINAL_ID,
                            "card_id": card_id,
                            "amount": encrypt_data(amount) if ENCRYPTION_ENABLED else amount,
                            "timestamp": datetime.utcnow().isoformat(),
                            "encrypted": ENCRYPTION_ENABLED,
                            "encrypted_fields": ["amount"]
                        }
                        
                        await websocket.send(json.dumps(payload))
                        logger.info(f"Sent encrypted scan for card {card_id}")
                    except Exception as e:
                        logger.error(f"Failed to send scan: {e}")
                        break

            await asyncio.gather(
                heartbeat(),
                receive(),
                send_encrypted_scan()
            )
    except Exception as e:
        logger.error(f"Connection error: {e}")
        

if __name__ == "__main__":
    while True:
        try:
            asyncio.run(connect())
        except KeyboardInterrupt:
            logger.info("Client shutdown by user")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            logger.info("Attempting to reconnect in 10 seconds...")
            time.sleep(10)
