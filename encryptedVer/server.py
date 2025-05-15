import asyncio
import websockets
import pymysql
from datetime import datetime, timedelta

#start by pulling list of all known devices from DB
#need to pull each device and most recent time seen then import them into the list below
conn_mariadb = pymysql.connect(host='100.102.124.81',
user='temp',
password='Password',
database='temp',
charset='utf8mb4',
cursorclass=pymysql.cursors.DictCursor,
autocommit=True)
conn_mariadb.commit()
sql = """SELECT d1.*
FROM device_status_log d1
JOIN (
    SELECT ip, MAX(timestamp) AS latest_time
    FROM device_status_log
    GROUP BY ip
) d2 ON d1.ip = d2.ip AND d1.timestamp = d2.latest_time;"""
cursor_mariadb = conn_mariadb.cursor()
cursor_mariadb.execute(sql)
results_mariadb = cursor_mariadb.fetchall()

print(results_mariadb)






#Store last_seen times by IP or device ID

#adding example entry here
temp = datetime.utcnow()
last_seen = {}
status_state = {}  # Stores last known status per device


for x in results_mariadb:
    ip = x["ip"]
    time = x["timestamp"]
    status = x["status"]
    last_seen[ip] = time
    status_state[ip] = status


print(status_state)

async def handler(websocket):
    client_ip = websocket.remote_address[0]
    print(f"Connected: {client_ip}")

    try:
        async for message in websocket:
            now = datetime.utcnow()

            if message == "heartbeat":
                last_seen[client_ip] = now
                print(f"Heartbeat from {client_ip} at {now.isoformat()}")
            else:
                print(f"Message from {client_ip}: {message}")
                last_seen[client_ip] = now
                await websocket.send(f"Echo: {message}")
    except websockets.ConnectionClosed:
        print(f"Disconnected: {client_ip}")
    except Exception as e:
        print(f"Error with {client_ip}: {e}")



async def monitor_devices():
    while True:
        await asyncio.sleep(10)
        now = datetime.utcnow()
        print("\nDevice Status Report:")

        for device_id, seen_time in last_seen.items():
            online = (now - seen_time) < timedelta(seconds=15)
            new_status = "online" if online else "offline"

            # Compare with last known status
            old_status = status_state.get(device_id)
            if old_status != new_status:
                print(f">>> STATUS CHANGE: {device_id} is now {new_status}")
                #change detected, logging database.
                sql = """
            INSERT INTO device_status_log (name, ip, status)
            VALUES (%s, %s, %s)
        """

                values = (' ', device_id, new_status)
                cursor_mariadb.execute(sql,values)
                print("inserted")

            # Save new status
            status_state[device_id] = new_status

            print(f"{device_id} - Last seen: {seen_time.isoformat()} - {new_status}")

async def main():
    print("Starting WebSocket server on 0.0.0.0:8000")
    server = websockets.serve(handler, "0.0.0.0", 8000)
    await asyncio.gather(server, monitor_devices())

asyncio.run(main())
