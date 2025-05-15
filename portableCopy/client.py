import asyncio
import websockets

async def connect():
    uri = "ws://100.102.124.81:8000"  # Replace with your server's IP

    async with websockets.connect(uri) as websocket:
        print("Connected to server.")
        await websocket.send("scanner_01 online")
        print("Initial message sent.")

        async def heartbeat():
            while True:
                await asyncio.sleep(5)  # Send every 5 seconds
                try:
                    await websocket.send("heartbeat")
                    print("Sent heartbeat.")
                except Exception as e:
                    print(f"Heartbeat failed: {e}")
                    break

        async def receive():
            try:
                while True:
                    message = await websocket.recv()
                    print(f"Received: {message}")
            except websockets.ConnectionClosed:
                print("Server disconnected.")

        await asyncio.gather(heartbeat(), receive())

asyncio.run(connect())

