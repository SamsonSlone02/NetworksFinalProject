import asyncio
import websockets

async def handler(websocket):
    client_ip = websocket.remote_address[0]
    print(f"Connected: {client_ip}")

    try:
        async for message in websocket:
            if message == "heartbeat":
                print(f"Heartbeat from {client_ip}")
                
            else:
                print(f"Message from {client_ip}: {message}")
                await websocket.send(f"Echo: {message}")
    except websockets.ConnectionClosed:
        print(f"Disconnected: {client_ip}")
    except Exception as e:
        print(f"Error with {client_ip}: {e}")

async def main():
    print("Starting WebSocket server on 0.0.0.0:8000")
    async with websockets.serve(handler, "0.0.0.0", 8000):
        await asyncio.Future()  # Run forever

asyncio.run(main())

