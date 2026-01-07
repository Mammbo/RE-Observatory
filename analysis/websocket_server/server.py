import asyncio
import json
import sys
from pathlib import Path
import websockets

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from analysis.shared.analyzers.ghidra_manager import GhidraManager

class AnalysisWebSocketServer:
    """WebSocket server that streams Ghidra analysis to Electron"""

    def __init__(self, host='localhost', port=9999):
        self.host = host
        self.port = port
        self.ghidra_manager = None
        self.client = None

    async def send(self, websocket, type_, payload):
        await websocket.send(json.dumps({
            "type": type_,
            "payload": payload
        }))

    async def error(self, websocket, message): 
        await self.send(websocket, "error", {"message": message})
        
    async def handle_analyze_binary(self, binary_path):
        pass

    async def handle_decompile_function(self, websocket, address):
        pass

    async def handle_get_cfg(self, function_address):
        pass
    
    async def handle_get_call_graph(self, websocket):
        pass


    async def handler(self, websocket):
        """Handle incoming WebSocket connections"""
        try:
            async for message in websocket:
                event = json.loads(message)
                command = event.get('command')
                data = event.get('data', {})

                print(f"Recieved: {command}")

                if command == "analyze_binary":
                    await self.handle_analyze_binary(websocket, data.get("binary_path"))
                elif command == 'decompile_function':
                    await self.handle_decompile_function(websocket, data.get('address'))
                elif command == 'get_cfg':
                    await self.handle_get

        except websockets.exceptions.ConnectionClosed:
            print("Client disconnected")
        finally:
            if self.ghidra_manager:
                self.ghidra_manager.close_program()
                self.ghidra_manager = None
                print("Ghidra session closed")

    async def start(self):
        """Start the WebSocket server"""
        print(f"Starting WebSocket server on {self.host}:{self.port}")
        async with websockets.serve(self.handler, self.host, self.port):
            print(f"WebSocket servera started at ws://{self.host}:{self.port}")
            await asyncio.Future()  # Run forever

def main(): 
    server = AnalysisWebSocketServer(host='localhost', port=9999)
    try: 
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("Server Stopped")

if __name__ == "__main__": 
    main()