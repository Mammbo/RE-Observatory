import asyncio
import json
import sys
import os
from pathlib import Path
import websockets

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from analysis.shared.analyzers.ghidra_manager import GhidraManager
from analysis.shared.analyzers.analysis_manager import AnalysisManager


class AnalysisWebSocketServer:
    """WebSocket server that streams Ghidra analysis to Electron"""

    def __init__(self, host='localhost', port=9999):
        self.host = host
        self.port = port
        self.ghidra_manager = None
        self.analysis_manager = None
        self.binary_path = None
        self.client = None

    # -----------------------------
    # Utility Methods
    # -----------------------------

    async def send(self, websocket, type_, payload):
        """Send a typed message to the client"""
        await websocket.send(json.dumps({
            "type": type_,
            "payload": payload
        }))

    async def error(self, websocket, message):
        """Send an error message to the client"""
        print(f"Error: {message}")
        await self.send(websocket, "error", {"message": message})

    # -----------------------------
    # Binary Analysis Handlers
    # -----------------------------

    async def handle_analyze_binary(self, websocket, binary_path):
        """Load and analyze a binary file"""
        try:
            if not binary_path:
                return await self.error(websocket, "binary_path is required")

            # Initialize AnalysisManager for this binary
            self.binary_path = binary_path
            self.analysis_manager = AnalysisManager(binary_path)

            loop = asyncio.get_event_loop()
            program = await loop.run_in_executor(
                None,
                self.ghidra_manager.analyze_binary,
                binary_path
            )

            program_info = self.ghidra_manager.get_program_info()

            await self.send(websocket, "analysis_complete", {
                "name": program.getName(),
                "info": program_info
            })

        except Exception as e:
            await self.error(websocket, f"Analysis failed: {e}")

    async def handle_get_program_info(self, websocket):
        """Get metadata about the loaded program"""
        try:
            if self.analysis_manager is None:
                return await self.error(websocket, "No program loaded")

            info = self.analysis_manager.get_program_info()
            await self.send(websocket, "program_info", info)

        except Exception as e:
            await self.error(websocket, f"Failed to get program info: {e}")

    # -----------------------------
    # Function Handlers
    # -----------------------------

    async def handle_get_functions(self, websocket):
        """Get all functions in the binary"""
        try:
            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            functions = await loop.run_in_executor(
                None,
                self.ghidra_manager.get_functions
            )

            # Convert Java Function objects to JSON-serializable dicts
            func_list = [{
                "name": f.getName(),
                "address": hex(f.getEntryPoint().getOffset()),
                "size": f.getBody().getNumAddresses()
            } for f in functions]

            await self.send(websocket, "functions", {"functions": func_list})

        except Exception as e:
            await self.error(websocket, f"Failed to get functions: {e}")

    async def handle_decompile_function(self, websocket, address):
        """Decompile a function at the given address"""
        try:
            if not address:
                return await self.error(websocket, "address is required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            decompiled = await loop.run_in_executor(
                None,
                self.ghidra_manager.decompile_function,
                address
            )

            if decompiled is None:
                return await self.error(websocket, f"Failed to decompile function at {address}")

            await self.send(websocket, "decompiled", {
                "address": address,
                "code": decompiled
            })

        except Exception as e:
            await self.error(websocket, f"Decompilation failed: {e}")

    # -----------------------------
    # Graph Handlers
    # -----------------------------

    async def handle_get_cfg(self, websocket, function_address):
        """Get control flow graph for a function"""
        try:
            if not function_address:
                return await self.error(websocket, "function_address is required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            cfg = await loop.run_in_executor(
                None,
                self.ghidra_manager.get_cfg,
                function_address
            )

            if cfg is None:
                return await self.error(websocket, f"Failed to get CFG for {function_address}")

            await self.send(websocket, "cfg", {
                "address": function_address,
                "cfg": cfg
            })

        except Exception as e:
            await self.error(websocket, f"CFG generation failed: {e}")

    async def handle_get_call_graph(self, websocket):
        """Get the call graph for the entire program"""
        try:
            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            call_graph = await loop.run_in_executor(
                None,
                self.ghidra_manager.get_call_graph
            )

            if call_graph is None:
                return await self.error(websocket, "Failed to get call graph")

            await self.send(websocket, "call_graph", call_graph)

        except Exception as e:
            await self.error(websocket, f"Call graph generation failed: {e}")

    # -----------------------------
    # Connection Handler
    # -----------------------------

    async def handler(self, websocket):
        """Handle incoming WebSocket connections"""
        print(f"Client connected: {websocket.remote_address}")
        self.client = websocket

        try:
            async for message in websocket:
                event = json.loads(message)
                command = event.get('command')
                data = event.get('data', {})

                print(f"Received: {command}")

                # Binary analysis
                if command == "analyze_binary":
                    await self.handle_analyze_binary(websocket, data.get("binary_path"))

                elif command == "get_program_info":
                    await self.handle_get_program_info(websocket)

                # Functions
                elif command == "get_functions":
                    await self.handle_get_functions(websocket)

                elif command == "decompile_function":
                    await self.handle_decompile_function(websocket, data.get("address"))

                # Graphs
                elif command == "get_cfg":
                    await self.handle_get_cfg(websocket, data.get("address"))

                elif command == "get_call_graph":
                    await self.handle_get_call_graph(websocket)

                # Unknown command
                else:
                    await self.error(websocket, f"Unknown command: {command}")

        except websockets.exceptions.ConnectionClosed:
            print("Client disconnected")
        except json.JSONDecodeError as e:
            print(f"Invalid JSON received: {e}")
        except Exception as e:
            print(f"Handler error: {e}")
        finally:
            self.client = None
            if self.ghidra_manager and self.ghidra_manager.current_program:
                self.ghidra_manager.close_decompiler()
                self.ghidra_manager.close_program()
                print("Ghidra program closed")

    # -----------------------------
    # Server Lifecycle
    # -----------------------------

    async def start(self):
        """Start the WebSocket server"""
        # Initialize Ghidra once at startup
        ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR")
        if not ghidra_install:
            raise RuntimeError("GHIDRA_INSTALL_DIR not set")
        print(f"Initializing Ghidra from {ghidra_install}...")
        self.ghidra_manager = GhidraManager(ghidra_install)

        print(f"Starting WebSocket server on {self.host}:{self.port}")
        async with websockets.serve(self.handler, self.host, self.port):
            print(f"WebSocket server started at ws://{self.host}:{self.port}")
            print("Waiting for connections...")
            await asyncio.Future()  # Run forever


def main():
    server = AnalysisWebSocketServer(host='localhost', port=9999)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nServer stopped")


if __name__ == "__main__":
    main()
