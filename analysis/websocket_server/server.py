import asyncio
import json
import sys
import os
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
            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            info = self.ghidra_manager.get_program_info()
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
    # Data Extraction Handlers
    # -----------------------------

    async def handle_get_strings(self, websocket, min_length=4):
        """Get all strings in the binary"""
        try:
            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            strings = await loop.run_in_executor(
                None,
                self.ghidra_manager.get_strings,
                min_length
            )

            await self.send(websocket, "strings", {"strings": strings})

        except Exception as e:
            await self.error(websocket, f"Failed to get strings: {e}")

    async def handle_get_imports(self, websocket):
        """Get all imports in the binary"""
        try:
            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            imports = await loop.run_in_executor(
                None,
                self.ghidra_manager.get_imports
            )

            await self.send(websocket, "imports", {"imports": imports})

        except Exception as e:
            await self.error(websocket, f"Failed to get imports: {e}")

    # -----------------------------
    # Annotation Handlers
    # -----------------------------

    async def handle_rename_function(self, websocket, address, new_name):
        """Rename a function"""
        try:
            if not address or not new_name:
                return await self.error(websocket, "address and new_name are required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            func = self.ghidra_manager.get_function_by_address(address)
            old_name = func.getName() if func else None

            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None,
                self.ghidra_manager.rename_function,
                address,
                new_name
            )

            if not success:
                return await self.error(websocket, f"Failed to rename function at {address}")

            await self.send(websocket, "function_renamed", {
                "address": address,
                "old_name": old_name,
                "new_name": new_name
            })

        except Exception as e:
            await self.error(websocket, f"Rename failed: {e}")

    async def handle_add_comment(self, websocket, address, comment):
        """Add an end-of-line comment at an address"""
        try:
            if not address or not comment:
                return await self.error(websocket, "address and comment are required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None,
                self.ghidra_manager.add_comment,
                address,
                comment
            )

            if not success:
                return await self.error(websocket, f"Failed to add comment at {address}")

            await self.send(websocket, "comment_added", {
                "address": address,
                "comment": comment
            })

        except Exception as e:
            await self.error(websocket, f"Add comment failed: {e}")

    async def handle_add_function_comment(self, websocket, function_address, comment):
        """Add a comment to a function"""
        try:
            if not function_address or not comment:
                return await self.error(websocket, "function_address and comment are required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None,
                self.ghidra_manager.add_function_comment,
                function_address,
                comment
            )

            if not success:
                return await self.error(websocket, f"Failed to add function comment")

            await self.send(websocket, "function_comment_added", {
                "address": function_address,
                "comment": comment
            })

        except Exception as e:
            await self.error(websocket, f"Add function comment failed: {e}")

    async def handle_add_bookmark(self, websocket, address, category, comment, bookmark_type="Note"):
        """Add a bookmark at an address"""
        try:
            if not address or not category or not comment:
                return await self.error(websocket, "address, category, and comment are required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None,
                self.ghidra_manager.add_bookmark,
                address,
                category,
                comment,
                bookmark_type
            )

            if not success:
                return await self.error(websocket, f"Failed to add bookmark at {address}")

            await self.send(websocket, "bookmark_added", {
                "address": address,
                "category": category,
                "comment": comment,
                "type": bookmark_type
            })

        except Exception as e:
            await self.error(websocket, f"Add bookmark failed: {e}")

    async def handle_add_function_tag(self, websocket, function_address, tag):
        """Add a tag to a function"""
        try:
            if not function_address or not tag:
                return await self.error(websocket, "function_address and tag are required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            success = await loop.run_in_executor(
                None,
                self.ghidra_manager.add_function_tag,
                function_address,
                tag
            )

            if not success:
                return await self.error(websocket, f"Failed to add tag to function")

            await self.send(websocket, "function_tag_added", {
                "address": function_address,
                "tag": tag
            })

        except Exception as e:
            await self.error(websocket, f"Add function tag failed: {e}")

    async def handle_get_function_annotations(self, websocket, function_address):
        """Get all annotations for a function"""
        try:
            if not function_address:
                return await self.error(websocket, "function_address is required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            annotations = await loop.run_in_executor(
                None,
                self.ghidra_manager.get_function_annotations,
                function_address
            )

            if annotations is None:
                return await self.error(websocket, f"Function not found at {function_address}")

            # Convert tags to strings for JSON serialization
            if annotations.get("tags"):
                annotations["tags"] = [str(t) for t in annotations["tags"]]

            await self.send(websocket, "function_annotations", annotations)

        except Exception as e:
            await self.error(websocket, f"Get function annotations failed: {e}")

    async def handle_get_comments_at(self, websocket, address):
        """Get all comments at an address"""
        try:
            if not address:
                return await self.error(websocket, "address is required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            comments = await loop.run_in_executor(
                None,
                self.ghidra_manager.get_comments_at,
                address
            )

            await self.send(websocket, "comments", {
                "address": address,
                "comments": comments
            })

        except Exception as e:
            await self.error(websocket, f"Get comments failed: {e}")

    async def handle_get_bookmarks_at(self, websocket, address):
        """Get all bookmarks at an address"""
        try:
            if not address:
                return await self.error(websocket, "address is required")

            if self.ghidra_manager.current_program is None:
                return await self.error(websocket, "No program loaded")

            loop = asyncio.get_event_loop()
            bookmarks = await loop.run_in_executor(
                None,
                self.ghidra_manager.get_bookmarks_at,
                address
            )

            await self.send(websocket, "bookmarks", {
                "address": address,
                "bookmarks": bookmarks
            })

        except Exception as e:
            await self.error(websocket, f"Get bookmarks failed: {e}")

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

                # Data extraction
                elif command == "get_strings":
                    await self.handle_get_strings(websocket, data.get("min_length", 4))

                elif command == "get_imports":
                    await self.handle_get_imports(websocket)

                # Annotations - Rename
                elif command == "rename_function":
                    await self.handle_rename_function(
                        websocket,
                        data.get("address"),
                        data.get("new_name")
                    )

                # Annotations - Comments
                elif command == "add_comment":
                    await self.handle_add_comment(
                        websocket,
                        data.get("address"),
                        data.get("comment")
                    )

                elif command == "add_function_comment":
                    await self.handle_add_function_comment(
                        websocket,
                        data.get("address"),
                        data.get("comment")
                    )

                elif command == "get_comments":
                    await self.handle_get_comments_at(websocket, data.get("address"))

                # Annotations - Bookmarks
                elif command == "add_bookmark":
                    await self.handle_add_bookmark(
                        websocket,
                        data.get("address"),
                        data.get("category"),
                        data.get("comment"),
                        data.get("type", "Note")
                    )

                elif command == "get_bookmarks":
                    await self.handle_get_bookmarks_at(websocket, data.get("address"))

                # Annotations - Tags
                elif command == "add_function_tag":
                    await self.handle_add_function_tag(
                        websocket,
                        data.get("address"),
                        data.get("tag")
                    )

                elif command == "get_function_annotations":
                    await self.handle_get_function_annotations(
                        websocket,
                        data.get("address")
                    )

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
        ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")
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
