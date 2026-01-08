# RE-Observatory
Interactive canvas-based reverse engineering tool that provides visual binary analysis through draggable function nodes, control flow graphs, and real-time decompilation. Built with Electron, React, Python, Ghidra, and pwndbg, with optional AI assistance via MCP server.



## Next Steps when finshed with other parts of the project

1. **Set up PostgreSQL locally**
   - Install PostgreSQL
   - Create `re_observatory` database
   - Run schema.sql

2. **Implement DatabaseManager**
   - Create the db_manager.py file
   - Add asyncpg to requirements.txt

3. **Add save methods to GhidraManager**
   - Implement save_program()
   - Test with transactions

4. **Update WebSocket server**
   - Integrate DatabaseManager
   - Add new command handlers
   - Handle all the rename/canvas operations

5. **Update Electron/React**
   - Handle new message types
   - Send canvas position updates on drag