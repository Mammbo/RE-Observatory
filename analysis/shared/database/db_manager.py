import sqlite3
from pathlib import Path
import json
class DBManager:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = Path(__file__).parent / "analysis_and_graph.db"
        self.con = sqlite3.connect(db_path)
        self.cur = self.con.cursor()
        self.con.execute("PRAGMA foreign_keys = ON")                           
        self._init_schema() 
    def _init_schema(self):
        schema_path = Path(__file__).parent / "schema.sql"                     
        self.con.executescript(schema_path.read_text())

    def _insert_binary(self, data):
        self.cur.execute("INSERT INTO binaries (name, filepath, format, image_base, entrypoint, architecture, bits, min_address, max_address, virtual_size, original_size) " \
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (data["name"], data["filepath"], data["format"], data["image_base"], data["entrypoint"], data["architecture"], data["bits"], data["min_address"], data["max_address"], data["virtual_size"], data["original_size"]))
        id = self.cur.lastrowid
        return id   
    def _insert_security(self, binary_id, data):
        self.cur.execute("INSERT INTO security_features (binary_id, pie, nx, aslr, relro, stack_canary, rwx_sections, pe_features, elf_features, macho_features)" \
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (binary_id, data["pie"], data["nx"], data["aslr"], data["relro"], data["stack_canary"], json.dumps(data["rwx_sections"]) if data.get("rwx_sections") else None, json.dumps(data["pe"]) if data.get("pe") else None, json.dumps(data["elf"]) if data.get("elf") else None, json.dumps(data["macho"]) if data.get("macho") else None)) 
    def _insert_imports(self, binary_id, data): 
        # conver to list and use list comprhension to unwrap large array
        imports = [
            (binary_id, imp["name"], imp["address"])
            for imp in data
        ]
        self.cur.executemany("INSERT INTO imports (binary_id, name, address) VALUES (?, ?, ?)", imports)
    def _insert_exports(self, binary_id, data): 
        exports = [
            (binary_id, exp["name"], exp["address"])
            for exp in data
        ]
        self.cur.executemany("INSERT INTO exports (binary_id, name, address) VALUES (?, ?, ?)", exports)
    def _insert_libraries(self, binary_id, data):
        if not data:
            return
        libraries = [
            (binary_id, lib["name"], json.dumps(lib["current_version"]), json.dumps(lib["compatibility_version"]))
            for lib in data
        ]
        self.cur.executemany("INSERT INTO libraries (binary_id, name, current_version, compatibility_version) VALUES (?, ?, ?, ?)", libraries)
    def _insert_strings(self, binary_id, data):
        if not data:
            return
        rows = []
        mapping = {
            "ascii": data["static"]["ascii"],
            "utf16": data["static"]["utf16"],
            "stack": data["advanced"]["stack"],
            "tight": data["advanced"]["tight"],
            "decode": data["obfuscated"]["decode"],
        }
        for category, values in mapping.items():
            if values:
                rows.extend((binary_id, category, v) for v in values)
        if rows:
            self.cur.executemany("INSERT INTO strings (binary_id, category, value) VALUES (?, ?, ?)", rows)
    def _insert_functions(self, binary_id, functions, decompiled):
        if not functions:
            return
        rows = [
            (binary_id, fn["name"], fn["address"], fn["size"], decompiled[fn["address"]] if decompiled and fn["address"] in decompiled else None)
            for fn in functions
        ]
        self.cur.executemany("INSERT INTO functions (binary_id, name, address, size, decompiled) VALUES (?, ?, ?, ?, ?)", rows)
    def _insert_call_graph(self, binary_id, call_graph):
        if not call_graph:
            return
        nodes = call_graph["nodes"]
        edges = call_graph["edges"]
        if nodes:
            node_rows = [
                (binary_id, addr, info["name"], info["type"])
                for addr, info in nodes.items()
            ]
            self.cur.executemany("INSERT INTO call_graph_nodes (binary_id, address, name, type) VALUES (?, ?, ?, ?)", node_rows)
        if edges:
            edge_rows = [(binary_id, e["src"], e["dst"]) for e in edges]
            self.cur.executemany("INSERT INTO call_graph_edges (binary_id, src, dst) VALUES (?, ?, ?)", edge_rows)
    def _insert_cfgs(self, binary_id, cfgs):
        if not cfgs:
            return
        node_rows = []
        edge_rows = []
        for func_addr, cfg in cfgs.items():
            for node in cfg["nodes"]:
                node_rows.append((binary_id, func_addr, node["id"], node["start"], node["end"]))
            for edge in cfg["edges"]:
                edge_rows.append((binary_id, func_addr, edge["src"], edge["dst"], edge["type"]))
        if node_rows:
            self.cur.executemany("INSERT INTO cfg_nodes (binary_id, function_addr, block_id, start_addr, end_addr) VALUES (?, ?, ?, ?, ?)", node_rows)
        if edge_rows:
            self.cur.executemany("INSERT INTO cfg_edges (binary_id, function_addr, src, dst, type) VALUES (?, ?, ?, ?, ?)", edge_rows)
    def _insert_user_nodes(self, binary_id, user_nodes):
        if not user_nodes:
            return
        rows = [
            (binary_id, n["id"], n["position"]["x"], n["position"]["y"], json.dumps(n["data"]))
            for n in user_nodes
        ]
        self.cur.executemany("INSERT INTO user_nodes (binary_id, node_id, position_x, position_y, data) VALUES (?, ?, ?, ?, ?)", rows)
    def _insert_user_edges(self, binary_id, user_edges):
        if not user_edges:
            return
        rows = [
            (binary_id, e["id"], e["source"], e["target"])
            for e in user_edges
        ]
        self.cur.executemany("INSERT INTO user_edges (binary_id, edge_id, source, target) VALUES (?, ?, ?, ?)", rows)
    def save_analysis(self, data):
        meta = data["programInfo"]["meta"]
        binary_id = self._insert_binary(meta)
        self._insert_security(binary_id, meta["security"])
        self._insert_imports(binary_id, meta["imports"])
        self._insert_exports(binary_id, meta["exports"])
        self._insert_libraries(binary_id, meta["libraries"])
        self._insert_strings(binary_id, meta["strings"])
        self._insert_functions(binary_id, data["functions"], data["decompiled"])
        self._insert_call_graph(binary_id, data["callGraph"])
        self._insert_cfgs(binary_id, data["cfgs"])
        self.con.commit()
        return binary_id
    def close(self):
        self.con.close()
    def get_binary(self, binary_id):
        self.con.row_factory = sqlite3.Row
        cur = self.con.cursor()

        # binaries
        row = cur.execute("SELECT * FROM binaries WHERE id = ?", (binary_id,)).fetchone()
        if not row:
            return None
        meta = {
            "name": row["name"],
            "filepath": row["filepath"],
            "format": row["format"],
            "image_base": row["image_base"],
            "entrypoint": row["entrypoint"],
            "architecture": row["architecture"],
            "bits": row["bits"],
            "min_address": row["min_address"],
            "max_address": row["max_address"],
            "virtual_size": row["virtual_size"],
            "original_size": row["original_size"],
        }

        # security
        sec_row = cur.execute("SELECT * FROM security_features WHERE binary_id = ?", (binary_id,)).fetchone()
        if sec_row:
            meta["security"] = {
                "format": meta["format"],
                "pie": sec_row["pie"],
                "nx": sec_row["nx"],
                "aslr": sec_row["aslr"],
                "relro": sec_row["relro"],
                "stack_canary": sec_row["stack_canary"],
                "rwx_sections": json.loads(sec_row["rwx_sections"]) if sec_row["rwx_sections"] else None,
                "pe": json.loads(sec_row["pe_features"]) if sec_row["pe_features"] else None,
                "elf": json.loads(sec_row["elf_features"]) if sec_row["elf_features"] else None,
                "macho": json.loads(sec_row["macho_features"]) if sec_row["macho_features"] else None,
            }
        else:
            meta["security"] = None

        # imports
        meta["imports"] = [
            {"name": r["name"], "address": r["address"]}
            for r in cur.execute("SELECT * FROM imports WHERE binary_id = ?", (binary_id,)).fetchall()
        ]

        # exports
        meta["exports"] = [
            {"name": r["name"], "address": r["address"]}
            for r in cur.execute("SELECT * FROM exports WHERE binary_id = ?", (binary_id,)).fetchall()
        ]

        # libraries
        meta["libraries"] = [
            {"name": r["name"], "current_version": json.loads(r["current_version"]) if r["current_version"] else None, "compatibility_version": json.loads(r["compatibility_version"]) if r["compatibility_version"] else None}
            for r in cur.execute("SELECT * FROM libraries WHERE binary_id = ?", (binary_id,)).fetchall()
        ]

        # strings
        string_rows = cur.execute("SELECT * FROM strings WHERE binary_id = ?", (binary_id,)).fetchall()
        strings = {
            "static": {"ascii": [], "utf16": []},
            "advanced": {"stack": [], "tight": []},
            "obfuscated": {"decode": []},
        }
        category_map = {
            "ascii": strings["static"]["ascii"],
            "utf16": strings["static"]["utf16"],
            "stack": strings["advanced"]["stack"],
            "tight": strings["advanced"]["tight"],
            "decode": strings["obfuscated"]["decode"],
        }
        for r in string_rows:
            if r["category"] in category_map:
                category_map[r["category"]].append(r["value"])
        # convert empty lists to None to match original format
        for group in strings.values():
            for key in group:
                if not group[key]:
                    group[key] = None
        meta["strings"] = strings

        # functions + decompiled
        func_rows = cur.execute("SELECT * FROM functions WHERE binary_id = ?", (binary_id,)).fetchall()
        functions = [
            {"name": r["name"], "address": r["address"], "size": r["size"]}
            for r in func_rows
        ]
        decompiled = {}
        for r in func_rows:
            if r["decompiled"]:
                decompiled[r["address"]] = r["decompiled"]

        # call graph
        cg_nodes_rows = cur.execute("SELECT * FROM call_graph_nodes WHERE binary_id = ?", (binary_id,)).fetchall()
        cg_edges_rows = cur.execute("SELECT * FROM call_graph_edges WHERE binary_id = ?", (binary_id,)).fetchall()
        call_graph = {
            "nodes": {r["address"]: {"name": r["name"], "type": r["type"]} for r in cg_nodes_rows},
            "edges": [{"src": r["src"], "dst": r["dst"]} for r in cg_edges_rows],
        }

        # cfgs
        cfg_node_rows = cur.execute("SELECT * FROM cfg_nodes WHERE binary_id = ?", (binary_id,)).fetchall()
        cfg_edge_rows = cur.execute("SELECT * FROM cfg_edges WHERE binary_id = ?", (binary_id,)).fetchall()
        cfgs = {}
        for r in cfg_node_rows:
            addr = r["function_addr"]
            if addr not in cfgs:
                cfgs[addr] = {"nodes": [], "edges": []}
            cfgs[addr]["nodes"].append({"id": r["block_id"], "start": r["start_addr"], "end": r["end_addr"]})
        for r in cfg_edge_rows:
            addr = r["function_addr"]
            if addr not in cfgs:
                cfgs[addr] = {"nodes": [], "edges": []}
            cfgs[addr]["edges"].append({"src": r["src"], "dst": r["dst"], "type": r["type"]})

        return {
            "name": meta["name"],
            "programInfo": {"meta": meta},
            "functions": functions,
            "decompiled": decompiled,
            "callGraph": call_graph,
            "cfgs": cfgs,
        }

    def save_graph(self, graph):
        pass
