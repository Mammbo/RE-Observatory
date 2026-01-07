import os, jpype, pyghidra, time 
from pathlib import Path



class GhidraManager:
    def __init__(self, install_dir):
        self.install_dir = install_dir
        self.project = None
        self.current_program = None
        self.program_consumer = None
        self.decompiler = None

        if not pyghidra.started():
            pyghidra.start(verbose=False, install_dir=self.install_dir)
            print("PyGhidra Started!")

    # -----------------------------
    # Lifecycle / Runtime
    # -----------------------------

    def open_project(self, project_path, project_name, create=True):
        """
        Open or create a Ghidra project.

        Args:
            project_path: path to the parent directory for the project
            project_name: name of the Ghidra project to open or create
            create: whether to create the project if it doesn't exist (default: True)

        Returns:
            Ghidra Project Object
        """
        project_path = Path(project_path)
        if not project_path.exists():
            raise FileNotFoundError(f"Project path not found: {project_path}")
        self.project = pyghidra.open_project(project_path, project_name, create=True)
        print(f"Project opened: {project_name} at {project_path}")
        return self.project


    def analyze_binary(self, binary_path, analyze=True):
        """
        Load and analyze a binary file in Ghidra without requiring a project.
        Uses program_loader() for project-agnostic binary analysis.

        Args:
            binary_path: path to binary file
            analyze: Whether to run auto-analysis (default: True)

        Returns:
            Ghidra Program Object
        """
        binary_path = Path(binary_path)
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Choose a writable project directory
        project_root = Path.home() / ".ghidra_pyghidra_projects"
        project_root.mkdir(parents=True, exist_ok=True)

        program_cm = pyghidra.open_program(
            binary_path,
            project_location=project_root,
        )

        program = program_cm.__enter__()

        self._program_cm = program_cm
        self.current_program = program.getCurrentProgram()
    
        return self.current_program
    #finish this 
    def close_program(self):
        """
        Close the currently loaded program.
        """
        if self.current_program is not None:
            self._program_cm.__exit__(None, None, None)
            self.current_program = None
            self._program_cm = None
    # -----------------------------
    # Program Context
    # -----------------------------

    def get_program(self):
        """
        Get the currently loaded program.

        Returns:
            Ghidra Program object, or None if no program is loaded
        """
        return self.current_program

    def get_language(self):
        """
        Get the processor language/architecture of the current program.

        Returns:
            dict with language info (processor, endianness, size, variant)
            or None if no program is loaded
        """
        if self.current_program is None:
            return None

        lang = self.current_program.getLanguage()
        return {
            "processor": str(lang.getProcessor()),
            "endianness": str(lang.isBigEndian() and "big" or "little"),
            "size": lang.getLanguageDescription().getSize(),
            "variant": str(lang.getLanguageDescription().getVariant()),
            "language_id": str(lang.getLanguageID()),
        }

    def get_image_base(self):
        """
        Get the image base address of the current program.

        Returns:
            int: the base address as an integer, or None if no program loaded
        """
        if self.current_program is None:
            return None

        return self.current_program.getImageBase().getOffset()

    def get_program_info(self):
        """
        Get comprehensive program metadata.

        Returns:
            dict with program name, path, format, compiler, etc.
        """
        if self.current_program is None:
            return None

        prog = self.current_program
        return {
            "name": prog.getName(),
            "path": str(prog.getExecutablePath()),
            "format": str(prog.getExecutableFormat()),
            "image_base": hex(prog.getImageBase().getOffset()),
            "language": self.get_language(),
            "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
            "min_address": hex(prog.getMinAddress().getOffset()),
            "max_address": hex(prog.getMaxAddress().getOffset()),
            "memory_size": prog.getMemory().getSize(),
        }


    # -----------------------------
    # Address Utilities
    # -----------------------------

    def normalize_address(self, address):
        """
        Convert various address formats to a Ghidra Address object.

        Args:
            address: Can be an int, hex string ("0x401000"), or Ghidra Address

        Returns:
            Ghidra Address object, or None if invalid
        """
        if self.current_program is None:
            return None

        # Already a Ghidra Address object
        Address = jpype.JClass("ghidra.program.model.address.Address")
        if isinstance(address, Address):
            return address

        # Convert to int if string
        if isinstance(address, str):
            address = int(address, 16) if address.startswith("0x") else int(address)

        # Create Address from int using the program's address factory
        addr_factory = self.current_program.getAddressFactory()
        return addr_factory.getDefaultAddressSpace().getAddress(address)

    def address_exists(self, address):
        """
        Check if an address exists in the program's memory.

        Args:
            address: Address to check (int, hex string, or Ghidra Address)

        Returns:
            bool: True if address is valid and exists in memory
        """
        if self.current_program is None:
            return False

        addr = self.normalize_address(address)
        if addr is None:
            return False

        return self.current_program.getMemory().contains(addr)


    # -----------------------------
    # Functions
    # -----------------------------

    def get_functions(self):
        if self.current_program is None:
            return []
        return list(self.current_program.getFunctionManager().getFunctions(True))

    def get_function_by_address(self, function_address):
        if self.current_program is None:
            return None
        addr = self.normalize_address(function_address)
        func_mgr = self.current_program.getFunctionManager()
        return func_mgr.getFunctionAt(addr) or func_mgr.getFunctionContaining(addr)

    def rename_function(self, function_address, new_name):
        func = self.get_function_by_address(function_address)
        if func is None:
            return False
        SourceType = jpype.JClass("ghidra.program.model.symbol.SourceType")
        with pyghidra.transaction(self.current_program):
            func.setName(new_name, SourceType.USER_DEFINED)
        return True


    # -----------------------------
    # Decompiler
    # -----------------------------

    def open_decompiler(self):
        """Open the decompiler interface for the current program."""
        if self.current_program is None:
            return False
        if self.decompiler is not None:
            return True  # already open

        DecompInterface = jpype.JClass("ghidra.app.decompiler.DecompInterface")
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(self.current_program)
        return True

    def decompile_function(self, function_address, timeout=30):
        """
        Decompile a function and return the C code.

        Returns:
            str: Decompiled C code, or None if failed
        """
        if self.decompiler is None:
            self.open_decompiler()

        func = self.get_function_by_address(function_address)
        if func is None:
            return None

        TaskMonitor = jpype.JClass("ghidra.util.task.ConsoleTaskMonitor")
        result = self.decompiler.decompileFunction(func, timeout, TaskMonitor())

        if not result.decompileCompleted():
            print(f"Decompile failed: {result.getErrorMessage()}")
            return None

        return result.getDecompiledFunction().getC()

    def close_decompiler(self):
        """Close the decompiler interface."""
        if self.decompiler is not None:
            self.decompiler.dispose()
            self.decompiler = None


    # -----------------------------
    # Control Flow
    # -----------------------------

    def get_cfg(self, function_address):
        """
        Build a basic-block CFG for a function.

        Returns:
            {
            "nodes": [ {id, start, end} ],
            "edges": [ {src, dst, type} ]
            }
        """
        if self.current_program is None:
            return None

        func = self.get_function_by_address(function_address)
        if func is None:
            return None

        BasicBlockModel = jpype.JClass(
            "ghidra.program.model.block.BasicBlockModel"
        )
        TaskMonitor = jpype.JClass(
            "ghidra.util.task.TaskMonitor"
        )

        program = self.current_program
        monitor = TaskMonitor.DUMMY
        bbm = BasicBlockModel(program)

        blocks = list(
            bbm.getCodeBlocksContaining(func.getEntryPoint(), monitor)
        )

        nodes = {}
        edges = []

        for block in blocks:
            start = block.getFirstStartAddress().getOffset()
            end = block.getMaxAddress().getOffset()
            node_id = hex(start)

            nodes[node_id] = {
                "id": node_id,
                "start": hex(start),
                "end": hex(end)
            }

            nodes_ids = set(nodes.keys())

            dests = block.getDestinations(monitor)
            while dests.hasNext():
                ref = dests.next()
                dst_block = ref.getDestinationBlock()
                if dst_block is None:
                    continue

                dst_start = dst_block.getFirstStartAddress().getOffset()
                if dst_start not in nodes:
                    continue
                edges.append({
                    "src": node_id,
                    "dst": hex(dst_start),
                    "type": ref.getFlowType().toString()
                })

        return {
            "nodes": list(nodes.values()),
            "edges": edges
        }
    def get_call_graph(self):
        """
        Build a function-level call graph.

        Returns:
            {
            "nodes": { addr: name },
            "edges": [ {src, dst} ]
            }
        """
        if self.current_program is None:
            return None

        TaskMonitor = jpype.JClass(
            "ghidra.util.task.TaskMonitor"
        )
        monitor = TaskMonitor.DUMMY

        fm = self.current_program.getFunctionManager()
        funcs = list(fm.getFunctions(True))

        nodes = {}
        edges = []

        for f in funcs:
            src = hex(f.getEntryPoint().getOffset())
            nodes[src] = f.getName()

            called = f.getCalledFunctions(monitor)
            for callee in called:
                dst = hex(callee.getEntryPoint().getOffset())
                edges.append({
                    "src": src,
                    "dst": dst
                })

        return {
            "nodes": nodes,
            "edges": edges
        }


    # -----------------------------
    # Data Extraction
    # -----------------------------

    def get_strings(self, min_length=4):
        if self.current_program is None:
            return []

        strings = []

        # Import lazily (JPype-safe)
        StringDataInstance = jpype.JClass(
            "ghidra.program.model.data.StringDataInstance"
        )

        listing = self.current_program.getListing()
        data_iter = listing.getDefinedData(True)

        while data_iter.hasNext():
            data = data_iter.next()

            sdi = StringDataInstance.getStringDataInstance(data)
            if sdi is None:
                continue

            value = sdi.getStringValue()
            if value is None or len(value) < min_length:
                continue

            strings.append({
                "address": hex(data.getAddress().getOffset()),
                "value": value,
                "length": len(value)
            })

        return strings


    def get_imports(self):
        if self.current_program is None:
            return []

        imports = []
        symbol_table = self.current_program.getSymbolTable()
        external_symbols = symbol_table.getExternalSymbols()

        for sym in external_symbols:
            imports.append({
                "name": sym.getName(),
                "address": hex(sym.getAddress().getOffset()),
                "namespace": str(sym.getParentNamespace())
            })

        return imports

    # -----------------------------
    # Annotation
    # -----------------------------

    def add_comment(self, address, comment):
        """
        Add an end-of-line comment at an address.
        """
        if self.current_program is None:
            return False

        addr = self.normalize_address(address)
        if addr is None:
            return False

        CommentType = jpype.JClass(
            "ghidra.program.model.listing.CodeUnit"
        ).EOL_COMMENT

        listing = self.current_program.getListing()

        with pyghidra.transaction(self.current_program, "Add Comment"):
            listing.setComment(addr, CommentType, comment)

        return True


    def add_function_comment(self, function_address, comment):
        func = self.get_function_by_address(function_address)
        if func is None:
            return False
        with pyghidra.transaction(self.current_program, "Add Function Comment"):
            func.setComment(comment)
        return True


    def add_bookmark(self, address, category, comment, bookmark_type="Note"):
        """
        Add a bookmark at an address.

        Args:
            address: Address to bookmark
            category: Category string for the bookmark
            comment: Comment text for the bookmark
            bookmark_type: Type of bookmark (default: "Note")
        """
        if self.current_program is None:
            return False

        addr = self.normalize_address(address)
        if addr is None:
            return False

        bookmark_mgr = self.current_program.getBookmarkManager()

        with pyghidra.transaction(self.current_program, "Add Bookmark"):
            bookmark_mgr.setBookmark(
                addr,
                bookmark_type,
                category,
                comment
            )

        return True


    def add_function_tag(self, function_address, tag):
        func = self.get_function_by_address(function_address)
        if func is None:
            return False 
        with pyghidra.transaction(self.current_program, "Add Function Tag"):
            func.addTag(tag)
        return True

    def get_function_annotations(self, function_address):
        func = self.get_function_by_address(function_address)
        if func is None:
            return None

        return {
            "name": func.getName(),
            "entry": hex(func.getEntryPoint().getOffset()),
            "comment": func.getComment(),
            "tags": list(func.getTags())
        }
    
    def get_comments_at(self, address):
        if self.current_program is None:
            return {}

        addr = self.normalize_address(address)
        if addr is None:
            return {}

        CodeUnit = jpype.JClass("ghidra.program.model.listing.CodeUnit")
        listing = self.current_program.getListing()

        comments = {}
        for ctype in (
            CodeUnit.EOL_COMMENT,
            CodeUnit.PRE_COMMENT,
            CodeUnit.POST_COMMENT,
            CodeUnit.PLATE_COMMENT,
        ):
            text = listing.getComment(ctype, addr)
            if text:
                comments[ctype] = text

        return comments

    def get_bookmarks_at(self, address):
        if self.current_program is None:
            return []

        addr = self.normalize_address(address)
        if addr is None:
            return []

        bm_mgr = self.current_program.getBookmarkManager()
        bookmarks = bm_mgr.getBookmarks(addr)

        return [
            {
                "address": hex(b.getAddress().getOffset()),
                "type": b.getTypeString(),
                "category": b.getCategory(),
                "comment": b.getComment()
            }
            for b in bookmarks
        ]


