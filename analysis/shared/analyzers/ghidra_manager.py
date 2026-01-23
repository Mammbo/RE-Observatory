import os, jpype, pyghidra
from pathlib import Path



class GhidraManager:
    def __init__(self, install_dir=None):
        resolved_install = install_dir or os.environ.get("GHIDRA_INSTALL_DIR")
        if not resolved_install:
            raise RuntimeError("GHIDRA_INSTALL_DIR not set")

        install_path = Path(resolved_install).expanduser()
        if not install_path.is_dir():
            raise RuntimeError(f"GHIDRA_INSTALL_DIR is invalid: {install_path}")

        self.install_dir = str(install_path)
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
            "edges": [ {src, dst, type} ]  # includes edges to external blocks
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
        TaskMonitor = jpype.JClass("ghidra.util.task.TaskMonitor")

        monitor = TaskMonitor.DUMMY
        bbm = BasicBlockModel(self.current_program)

        # Get ALL blocks within the function's body
        block_iter = bbm.getCodeBlocksContaining(func.getBody(), monitor)

        nodes = {}
        edges = []

        # Single pass: collect nodes and edges together
        while block_iter.hasNext():
            block = block_iter.next()
            start = block.getFirstStartAddress().getOffset()
            end = block.getMaxAddress().getOffset()
            node_id = hex(start)

            nodes[node_id] = {
                "id": node_id,
                "start": hex(start),
                "end": hex(end)
            }

            dests = block.getDestinations(monitor)
            while dests.hasNext():
                ref = dests.next()
                dst_block = ref.getDestinationBlock()
                if dst_block is None:
                    continue

                edges.append({
                    "src": node_id,
                    "dst": hex(dst_block.getFirstStartAddress().getOffset()),
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