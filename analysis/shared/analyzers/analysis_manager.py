# extension of ghidra_manager that uses programs or replaces functionality ghidra can do but at a much faster rate.
import lief
from pathlib import Path

class AnalysisManager: 
    def __init__(self, filepath):
            self.filepath = Path(filepath)
            if not self.filepath.exists():
                raise FileNotFoundError(f"Binary not found: {filepath}")
            self.binary = None
            self._parse()

    def _parse(self):
        """Parse the binary"""
        try:
            self.binary = lief.parse(str(self.filepath))
            if self.binary is None:
                raise ValueError(f"Failed to parse binary: {self.filepath}")
        except Exception as e:
            raise ValueError(f"Error parsing {self.filepath}: {e}")

    #--------------------------
    # Date Extraction 
    #--------------------------
    # replace this with Floss
    def get_strings(self):
            if self.binary is None:
                return []

            strings = []

            return strings

    # we are replacing get imports with Lief!
    def get_imports(self):
        imports = []

        for func in self.binary.imported_functions:
            imports.append({
                "name": func.name,
                "address": hex(func.address)
            }) 

        return imports
    
    def get_exports(self):
        exports = []
        for func in self.binary.exported_functions:
            exports.append({
                "name": func.name,
                "address": hex(func.address)
            }) 
    
        return exports
         
    def get_libraries(self): 
        return list(self.binary.libraries)


    # -----------------------------
    # Program Context
    # -----------------------------

   
    def get_language(self):
            """
            Get the processor language/architecture of the current program.

            Returns:
                dict with language info (processor, endianness, size, variant)
                or None if no program is loaded
            """
            if self.current_program is None:
                return None

            return {
                "processor": self.binary.header.architecture.name,  # Header.ARCHITECTURES enum
                "endianness": self.binary.header.endianness.name,  # Header.ENDIANNESS enum
                "size": 64 if self.binary.header.is_64 else 32,  # Header.is_64 -> bool
                "object_type": self.binary.header.object_type.name,  # Header.OBJECT_TYPES enum
            }

    def get_image_base(self):
            """
            Get the image base address of the current program.

            Returns:
                int: the base address as an integer, or None if no program loaded
            """
            if self.binary is None:
                return None

            return self.binary.imagebase

    def get_program_info(self):
            """
            Get comprehensive program metadata.

            Returns:
                dict with program name, path, format, compiler, etc.
            """
            if self.binary is None:
                return None

            min_addr = float('inf')
            max_addr = 0
            for section in self.binary.sections:
                # Section.virtual_address -> int
                if section.virtual_address < min_addr:
                    min_addr = section.virtual_address
                # Section.size -> int
                if section.virtual_address + section.size > max_addr:
                    max_addr = section.virtual_address + section.size

          
            return { 
                "meta": 
                    { 
                        "filepath": str(self.filepath),
                        "name": self.filepath.stem,
                        "format": self.binary.format.name,
                        "image_base": hex(self.binary.imagebase),
                        "entrypoint": hex(self.binary.entrypoint),
                        "architecture": self.binary.concrete.header.machine_type,
                        "endianness": self.binary.concrete.header.ELF_DATA,
                        "is_pie": self.binary.is_pie,
                        "has_nx": self.binary.has_nx,
                        "min_address": hex(min_addr) if min_addr != float('inf') else "0x0",
                        "max_address": hex(max_addr),
                        "virtual_size": hex(self.binary.virtual_size),  # Binary.virtual_size -> int
                        "original_size": self.binary.original_size, 
                    }
            }

analyze = AnalysisManager("/usr/bin/ls")
data = analyze.get_program_info()

print(data)