# extension of ghidra_manager that uses programs or replaces functionality ghidra can do but at a much faster rate.
import lief
from pathlib import Path
import floss.strings
import floss.main
import floss.identify
import vivisect

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
        _ascii_strings = None
        _utf16_strings = None
        _stack_strings = None
        _tight_strings = None
        _decode_strings = None
        try: 
            with open(self.filepath, 'rb') as f: 
                file_data = f.read()

            _ascii_strings = [s.string for s in floss.strings.extract_ascii_strings(file_data, 4)]
            _utf16_strings = [s.string for s in floss.strings.extract_unicode_strings(file_data, 4)]
        except Exception as e: 
            print(f"Error extracting static strings {e}")

        try:
            vw = floss.main.load_vw(self.filepath, format=None, sigpaths=None)
            selected_functions = floss.main.select_functions(vw, None)
            tight_functions = floss.main.get_functions_with_tightloops(vw, None)

            decoding_features = floss.identify.find_decoding_function_features()
            _decode_strings = [s.string for s in floss.main.decode_strings(file_data, decoding_features, 4)]

            _stack_strings = [s.string for s in floss.main.extract_stackstrings(vw, selected_functions, 4)]
            _tight_strings = [s.string for s in floss.main.extract_tightstrings(vw, tight_functions, 4)]
        except Exception as e: 
            print(f"Error extracting strings {e}")
           

        return {
            "static": {
            "ascii": _ascii_strings if _ascii_strings else None,
            "utf16": _utf16_strings if _utf16_strings else None,
            },
            "advanced": { 
                "stack": _stack_strings if _stack_strings else None,
                "tight": _tight_strings if _tight_strings else None,
            },
            "obfuscated": {
                "decode": _decode_strings if _decode_strings else None}
        }
        
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
        libs = []
        for lib in self.binary.libraries:
             
             libs.append({
                  "name": lib.name,
                  "current_version": lib.current_version,
                  "compatibility_version": lib.compatibility_version,
             })
        return libs


    # -----------------------------
    # Program Context
    # -----------------------------

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

            imports = self.get_imports()
            exports = self.get_exports()
            libraries = self.get_libraries()
            strings = self.get_strings()

            return { 
                "meta": 
                    { 
                        "filepath": str(self.filepath),
                        "name": self.filepath.stem,
                        "format": self.binary.format.name,
                        "image_base": hex(self.binary.imagebase),
                        "entrypoint": hex(self.binary.entrypoint),
                        "architecture": self.binary.concrete.header.cpu_type.name,
                        "bits": 64 if self.binary.concrete.header.is_64bit else 32, 
                        "encryption_info": self.binary.encryption_info,
                        "is_pie": self.binary.is_pie,
                        "has_nx": self.binary.has_nx,
                        "min_address": hex(min_addr) if min_addr != float('inf') else "0x0",
                        "max_address": hex(max_addr),
                        "virtual_size": hex(self.binary.virtual_size),  # Binary.virtual_size -> int
                        "original_size": self.binary.original_size, 
                        
                        "imports": imports,
                        "exports": exports,
                        "libraries": libraries,

                        "strings": strings,
                    }
            }

analyze = AnalysisManager("/usr/bin/find/")
data = analyze.get_program_info()
print(data)