# extension of ghidra_manager that uses programs or replaces functionality ghidra can do but at a much faster rate.
import lief

class AnalysisManager: 
    def __init__(self):
          self.current_program = None

    #--------------------------
    # Date Extraction 
    #--------------------------
    # replace this with Floss
    def get_strings(self):
            if self.current_program is None:
                return []

            strings = []

            return strings

    # we are replacing get imports with Lief!
    def get_imports(self):
            if self.current_program is None:
                return []

            imports = []

            return imports

    # this will also be replaced by LIEF.


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
