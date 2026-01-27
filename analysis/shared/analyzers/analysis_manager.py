# extension of ghidra_manager that uses programs or replaces functionality ghidra can do but at a much faster rate.
import lief
from pathlib import Path
import floss.strings
import floss.main
import floss.identify
class AnalysisManager: 
    def __init__(self, filepath):
            self.filepath = Path(filepath)
            if not self.filepath.exists():
                raise FileNotFoundError(f"Binary not found: {filepath}")
            self.binary = None
            self._parse()

    def _parse(self):
        """Parse the binary. For Mach-O Fat binaries, prefer ARM64 slice."""
        try:
            self.binary = lief.parse(str(self.filepath))
            if self.binary is None:
                raise ValueError(f"Failed to parse binary: {self.filepath}")

            # For Mach-O files, check if Fat binary and get ARM64 slice
            # Keep reference to FatBinary to prevent slice invalidation
            self._fat_binary = None
            if isinstance(self.binary, lief.MachO.Binary):
                self._fat_binary = lief.MachO.parse(str(self.filepath))
                if isinstance(self._fat_binary, lief.MachO.FatBinary):
                    # Find ARM64 slice index
                    arm64_idx = 0
                    for i, binary in enumerate(self._fat_binary):
                        cpu_type_name = getattr(binary.header.cpu_type, "name", "")
                        if "ARM64" in cpu_type_name:
                            arm64_idx = i
                            break
                    # Use at() method to get a stable reference
                    self.binary = self._fat_binary.at(arm64_idx)
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

        # FLOSS advanced modes only supported for PE; skip on other formats to avoid hangs
        if self.binary.format.name == "PE":
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
                "decode": _decode_strings if _decode_strings else None
            }
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
             
             # LIEF returns different types per format (sometimes plain strings).
             if isinstance(lib, str):
                  libs.append({
                       "name": lib,
                       "current_version": None,
                       "compatibility_version": None,
                  })
                  continue

             libs.append({
                  "name": getattr(lib, "name", str(lib)),
                  "current_version": getattr(lib, "current_version", None),
                  "compatibility_version": getattr(lib, "compatibility_version", None),
             })
        return libs


    # -----------------------------
    # Program Context
    # -----------------------------

    def get_security_features(self):
            """
            Collect security mitigations inferred from LIEF metadata.
            Covers common hardening signals across ELF/PE/Mach-O.
            """
            if self.binary is None:
                return None

            fmt = self.binary.format.name

            # Base flags exposed uniformly by LIEF
            pie = getattr(self.binary, "is_pie", None)
            nx = getattr(self.binary, "has_nx", None)

            # ASLR: PIE implies ASLR for ELF/Mach-O; PE uses DYNAMIC_BASE
            aslr = None
            if fmt in {"ELF", "MACHO"}:
                aslr = pie
            elif fmt == "PE":
                try:
                    dc = getattr(self.binary.optional_header, "dll_characteristics", 0)
                    aslr = bool(dc & int(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE))
                except Exception:
                    aslr = None

            # RELRO (ELF only) - detect via GNU_RELRO segment + BIND_NOW
            relro_state = None
            if fmt == "ELF":
                try:
                    has_relro_seg = any(
                        getattr(seg.type, "name", "") == "GNU_RELRO"
                        for seg in self.binary.segments
                    )
                    # Check for BIND_NOW in dynamic entries
                    bind_now = False
                    for entry in self.binary.dynamic_entries:
                        tag_name = getattr(entry.tag, "name", "")
                        if tag_name == "BIND_NOW":
                            bind_now = True
                            break
                        if tag_name in ("FLAGS", "FLAGS_1") and hasattr(entry, "flags"):
                            for flag in entry.flags:
                                fname = getattr(flag, "name", "")
                                if fname in ("BIND_NOW", "NOW"):
                                    bind_now = True
                                    break

                    if has_relro_seg:
                        relro_state = "full" if bind_now else "partial"
                    else:
                        relro_state = "none"
                except Exception:
                    relro_state = None

            # Stack canary heuristics: look for common guard symbols in imports AND symbol table
            stack_canary = False
            try:
                stack_guard_syms = {
                    # Linux/ELF
                    "__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local",
                    # macOS/Mach-O (triple underscore)
                    "___stack_chk_fail", "___stack_chk_guard",
                    # Windows/PE
                    "__security_check_cookie", "__report_gsfailure", "_security_cookie",
                    "__security_cookie", "___security_cookie",
                }
                # Check imported symbols
                imported_names = {
                    func.name for func in self.binary.imported_functions
                    if getattr(func, "name", None)
                }
                if imported_names.intersection(stack_guard_syms):
                    stack_canary = True
                # Also check full symbol table (catches statically linked canaries)
                if not stack_canary and hasattr(self.binary, "symbols"):
                    for sym in self.binary.symbols:
                        sym_name = getattr(sym, "name", "")
                        if sym_name in stack_guard_syms:
                            stack_canary = True
                            break
            except Exception:
                stack_canary = None

            # Section W+X scan (PE/ELF only; Mach-O uses segment-level checks in macho_features)
            rwx_sections = None
            if fmt in {"PE", "ELF"}:
                rwx_sections = []
                try:
                    for sec in self.binary.sections:
                        is_exec = False
                        is_write = False
                        if fmt == "PE":
                            flags = getattr(sec, "characteristics", 0)
                            is_exec = bool(flags & int(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE))
                            is_write = bool(flags & int(lief.PE.Section.CHARACTERISTICS.MEM_WRITE))
                        elif fmt == "ELF":
                            flags = getattr(sec, "flags", 0)
                            is_exec = bool(flags & int(lief.ELF.Section.FLAGS.EXECINSTR))
                            is_write = bool(flags & int(lief.ELF.Section.FLAGS.WRITE))
                        if is_exec and is_write:
                            rwx_sections.append(getattr(sec, "name", ""))
                except Exception:
                    rwx_sections = None

            # Platform-specific features
            pe_features = self._get_pe_security_features() if fmt == "PE" else None
            elf_features = self._get_elf_security_features() if fmt == "ELF" else None
            macho_features = self._get_macho_security_features() if fmt == "MACHO" else None

            return {
                "format": fmt,
                "pie": pie,
                "nx": nx,
                "aslr": aslr,
                "relro": relro_state,
                "stack_canary": stack_canary,
                "rwx_sections": rwx_sections,
                "pe": pe_features,
                "elf": elf_features,
                "macho": macho_features,
            }

    def _get_pe_security_features(self):
        """Extract PE-specific security features."""
        features = {}
        try:
            dc = getattr(self.binary.optional_header, "dll_characteristics", 0)
            DLL_CHAR = lief.PE.OptionalHeader.DLL_CHARACTERISTICS

            features = {
                # DEP/NX compatibility
                "dep": bool(dc & int(DLL_CHAR.NX_COMPAT)),
                # High entropy 64-bit ASLR
                "high_entropy_va": bool(dc & int(DLL_CHAR.HIGH_ENTROPY_VA)),
                # Control Flow Guard
                "control_flow_guard": bool(dc & int(DLL_CHAR.GUARD_CF)),
                # SEH protections
                "no_seh": bool(dc & int(DLL_CHAR.NO_SEH)),
                # Mandatory code signing
                "force_integrity": bool(dc & int(DLL_CHAR.FORCE_INTEGRITY)),
                # Isolation (manifest)
                "isolation": not bool(dc & int(DLL_CHAR.NO_ISOLATION)),
                # AppContainer sandbox
                "appcontainer": bool(dc & int(DLL_CHAR.APPCONTAINER)),
                # Terminal Server aware
                "terminal_server_aware": bool(dc & int(DLL_CHAR.TERMINAL_SERVER_AWARE)),
            }
        except Exception:
            pass

        # SafeSEH from Load Configuration
        try:
            load_config = self.binary.load_configuration
            if load_config is not None:
                se_count = getattr(load_config, "se_handler_count", None)
                features["safe_seh"] = se_count is not None and se_count > 0

                # Security cookie presence
                sec_cookie = getattr(load_config, "security_cookie", 0)
                features["security_cookie"] = sec_cookie != 0

                # XFG (eXtended Flow Guard)
                xfg_check = getattr(load_config, "guard_xfg_check_function_pointer", 0)
                xfg_dispatch = getattr(load_config, "guard_xfg_dispatch_function_pointer", 0)
                features["xfg"] = xfg_check != 0 or xfg_dispatch != 0

                # RF Guard (Return Flow Guard)
                rf_failure = getattr(load_config, "guard_rf_failure_routine", 0)
                features["rf_guard"] = rf_failure != 0
        except Exception:
            pass

        # Authenticode signature
        try:
            features["signed"] = self.binary.has_signatures
            if features["signed"]:
                # Verify signature validity
                verify_result = self.binary.verify_signature()
                features["signature_valid"] = verify_result == lief.PE.Signature.VERIFICATION_FLAGS.OK
        except Exception:
            features["signed"] = None
            features["signature_valid"] = None

        return features if features else None

    def _get_elf_security_features(self):
        """Extract ELF-specific security features."""
        features = {}

        # Intel CET features from GNU properties
        ibt = False
        shstk = False
        try:
            for prop in getattr(self.binary, "gnu_properties", []):
                ptype = getattr(prop, "type", None)
                pname = getattr(ptype, "name", "")
                if "X86_FEATURE_1_IBT" in pname:
                    ibt = True
                if "X86_FEATURE_1_SHSTK" in pname:
                    shstk = True
        except Exception:
            pass
        features["ibt"] = ibt
        features["shadow_stack"] = shstk

        # BIND_NOW (immediate binding for full RELRO)
        bind_now = False
        try:
            for entry in self.binary.dynamic_entries:
                tag_name = getattr(entry.tag, "name", "")
                if tag_name in ("BIND_NOW", "FLAGS", "FLAGS_1"):
                    if tag_name == "BIND_NOW":
                        bind_now = True
                    elif hasattr(entry, "flags"):
                        # Check FLAGS or FLAGS_1 for BIND_NOW/NOW
                        for flag in entry.flags:
                            fname = getattr(flag, "name", "")
                            if fname in ("BIND_NOW", "NOW"):
                                bind_now = True
                                break
        except Exception:
            pass
        features["bind_now"] = bind_now

        # RUNPATH / RPATH (can indicate insecure library loading)
        runpath = None
        rpath = None
        try:
            for entry in self.binary.dynamic_entries:
                tag_name = getattr(entry.tag, "name", "")
                if tag_name == "RUNPATH":
                    runpath = getattr(entry, "runpath", None) or getattr(entry, "value", None)
                elif tag_name == "RPATH":
                    rpath = getattr(entry, "rpath", None) or getattr(entry, "value", None)
        except Exception:
            pass
        features["runpath"] = runpath
        features["rpath"] = rpath

        # Executable stack (via PT_GNU_STACK segment)
        exec_stack = None
        try:
            for seg in self.binary.segments:
                seg_type = getattr(seg.type, "name", "")
                if seg_type == "GNU_STACK":
                    # Check if executable flag is set
                    exec_stack = lief.ELF.Segment.FLAGS.X in seg.flags
                    break
        except Exception:
            pass
        features["executable_stack"] = exec_stack

        # Fortify Source (look for glibc *_chk function imports)
        fortify = False
        fortify_funcs = []
        # Known glibc fortify-source protected functions
        fortify_suffixes = {
            "__printf_chk", "__fprintf_chk", "__sprintf_chk", "__snprintf_chk",
            "__vprintf_chk", "__vfprintf_chk", "__vsprintf_chk", "__vsnprintf_chk",
            "__memcpy_chk", "__memmove_chk", "__memset_chk", "__strcpy_chk",
            "__strncpy_chk", "__strcat_chk", "__strncat_chk", "__gets_chk",
            "__fgets_chk", "__read_chk", "__pread_chk", "__recv_chk",
            "__recvfrom_chk", "__realpath_chk", "__wcsncpy_chk", "__wcscpy_chk",
            "__wmemcpy_chk", "__wmemmove_chk", "__wmemset_chk",
            "__longjmp_chk", "__fdelt_chk", "__poll_chk", "__ppoll_chk",
        }
        try:
            for func in self.binary.imported_functions:
                fname = getattr(func, "name", "")
                if fname in fortify_suffixes:
                    fortify = True
                    fortify_funcs.append(fname)
        except Exception:
            pass
        features["fortify_source"] = fortify
        features["fortify_functions"] = fortify_funcs if fortify_funcs else None

        return features if features else None

    def _get_macho_security_features(self):
        """Extract Mach-O specific security features."""
        features = {}

        # Header flags
        try:
            header = self.binary.header
            FLAGS = lief.MachO.Header.FLAGS

            # Check each security-relevant flag
            features["pie"] = header.has(FLAGS.PIE)
            features["no_heap_execution"] = header.has(FLAGS.NO_HEAP_EXECUTION)
            features["allow_stack_execution"] = header.has(FLAGS.ALLOW_STACK_EXECUTION)

            # Additional useful flags
            features["binds_to_weak"] = header.has(FLAGS.BINDS_TO_WEAK)
            features["root_safe"] = header.has(FLAGS.ROOT_SAFE)
            features["setuid_safe"] = header.has(FLAGS.SETUID_SAFE)
            features["app_extension_safe"] = header.has(FLAGS.APP_EXTENSION_SAFE)
        except Exception:
            pass

        # Code signature
        try:
            features["code_signed"] = self.binary.has_code_signature
            if features["code_signed"]:
                code_sig = self.binary.code_signature
                features["code_signature_size"] = getattr(code_sig, "data_size", None)
        except Exception:
            features["code_signed"] = None

        # Check for __RESTRICT segment (library injection protection)
        restrict_segment = False
        try:
            for seg in self.binary.segments:
                seg_name = getattr(seg, "name", "")
                if seg_name == "__RESTRICT":
                    restrict_segment = True
                    break
        except Exception:
            pass
        features["restrict_segment"] = restrict_segment

        # Check for encrypted binary (common in iOS)
        try:
            encryption_info = getattr(self.binary, "encryption_info", None)
            if encryption_info is not None:
                features["encrypted"] = getattr(encryption_info, "crypt_id", 0) != 0
            else:
                features["encrypted"] = False
        except Exception:
            features["encrypted"] = None

        # RWX segments scan
        rwx_segments = []
        try:
            for seg in self.binary.segments:
                init_prot = getattr(seg, "init_protection", 0)
                max_prot = getattr(seg, "max_protection", 0)
                # Check for RWX in either initial or max protection
                rwx = 0x7  # READ | WRITE | EXECUTE
                if (init_prot & rwx) == rwx or (max_prot & rwx) == rwx:
                    rwx_segments.append(getattr(seg, "name", ""))
        except Exception:
            pass
        features["rwx_segments"] = rwx_segments if rwx_segments else None

        # ARM64e PAC (Pointer Authentication) - check CPU subtype
        try:
            cpu_subtype = getattr(self.binary.header, "cpu_subtype", 0)
            # ARM64E subtype is 2 (0x80000002 with ABI flag)
            features["arm64e_pac"] = (cpu_subtype & 0xFF) == 2
        except Exception:
            features["arm64e_pac"] = None

        return features if features else None

    def get_program_info(self):
            """
            Get comprehensive program metadata.

            Returns:
                dict with program name, path, format, compiler, etc.
            """
            if self.binary is None:
                return None

            header = getattr(self.binary, "header", None)
            if header is None and hasattr(self.binary, "concrete"):
                header = getattr(self.binary.concrete, "header", None)

            # Resolve architecture across LIEF formats (ELF/PE/Mach-O)
            architecture = None
            if header is not None:
                for attr in ("cpu_type", "machine_type", "machine", "arch"):
                    value = getattr(header, attr, None)
                    if value is not None:
                        architecture = getattr(value, "name", str(value))
                        break
            if architecture is None:
                value = getattr(self.binary, "architecture", None)
                if value is not None:
                    architecture = getattr(value, "name", str(value))

            # Resolve bits across formats
            bits = None
            if header is not None:
                for attr in ("is_64bit", "is_64", "bits"):
                    value = getattr(header, attr, None)
                    if isinstance(value, bool):
                        bits = 64 if value else 32
                        break
                    if isinstance(value, int):
                        bits = value
                        break
            if bits is None:
                value = getattr(self.binary, "is_64", None)
                if isinstance(value, bool):
                    bits = 64 if value else 32

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
            security = self.get_security_features()

            return { 
                "meta": 
                    { 
                        "filepath": str(self.filepath),
                        "name": self.filepath.stem,
                        "format": self.binary.format.name,
                        "image_base": hex(getattr(self.binary, "imagebase", 0)),
                        "entrypoint": hex(getattr(self.binary, "entrypoint", 0)),
                        "architecture": architecture,
                        "bits": bits, 
                        "encryption_info": getattr(self.binary, "encryption_info", None),
                        "min_address": hex(min_addr) if min_addr != float('inf') else "0x0",
                        "max_address": hex(max_addr),
                        "virtual_size": hex(self.binary.virtual_size),  # Binary.virtual_size -> int
                        "original_size": self.binary.original_size, 
                        
                        "imports": imports,
                        "exports": exports,
                        "libraries": libraries,

                        "strings": strings,
                        "security": security,
                    }
            }
