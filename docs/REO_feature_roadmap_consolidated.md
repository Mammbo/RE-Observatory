# Reverse Engineering Observatory (REO) — Feature Roadmap + Fast Pre‑Analysis Layer

This document consolidates the original **REO feature roadmap** and expands it with a **Pre‑Analysis (Ultra‑Fast Triage) layer** designed to make the app feel instant and support multiple versions of the program.

It keeps the same v1/v2/v3/v4 scope discipline: **ship a credible, end‑to‑end triage + visualization platform first**, then expand power later.  
(Original roadmap source: `reverse_engineering_observatory_feature_roadmap.md`.) fileciteturn0file0

---

## Project Positioning (Important Context)

**Reverse Engineering Observatory (REO)** is a:

> Local, headless, Ghidra‑powered binary triage and visualization platform with persistent analysis, CFG‑first exploration, and automated malware capability detection.

REO focuses on:
- Base‑level triage
- Program structure understanding
- Automation
- Persistence & reuse
- Visualization (graphs over text)

REO explicitly does **not** try to:
- Replace decompilers
- Compete with interactive RE IDEs
- Perform deep symbolic execution

---

## Version Strategy (How to Think About “Multiple Versions”)

### Core principle
**Fast triage first, deep analysis later.**

### Why
- Recruiters/interviewers judge **clarity + scope + end‑to‑end design**, not “who has the best decompiler.”
- A responsive UI with fast signal is more demoable than a slow “analysis-only” tool.

### Layered pipeline model
You ship REO as a pipeline with layers:

1) **Pre‑Analysis (milliseconds → seconds):** instant UI population + early warnings  
2) **Deep Analysis (minutes):** Ghidra + CFG extraction + CAPA  
3) **Persistence:** store everything so reopens are instant  
4) **Future power:** diffing, annotations, dataflow, emulation, collaboration

---

# 0️⃣ Pre‑Analysis Layer (Ultra‑Fast Triage Tools)

These tools run in **milliseconds to seconds**, not minutes.  
They exist to provide **instant, high‑signal triage data** before (or even without) invoking Ghidra.

**Design principle:**  
> Populate the UI immediately with actionable context while heavyweight analysis runs (or is deferred).

This layer powers:
- Instant sidebar population
- Early warnings (packed / obfuscated / misleading binaries)
- Smarter decisions about whether full analysis is worth the cost

---

## 🔥 Category: Fast, Shallow, High‑Signal  
**Ideal for sidebar + upload‑time execution**

### 🟢 LIEF — Binary Structure & Metadata

**Speed:** ⚡⚡⚡ (milliseconds)

**Extracts:**
- Binary format (PE / ELF / Mach-O)
- Architecture & endianness
- Entry point
- Sections & segments
- Imports / exports
- Headers & load commands
- Linked dependencies

**Why it matters:**
- Zero analysis — pure parsing
- Python‑native (no IPC/subprocess cost)
- Deterministic and safe
- Perfect for instant UI hydration

**UI usage:**
- Binary Overview panel
- Header + section tables
- Import/export previews
- Architecture badge (x86/x64/ARM)

**Verdict:**
- ✅ **Mandatory in v1**
- Run immediately on upload
- Should complete before the UI finishes loading

---

### 🟢 Detect It Easy (DIE) — Packing & Compiler Signals

**Speed:** ⚡⚡⚡

**Extracts:**
- Packer detection (UPX, VMProtect, Themida, etc.)
- Compiler fingerprints
- Entropy measurements
- Language hints

**Why it matters:**
- Warns you if Ghidra output will be misleading
- Tells you upfront if unpacking is required
- Prevents wasted analysis time

**UI usage:**
- “Triage Signals” panel
- Packed/suspicious flags
- Entropy warning badges

**Verdict:**
- ✅ **Strong v1 candidate**
- Especially valuable for malware triage

---

### 🟢 strings — Human‑Readable Clues

**Speed:** ⚡⚡⚡⚡ (near‑instant)

**Extracts:**
- ASCII strings
- UTF‑16/Unicode strings
- URLs, file paths
- Registry keys
- API names
- Embedded error messages

**Why it matters:**
- Immediate human context
- Often more valuable early than CFGs
- Reveals intent before structure

**UI usage:**
- Strings explorer
- URL/path filtering
- Keyword search

**Verdict:**
- ✅ **Mandatory v1**
- Always run instantly
- Zero downside

---

### 🟢 YARA — Signature Classification

**Speed:** ⚡⚡

**Extracts:**
- Malware family hits
- Packer signatures
- Known byte patterns
- Heuristic indicators

**Why it matters:**
- Early classification signal
- Complements CAPA’s semantic analysis
- Helps prioritize binaries

**UI usage:**
- “Threat Signals” panel
- Rule hit list
- Confidence indicators

**Verdict:**
- 🟡 **Optional v1**
- ✅ **Recommended v2**
- Requires curated rule management

---

### 🟢 radare2 (Limited / Shallow Mode)

**Speed:** ⚡⚡

**Extracts quickly:**
- Entry points
- Symbols (if present)
- Basic function listing (when not packed)
- Light structural hints

**Why it matters:**
- Faster than Ghidra for shallow structure
- CLI‑friendly
- Useful fallback when Ghidra is deferred

**Constraints:**
- Do **not** overlap deeply with Ghidra
- Avoid full analysis (`aaa`) in v1

**UI usage:**
- Optional quick function preview
- Structure hints while Ghidra runs

**Verdict:**
- 🟡 **Optional v2**
- Not required for a strong v1

---

## Pre‑Analysis Pipeline (v1)

```
Upload →
  LIEF
  DIE
  strings
  (optional YARA)
→ Instant UI population
→ Ghidra queued in background
```

**Key rule:** These tools **must never block the UI**.

---

## Version Planning Summary (Pre‑Analysis)

| Tool | v1 | v2 | v3 |
|---|---|---|---|
| LIEF | ✅ | ✅ | ✅ |
| strings | ✅ | ✅ | ✅ |
| Detect It Easy | ✅ | ✅ | ✅ |
| YARA | 🟡 | ✅ | ✅ |
| radare2 | ❌ | 🟡 | ❌ |

---

# ✅ v1 — FEATURES TO SHIP (Jan 15)

These features correspond directly to **Phase 1 architecture**, **kanban tasks**, and what is realistically achievable as a solo dev.

---

## 1. Core Ghidra Project Manager (MANDATORY)

**Kanban reference:**
- `ghidra_manager.py`
- analysis pipeline tasks
- `phase1-architecture.md`

### What ships in v1

- Headless Ghidra startup via PyGhidra
- Safe JVM lifecycle management
- Create / open Ghidra projects
- Import binaries into a project
- Run full auto-analysis
- Controlled access to `Program` objects (context managers)

### Extracted artifacts

- Binary metadata (architecture, endian, compiler guess)
- Entry point
- Function list (name, address, size)
- Strings (basic static strings)
- Imports / exports

### Why this matters

This is the **engine** of the entire system. Without this, nothing else is meaningful. It demonstrates:
- Headless automation
- Safe resource management
- Program analysis orchestration

---

## 2. Control Flow Graph (CFG) Extraction (MANDATORY)

**Kanban reference:**
- cfg extraction tasks
- `phase1-architecture.md` (graph model)

### What ships in v1

- Function-level CFG extraction
- Nodes = basic blocks
- Edges = conditional / unconditional flow
- Instruction listing per basic block

### Data model

- CFG serialized as JSON
- Stored per function
- Address-stable identifiers

### Why this matters

CFGs are the **structural backbone** of program understanding. Making them first-class objects (instead of side views) is one of REO’s main differentiators.

---

## 3. Graph‑First Canvas UI (MANDATORY)

**Kanban reference:**
- frontend canvas tasks
- inspector panel tasks

### What ships in v1

- Interactive CFG canvas
- Zoom / pan
- Click function → load its CFG
- Click node → view instructions

### Inspector panels

- Assembly view (read-only)
- Decompiled text (optional if stable)
- Metadata panel (addresses, size)

### Explicit non‑goals for v1

- No global program CFG
- No advanced layout algorithms
- No dataflow overlays

### Why this matters

This is what makes the tool **feel different** from Ghidra/IDA. It also makes the project visually demoable.

---

## 4. Persistent Local Storage (MANDATORY)

**Kanban reference:**
- database / sqlite tasks
- `phase1-architecture.md`

### What ships in v1

- SQLite database
- Binary registry (hash, filename, timestamps)
- Stored analysis artifacts:
  - functions
  - CFGs
  - strings
  - imports

### Behavior

- Reopen project without re-analysis
- Deterministic results per binary

### Why this matters

Persistence turns REO from a **script** into a **platform**. It also enables future diffing and collaboration.

---

## 5. Job‑Based Analysis Backend (Lightweight MPC)

**Kanban reference:**
- job queue tasks
- backend orchestration

### What ships in v1

- Job abstraction:
  - queued
  - running
  - completed
  - failed
- One analysis job at a time
- Progress updates to UI

### Explicit non‑goals

- No distributed workers
- No remote clients
- No auth

### Why this matters

This demonstrates **production-style architecture** and prevents UI blocking. It also sets up a clean path to multi-user later.

---

## 6. CAPA Integration (HIGH ROI)

**Kanban reference:**
- external tools integration tasks

### Tool integrated

- CAPA (Mandiant)

### What ships in v1

- Run CAPA automatically after analysis
- Parse JSON output
- Display detected capabilities
- Show rules and matched locations

### UI

- Dedicated "Capabilities" panel
- Optional highlighting of flagged functions

### Why this matters

CAPA gives **immediate malware triage value** and uses a real industry-standard tool. This dramatically improves resume credibility.

---

## 7. Documentation & Demo (MANDATORY)

### What ships in v1

- README.md
- Architecture diagram
- Feature list
- Demo GIF or screenshots

### Why this matters

Recruiters and interviewers **will not run the code**. They will judge clarity, scope, and intent.

---

# 🚀 FUTURE VERSIONS (POST‑JAN 15)

These features should be explicitly marked as **roadmap**.

---

## v2 — Analysis Power Expansion

### FLOSS Integration

- Tool: FLOSS
- Purpose: Extract obfuscated / runtime strings
- Output: Deobfuscated strings tagged in UI

---

### Binary Diffing (Function‑Level)

- Compare two binaries
- Match functions by structure
- Detect added / removed / changed functions
- Visual diff on CFGs

---

### Annotation System

- User comments
- Function renaming
- Notes stored in DB

---

## v3 — Exploit & Advanced Analysis

### ROP & Exploit Tooling

- ROP gadget browser
- Integration with Ropper / ROPgadget
- Gadget filtering UI

---

### Dataflow & Taint Analysis

- Track input → sink flows
- Vulnerability pattern detection
- CFG + dataflow overlays

---

### Lightweight Emulation

- Integrate Unicorn or angr (limited)
- Decode obfuscated logic
- Emulate small routines

---

## v4 — Collaboration & Scale

### Multi‑User Server Mode

- Central analysis DB
- Multiple clients
- Read/write permissions

---

### Analysis History & Versioning

- Track changes over time
- Rollback analysis states
- Merge annotations across versions

---

# 🔧 External Tools to Integrate (Summary)

| Tool | Version | Purpose |
|---|---|---|
| Ghidra (Headless) | v1 | Core analysis engine |
| CAPA | v1 | Malware capability detection |
| FLOSS | v2 | Obfuscated string recovery |
| YARA | v2 | Signature-based detection |
| Ropper / ROPgadget | v3 | Exploit research |
| angr | v3+ | Symbolic / dataflow analysis |

---

# Final Notes

- v1 is **already impressive** if shipped cleanly
- Avoid scope creep before Jan 15
- Treat future features as explicit roadmap
- A smaller, working system beats an ambitious unfinished one
