# RE-Observatory

Interactive canvas-based reverse engineering tool for visual binary analysis. Drag and explore function nodes on an interactive call graph, view control flow graphs, read decompiled pseudocode, inspect security features, and annotate your findings with Markdown notes. Includes an embedded terminal to run any advanced decompilation or debugging tool you want alongside the visual analysis.

Built with Electron, React, Python, Ghidra, LIEF, FLOSS, x-term and node-pty.

## Demo

https://github.com/user-attachments/assets/2b488a83-a17c-457f-bf5a-e6d1373297dc

## Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Python 3.11](https://www.python.org/)
- [Ghidra 12.0.2](https://ghidra-sre.org/) — place in `vendor/ghidra_12.0.2_PUBLIC` or set the `GHIDRA_INSTALL_DIR` environment variable

## Installation

```bash
git clone https://github.com/Mammbo/RE-Observatory.git
cd RE-Observatory
```

Install Node dependencies:

```bash
npm install
```

Create a Python virtual environment and install Python dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Start the app in development mode:

```bash
npm run dev:electron
```

### Getting Started

1. **Upload a binary** — On the home screen, click **Upload a Binary** to select a file, or **Examine an old Binary** to reload a previous analysis from the database.
2. **Wait for analysis** — The app runs Ghidra analysis automatically. A spinner shows progress in the sidebar.

### Canvas

- The **call graph** displays all functions as draggable nodes connected by call edges. Entry points and highly-connected functions are highlighted and sized larger.
- **Click** a node to highlight it and its connections. **Double-click** to open the function details panel on the right.
- **Right-click** a node and select **Set as root** to re-center the graph from that function.
- Use the **depth slider** (top-right) to filter how deep into the call graph you want to see.
- Toggle between **vertical** and **horizontal** layouts with the layout buttons.

### Function Details (Right Panel)

Double-clicking a function node opens three collapsible sections:

- **Function Info** — address, name, type, entry point status, connection count.
- **Decompiled Code** — Ghidra-generated C-like pseudocode, syntax-highlighted.
- **Control Flow Graph** — interactive mini-graph of basic blocks within the function, color-coded by edge type (fall-through, conditional, unconditional, call).

### Sidebar (Left Panel)

- **Binary Overview** — program metadata, memory layout, and security feature analysis (PIE, NX, ASLR, canaries, and format-specific checks for PE/ELF/Mach-O).
- **Triage Signals** — imports, exports, libraries, and extracted strings (ASCII, UTF-16, stack strings, decoded strings via FLOSS). Includes a fuzzy search bar across all fields.
- **Download JSON** — export the current analysis as a JSON file.

### Annotations

- Click the **+** button on the canvas to create a note node. Notes support Markdown (headers, lists, code blocks, bold, links, etc.).
- Drag edges between notes and function nodes to document relationships.
- Click **Save** (top-right) to persist your notes and edges to the database.

### Terminal

Toggle to the **Terminal** view (top center) for a full embedded shell. Run pwndbg, radare2, objdump, or any CLI tool directly alongside your visual analysis.

## Packaging

Package the app for distribution using [Electron Forge](https://www.electronforge.io/):

```bash
# Package without creating an installer
npm run package

# Build and create platform-specific distributables
npm run make
```

Output goes to the `out/` directory. On macOS this produces a `.zip`, on Linux `.deb`/`.rpm`, and on Windows a Squirrel installer.

## Credits

Thank you to the [Lief Project](https://github.com/lief-project/LIEF), [NSA w/ PyGhidra](https://pypi.org/project/pyghidra/), [the FLARE team w/ FLOSS](https://github.com/mandiant/flare-floss), [radare2 community](https://github.com/radareorg/radare2?tab=readme-ov-file)

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
