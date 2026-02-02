const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const  { app } = require('electron');


class PythonManager { 
    constructor() { 
        this.process = null;
        this.isRunning = false;
    }

    /** 
     * Get the path to the Python Script 
     * Handles both dev and packaged app scenarios
     */

    getScriptPath() {
        if (app.isPackaged) {
            return path.join(process.resourcesPath, 'analysis', 'websocket_server', 'server.py');
        }

        return path.join(__dirname, '..', 'analysis', 'websocket_server', 'server.py');
    }

    getPythonPath() {
        // Allow override via environment variable
        if (process.env.PYTHON_PATH) {
            return process.env.PYTHON_PATH;
        }

        // Production: venv bundled in app resources
        if (app.isPackaged) {
            const isWindows = process.platform === 'win32';
            return path.join(
                process.resourcesPath,
                'venv',
                isWindows ? 'Scripts' : 'bin',
                isWindows ? 'python.exe' : 'python'
            );
        }

        // Development: venv in project root
        return path.join(__dirname, '..', 'venv', 'bin', 'python');
    }

    getGhidraPath() {
        // Allow override via environment variable
        if (process.env.GHIDRA_INSTALL_DIR) {
            return process.env.GHIDRA_INSTALL_DIR;
        }

        // Packaged app: bundled in resources
        if (app.isPackaged) {
            return path.join(process.resourcesPath, 'ghidra_12.0.2_PUBLIC');
        }

        // Development: vendor directory in project root
        return path.join(__dirname, '..', 'vendor', 'ghidra_12.0.2_PUBLIC');
    }

    /**
     * Spawn the Python server process
     */

    async start() {
        if (this.isRunning) {
            console.log("Python process is already running");
            return;
        }

        const pythonPath = this.getPythonPath();
        const scriptPath = this.getScriptPath();
        const ghidraInstall = this.getGhidraPath();

        if (!fs.existsSync(ghidraInstall)) {
            throw new Error(`Ghidra not found at: ${ghidraInstall}. Place Ghidra in vendor/ghidra_12.0.2_PUBLIC or set GHIDRA_INSTALL_DIR.`);
        }

        console.log(`Starting Python server: ${pythonPath}:${scriptPath}`);

        this.process = spawn(pythonPath, [scriptPath], {
            env: {
                ...process.env,
                GHIDRA_INSTALL_DIR: ghidraInstall,
                PYTHONUNBUFFERED: '1'  // Disable output buffering
            },
            stdio: ['pipe', 'pipe', 'pipe']
        });

        this.isRunning = true;
        

        this.process.stdout.on('data', (data) => { 
            console.log(`[Python]: ${data.toString().trim()}`);
        });

        
        // Handle stderr
        this.process.stderr.on('data', (data) => {
            console.error(`[Python Error]: ${data.toString().trim()}`);
        });

        // Handle process exit
        this.process.on('close', (code) => {
            console.log(`Python process exited with code ${code}`);
            this.isRunning = false;
            this.process = null;
        });

        // Handle spawn errors
        this.process.on('error', (err) => {
            console.error('Failed to start Python process:', err);
            this.isRunning = false;
        });

        // Wait for server to be ready (look for startup message)
        return this.waitForReady();
    }

    /**
     * Wait for server to print ready message
     */
    waitForReady(timeout = 30000) {
        return new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                reject(new Error('Python server startup timeout'));
            }, timeout);

            const checkReady = (data) => {
                if (data.toString().includes('WebSocket server started')) {
                    clearTimeout(timeoutId);
                    this.process.stdout.off('data', checkReady);
                    resolve();
                }
            };

            this.process.stdout.on('data', checkReady);
        });
    }

    /**
     * Stop the Python server
     */
    stop() {
        if (this.process) {
            console.log('Stopping Python server...');

            // Send SIGTERM for graceful shutdown
            this.process.kill('SIGTERM');

            // Force kill after timeout
            setTimeout(() => {
                if (this.process) {
                    this.process.kill('SIGKILL');
                }
            }, 5000);
        }
    }

    /**
     * Restart the Python server
     */
    async restart() {
        this.stop();
        // Wait for process to fully stop
        await new Promise(resolve => setTimeout(resolve, 1000));
        return this.start();
    }
}

module.exports = new PythonManager();
