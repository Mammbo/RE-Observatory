const { app, BrowserWindow, ipcMain, dialog, Menu } = require('electron');
const path = require('path');
const pythonManager = require('./python-manager');
const wsClient = require('./websocket-client');
const os = require("os");
const pty = require("node-pty")

// inline if statement
try { 
  var shell = os.platform() === "win32" ? "powershell.exe" : process.env.SHELL;
  console.log(`SHELL: ${shell}`)
} catch { 
  console.log("error")
}

let mainWindow;
let ptyProcess;

const createWindow= () => {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    title: 'RE Observatory',
  });
    // supress native os menu
    Menu.setApplicationMenu(null);

  // In development, load from webpack dev server
  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL('http://localhost:8080');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../build/index.html'));
  }

  // Send initial connection status once window is ready
  mainWindow.webContents.on('did-finish-load', () => {
    mainWindow.webContents.send('ws-status', { connected: wsClient.isConnected });
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // spawn pty and forward output to renderer
  try {
    ptyProcess = pty.spawn(shell, [], {
      name: "xterm-color",
      cols: 80,
      rows: 24,
      cwd: process.env.HOME,
      env: process.env
    });
    console.log('✓ PTY spawned successfully');
  } catch (e) {
    console.error('✗ PTY spawn failed:', e.message);
  }

  ptyProcess.on("data", function(data) {
      mainWindow.webContents.send("terminal.incData", data);
  })
}

//setUp IPC handlers

const setupIPC = () => {
  // File selection dialog
  ipcMain.handle('select-binary', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      filters: [
        { name: 'All Files', extensions: ['*'] }
      ]
    });
    return result.canceled ? null : result.filePaths[0];
  });

  // WebSocket send handlers
  ipcMain.handle('ws-send', async (event, command, data) => {
    wsClient.send(command, data);
    return { sent: true };  // Response comes via events, not here
  });

  ipcMain.on('ws-send-async', (event, command, data) => {
    wsClient.send(command, data)
  });

  // writes data
  ipcMain.on("terminal.toterm", (event, data) => {
    if (ptyProcess) ptyProcess.write(data)
  });

  wsClient.on('message', (message) => { 
    if(mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('ws-message', message)
    }
  });

  const sendStatus = (connected) => { 
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('ws-status', { connected })
    }
  }
  
  wsClient.on('connected', () => sendStatus(true));
  wsClient.on('disconnected', () => sendStatus(false));

  console.log('✓ IPC handlers registered');
};


// App Startup
app.whenReady().then(async () => {
  try{
    await pythonManager.start();
  } 
  catch (e){
    console.error('Python Manger couldnt start: ', {e})
    app.quit();
  }

  try { 
    await wsClient.connect();
    console.log("WebSocket Connected")
  }
  catch (e) { 
    console.error(e);
    app.quit();
  }
    setupIPC();
    createWindow();
    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow();
        }
    });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    pythonManager.stop();
    wsClient.close();
    app.quit();
  }
});


console.log('Electron main process started');