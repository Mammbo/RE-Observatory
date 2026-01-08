const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const pythonManager = require('./python-manager');
const wsClient = require('./websocket-client')

let mainWindow;

const createWindow= () => {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: false,
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

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

//setUp IPC handlers

const setupIPC = () => {
  // set up IPC handlers for websocket!

  ipcMain.handle('ws-send', async (event, command, data) => { 
    return wsClient.request(command, data)
  })

  ipcMain.on('ws-send-async', (event, command, data) => { 
    wsClient.send(command, data)
  });

  wsClient.on('message', (message) => { 
    if(mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('ws-message', message)
    }
  })
  
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