const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');

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
  ipcMain.handle('get-platform', async () => {
    return process.platform;
  });

  ipcMain.handle('select-binary', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
      title: 'Select Binary to Analyze',
      filters: [
        { name: 'All Files', extensions: ['*'] },
        { name: 'Executables', extensions: ['exe', 'elf', 'out', 'bin'] },
        { name: 'Libraries', extensions: ['so', 'dll', 'dylib'] }
      ]
    });
    if (result.canceled || result.filePaths.length > 0) {
      return result.filePaths[0];
    }
    return null;
  });

  ipcMain.handle('save-project', async (event, projectData) => {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Save Project',
      defaultPath: 'project.reobs',
      filters: [
        { name: 'RE Observatory Project', extensions: ['reobs'] }
      
    ]});
    if (!result.canceled && result.filePath) {
      // TODO: Save project data to file
      console.log('Saving project to:', result.filePath);
      return { success: true, path: result.filePath };
    }
    return { success: false };
  });

  ipcMain.handle('load-project', async (event, projectPath) => {
    // TODO: Load project from file
    console.log('Loading project from:', projectPath);
    return { success: true, data: {} };
  });

  // Analysis operations
  ipcMain.handle('start-analysis', async (event, binaryPath) => {
    console.log('Starting analysis for:', binaryPath);
    // TODO: Send to Python analysis engine
    return { success: true, message: 'Analysis started' };
  });

  ipcMain.handle('start-triage', async (event, binaryPath) => {
    console.log('Starting quick triage for:', binaryPath);
    // TODO: Trigger triage analysis via Python
    return { success: true };
  });

  ipcMain.handle('start-deep-analysis', async (event, binaryPath) => {
    console.log('Starting deep analysis for:', binaryPath);
    // TODO: Trigger deep analysis via Python
    return { success: true };
  });

  ipcMain.handle('get-cfg', async (event, functionAddress) => {
    console.log('Getting CFG for function:', functionAddress);
    // TODO: Request CFG from Python/Ghidra
    return { success: true, cfg: {} };
  });

  // Interactive operations
  ipcMain.handle('rename-function', async (event, address, newName) => {
    console.log(`Renaming function at ${address} to ${newName}`);
    // TODO: Send rename command to Python/Ghidra
    return { success: true };
  });

  ipcMain.handle('add-comment', async (event, address, comment) => {
    console.log(`Adding comment at ${address}: ${comment}`);
    // TODO: Send comment to Python/Ghidra
    return { success: true };
  });

  console.log('✓ IPC handlers registered');
};


// App Startup
app.whenReady().then(() => {
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
    app.quit();
  }
});


console.log('Electron main process started');