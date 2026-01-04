const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods to renderer process
contextBridge.exposeInMainWorld('electron', {
  // Platform info
  getPlatform: () => ipcRenderer.invoke('get-platform'),

  // File operations
  selectBinary: () => ipcRenderer.invoke('select-binary'),
  saveProject: (data) => ipcRenderer.invoke('save-project', data),
  loadProject: (path) => ipcRenderer.invoke('load-project', path),

  // Analysis operations
  startAnalysis: (binaryPath) => ipcRenderer.invoke('start-analysis', binaryPath),
  startTriage: (binaryPath) => ipcRenderer.invoke('start-triage', binaryPath),
  startDeepAnalysis: (binaryPath) => ipcRenderer.invoke('start-deep-analysis', binaryPath),
  getCFG: (address) => ipcRenderer.invoke('get-cfg', address),

  // Interactive operations
  renameFunction: (address, newName) => ipcRenderer.invoke('rename-function', address, newName),
  addComment: (address, comment) => ipcRenderer.invoke('add-comment', address, comment),
});

console.log('✓ Preload script loaded - IPC bridge ready');