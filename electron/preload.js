 const { contextBridge } = require('electron');

// Expose protected methods to renderer process
contextBridge.exposeInMainWorld('electron', {
  // Will add IPC methods here later
  platform: process.platform
});

console.log('Preload script loaded');