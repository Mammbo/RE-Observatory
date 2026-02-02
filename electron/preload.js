const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods to renderer process
contextBridge.exposeInMainWorld('electron', {
  // File selection dialog
  selectBinary: () => ipcRenderer.invoke('select-binary'),

  // Send a message and wait for response
  send: (command, data) => ipcRenderer.invoke('ws-send', command, data),

  // Send a message without waiting for response
  sendAsync: (command, data) => ipcRenderer.send('ws-send-async', command, data),

  // Listen for all WebSocket messages
  onMessage: (callback) => {
    ipcRenderer.on('ws-message', (event, message) => callback(message));
  },

  // Listen for specific message types
  on: (type, callback) => {
    ipcRenderer.on('ws-message', (event, message) => {
      if (message.type === type) {
        callback(message.payload);
      }
    });
  },

  // Terminal: send user keystrokes to pty, listen for pty output
  terminalWrite: (data) => ipcRenderer.send('terminal.toterm', data),
  onTerminalData: (callback) => {
    ipcRenderer.on('terminal.incData', (event, data) => callback(data));
  },

  // Listen for connection status changes
  onConnectionStatus: (callback) => {
    ipcRenderer.on('ws-status', (event, status) => callback(status));
  },

  // Save file dialog
  saveFile: (defaultName, content) => ipcRenderer.invoke('save-file', defaultName, content),

  // Remove listeners (for cleanup)
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
})

console.log('✓ Preload script loaded - IPC bridge ready');