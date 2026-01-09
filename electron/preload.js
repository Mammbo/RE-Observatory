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

  // Listen for connection status changes
  onConnectionStatus: (callback) => {
    ipcRenderer.on('ws-status', (event, status) => callback(status));
  },

  // Remove listeners (for cleanup)
  removeAllListeners: (channel) => {
    ipcRenderer.removeAllListeners(channel);
  }
})

console.log('✓ Preload script loaded - IPC bridge ready');