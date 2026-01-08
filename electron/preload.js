const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods to renderer process
contextBridge.exposeInMainWorld('electron', {
  // Send a message and wait for response
  send: (command, data) => ipcRenderer.invoke('ws-send', command, data),

  // Send a message without waiting for response
  sendAsync: (command, data) => ipcRenderer.send('ws-send-async', command, data),
  
  onMessage: (callback) => { 
    ipcRenderer.on('ws-message', (event, message) => callback(message));
  },

  on: (type, callback) => { 
    ipcRenderer.on('ws-message', (event, message) => { 
      if (message.type === type) {
        callback(message.payload);
      }
    })
  }
})

console.log('✓ Preload script loaded - IPC bridge ready');