import WebSocket from 'ws';
import { EventEmitter } from 'events';

class AnalysisClient extends EventEmitter {

    constructor() {
        super()
        this.ws = null; 
        this.isConnected = false;
        this.pendingRequests = new Map(); 
    }
    connect() { 
        return new Promise((resolve, reject) => { 
            this.ws = new WebSocket('ws://127.0.0.1:9999');

            this.ws.onopen = () => { 
                console.log("connected to analysis backend");
                this.isConnected = true; 
                this.emit('connected');
                resolve();
            };
            
            this.ws.onmessage = (event) => { 
                const msg = JSON.parse(event.data);
                console.log("Backend:", msg);

                this.emit('message', msg);

                // If this message has a requestId, resolve the pending promise
              if (msg.requestId && this.pendingRequests.has(msg.requestId)) {
                  const { resolve } = this.pendingRequests.get(msg.requestId);
                  this.pendingRequests.delete(msg.requestId);
                  resolve(msg);
                }
            };

            this.ws.onerror = (err) => { 
                console.error("Websocket Error: ", err);
                this.emit('error', err);
                reject(err)
            };

            this.ws.onclose = () => { 
                console.log("Backend Disconnected");
                this.isConnected = false;
                this.emit('disconnected');
            }


        })
            }

    send(command, data) {
        if (!this.isConnected || !this.ws) {
            console.error("Cannot send: no connection");
            return false;
        }
        this.ws.send(JSON.stringify({command, data}));
        return true;
    }
    close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}
export default AnalysisClient