const WebSocket = require('ws');
const { EventEmitter } = require('events');

class AnalysisClient extends EventEmitter {
    constructor() {
        super();
        this.ws = null;
        this.isConnected = false;
    }

    connect() {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket('ws://127.0.0.1:9999');

            this.ws.onopen = () => {
                console.log("Connected to analysis backend");
                this.isConnected = true;
                this.emit('connected');
                resolve();
            };

            this.ws.onmessage = (event) => {
                const msg = JSON.parse(event.data);
                console.log("Backend:", msg);
                this.emit('message', msg);
            };

            this.ws.onerror = (err) => {
                console.error("WebSocket Error:", err);
                this.emit('error', err);
                reject(err);
            };

            this.ws.onclose = () => {
                console.log("Backend Disconnected");
                this.isConnected = false;
                this.emit('disconnected');
            };
        });
    }

    send(command, data) {
        if (!this.isConnected || !this.ws) {
            console.error("Cannot send: no connection");
            return false;
        }
        this.ws.send(JSON.stringify({ command, data }));
        return true;
    }

    close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

module.exports = new AnalysisClient();