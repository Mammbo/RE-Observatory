import WebSocket from 'ws';


class AnalysisClient {

    constructor() {
        this.ws = null; 
        this.isConnected = false; 
    }
    connect() { 
        return new Promise((resolve, reject) => { 
            this.ws = new WebSocket('ws://127.0.0.1:9999')

            this.ws.onopen = () => { 
                console.log("connected to analysis backend");
                this.isConnected = true; 
                resolve();
            };
            
            this.ws.onmessage = (event) => { 
                const msg = JSON.parse(event.data);
                console.log("Backend:", msg);
            };

            this.ws.onerror = (err) => { 
                console.error("Websocket Error: ", err);
                reject(err)
            };

            this.ws.onclose = () => { 
                console.log("Backend Disconnected");
                this.isConnected = false;
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