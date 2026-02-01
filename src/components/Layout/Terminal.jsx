import { Terminal } from "xterm";
import { FitAddon } from "@xterm/addon-fit";
import "xterm/css/xterm.css";
import { useEffect, useRef } from "react";
const TerminalComponent = () => { 
    const terminalRef = useRef(null);

    useEffect(() => {
        // customize settingsTerm
        const term = new Terminal({
            cursorBlink: true,
            fontSize: 13,
            fontFamily: '"Fira Code", "Menlo for Powerline", Menlo, Consolas, "Liberation Mono", Courier, monospace',
            theme: {
                foreground: '#d2d2d2',
                background: '#1e1e1e',
                cursor: '#adadad',
                black: '#000000',
                red: '#d81e00',
                green: '#5ea702',
                yellow: '#cfae00',
                blue: '#427ab3',
                magenta: '#89658e',
                cyan: '#00a7aa',
                white: '#dbded8',
                brightBlack: '#686a66',
                brightRed: '#f54235',
            }
        });
        let fitAddon = new FitAddon(); 
        term.loadAddon(fitAddon);
    
        const raf = requestAnimationFrame(() => { 
            term.open(terminalRef.current);   
            fitAddon.fit()
        
    
            term.onData(e => {
                window.electron.terminalWrite(e);        
        });
        window.electron.onTerminalData(data => {
            term.write(data);
        });
    });

        return () => {
            cancelAnimationFrame(raf);
            window.electron.removeAllListeners('terminal.incData');
            term.dispose();
        };
    }, []);    
    return (
    
        <div ref={terminalRef} className="w-full h-full border-2 border-active shadow-2xl"/>  
    );
}

export default TerminalComponent;