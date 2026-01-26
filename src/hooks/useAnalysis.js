import { useState, useEffect, useCallback } from 'react';

export function useAnalysis() {
    const [isConnected, setIsConnected] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const [analysisData, setAnalysisData] = useState(null);
    const [messages, setMessages] = useState([]);

    // Listen for connection status
    useEffect(() => {
        const handleConnectionStatus = (status) => {
            setIsConnected(status.connected);
        };

        window.electron.onConnectionStatus(handleConnectionStatus);

        // Cleanup on unmount
        return () => {
            window.electron.removeAllListeners('ws-status');
        };
    }, []);

    // Listen for messages from Python backend
    useEffect(() => {
        const handleMessage = (message) => {
            setMessages(prev => [...prev.slice(-199), message]); // keep last 200
            switch (message.type) {
                case 'analysis_complete':
                    setAnalysisData(prev => ({
                        ...prev,
                        name: message.payload?.name,
                        programInfo: message.payload?.info ?? prev?.programInfo
                    }));
                    setIsLoading(false);
                    // Auto-request details once analysis finishes
                    window.electron.sendAsync('get_functions', {});
                    window.electron.sendAsync('get_call_graph', {});
                    if (!message.payload?.info) {
                        window.electron.sendAsync('get_program_info', {});
                    }
                    break;
                case 'functions':
                    setAnalysisData(prev => {
                        const next = {
                        ...prev,
                        functions: message.payload.functions
                        };
                        // If we have at least one function, auto-request decompile + CFG for the first 
                        // do this for each function and store it
                        const first = message.payload.functions?.[0];
                        if (first?.address) {
                            window.electron.sendAsync('decompile_function', { address: first.address });
                            window.electron.sendAsync('get_cfg', { address: first.address });
                        }
                        return next;
                    });
                    break;
                case 'decompiled':
                    setAnalysisData(prev => ({
                        ...prev,
                        decompiled: message.payload
                    }));
                    break;
                case 'program_info':
                    setAnalysisData(prev => ({
                        ...prev,
                        programInfo: message.payload
                    }));
                    break;
                case 'call_graph':
                    setAnalysisData(prev => ({
                        ...prev,
                        callGraph: message.payload
                    }));
                    break;
                case 'cfg':
                    setAnalysisData(prev => ({
                        ...prev,
                        cfg: message.payload
                    }));
                    break;
                case 'analysis_started':
                case 'analysis_parsed':
                case 'analysis_loading':
                case 'analysis_loaded':
                    setAnalysisData(prev => ({
                        ...prev,
                        status: message.type,
                        statusPayload: message.payload
                    }));
                    break;
                case 'error':
                    setError(message.payload.message);
                    setIsLoading(false);
                    break;
                default:
                    console.log('Unhandled message type:', message.type);
            }
        };

        window.electron.onMessage(handleMessage);

        // Cleanup on unmount
        return () => {
            window.electron.removeAllListeners('ws-message');
        };
    }, []);

    // Analyze a binary file
    const analyzeBinary = useCallback(async (binaryPath) => {
        setIsLoading(true);
        setError(null);

        try {
            const result = await window.electron.send('analyze_binary', {
                binary_path: binaryPath
            });
            return result;
        } catch (err) {
            setError(err.message);
            throw err;
        }
    }, []);

    // Get functions list
    const getFunctions = useCallback(async () => {
        try {
            return await window.electron.send('get_functions', {});
        } catch (err) {
            setError(err.message);
        }
    }, []);

    // Get program info
    const getProgramInfo = useCallback(async () => {
        try {
            return await window.electron.send('get_program_info', {});
        } catch (err) {
            setError(err.message);
        }
    }, []);

    // Decompile a function at address
    const decompileFunction = useCallback(async (address) => {
        try {
            return await window.electron.send('decompile_function', { address });
        } catch (err) {
            setError(err.message);
        }
    }, []);

    const getCallGraph = useCallback(async () => { 
        try { 
            return await window.electron.send('get_call_graph', {})
        } catch (err) { 
            setError(err.message)
        }
    }, []);

    const getCFG = useCallback(async (address) => { 
        try { 
            return await window.electron.send("get_cfg", {address})
        } catch (err) { 
            setError(err.message)
        }
    }, []);

    // Clear error
    const clearError = useCallback(() => {
        setError(null);
    }, []);

    return {
        // State
        isConnected,
        isLoading,
        error,
        analysisData,
        messages,

        // Actions
        analyzeBinary,
        getProgramInfo,
        getFunctions,
        decompileFunction,
        getCFG,
        getCallGraph,
        clearError
    };
}
