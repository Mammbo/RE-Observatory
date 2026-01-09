import { useState, useEffect, useCallback } from 'react';

export function useAnalysis() {
    const [isConnected, setIsConnected] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const [analysisData, setAnalysisData] = useState(null);

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
            switch (message.type) {
                case 'analysis_complete':
                    setAnalysisData(message.payload);
                    setIsLoading(false);
                    break;
                case 'functions':
                    setAnalysisData(prev => ({
                        ...prev,
                        functions: message.payload.functions
                    }));
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

        // Actions
        analyzeBinary,
        getFunctions,
        getProgramInfo,
        decompileFunction,
        clearError
    };
}