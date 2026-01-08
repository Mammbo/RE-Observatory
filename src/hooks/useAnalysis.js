import { useState, useEffect, useCallback } from 'react';

export function useAnalysis () { 
    const [isConnected, setIsConnected] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] =  useState(null);

    //Listen for connection status 
    useEffect(() => {
        const handleDisconnected = () => setIsConnected(false);
        const handleConnected = () => setIsConnected(true)

        window.electron.on('connected', handleConnected);
        window.electron.on('disconnected', handleDisconnected);
        return () => { 
            window.electron.off('connected', handleConnected);
            window.electron.off('disconnected', handleDisconnected);
        }
    }, []);

    const analayzeBinary = useCallback(async (binaryPath) => { 
        setIsLoading(true);
        setError(null);

        try { 
            const result = await window.elecotron.send('analyze_bianry', { 
                binary_path: binaryPath
            });
            return result
        } catch (err) {
            setError(err.message)
        } finally { 
            setIsLoading(false)
        }
    }, []);

    //get functions 
    const getFunctions = useCallback(async () => { 
        try { 
            await window.electron.send('get_functions', {});
        } catch (err) {
            setError(err.message)
        }
    }, []);

    // get program info
    const getInfo = useCallback(async () => { 
        try {

        } catch (err) {

        }
        await window.electron.send('get_program_info', {});
    }, []);

    //decompile functions
    const decompileFunctions= useCallback(async () => {
        return window.electron.send('decompile_function', {})
    }, []);

    return { 
        isConnected,
        isLoading,
        error, 
        analayzeBinary,
        getFunctions,
        decompileFunctions,
        getInfo
    }
}