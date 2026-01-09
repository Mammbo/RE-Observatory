import { useEffect, useState } from 'react';
import { useAnalysis } from './hooks/useAnalysis';

function App() {
  const {
    isConnected,
    isLoading,
    error,
    analysisData,
    analyzeBinary,
    getFunctions,
    getProgramInfo,
    decompileFunction
  } = useAnalysis();

  const [binaryPath, setBinaryPath] = useState(null);
  const [selectedFunction, setSelectedFunction] = useState('');

  // Log state changes to console for testing
  useEffect(() => {
    console.log('Connection status:', isConnected);
  }, [isConnected]);

  useEffect(() => {
    console.log('Loading status:', isLoading);
  }, [isLoading]);

  useEffect(() => {
    console.log('Error:', error);
  }, [error]);

  useEffect(() => {
    console.log('Analysis data:', analysisData);
  }, [analysisData]);

  const handleSelectBinary = async () => {
    console.log('Opening file dialog...');
    const path = await window.electron.selectBinary();
    if (path) {
      setBinaryPath(path);
      console.log('Selected binary:', path);
    }
  };

  const handleAnalyzeBinary = async () => {
    if (!binaryPath) {
      console.log('No binary selected');
      return;
    }
    console.log('Analyzing binary:', binaryPath);
    await analyzeBinary(binaryPath);
  };

  const handleGetProgramInfo = async () => {
    console.log('Getting program info...');
    await getProgramInfo();
  };

  const handleGetFunctions = async () => {
    console.log('Getting functions...');
    await getFunctions();
  };

  const handleDecompileFunction = async () => {
    if (!selectedFunction) {
      console.log('No function address entered');
      return;
    }
    console.log('Decompiling function at:', selectedFunction);
    await decompileFunction(selectedFunction);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <h1 className="text-4xl font-bold mb-4">RE Observatory</h1>
      <p className="text-gray-400 mb-4">Binary analysis workspace - Hook Test</p>

      <div className="space-y-4">
        {/* Connection Status */}
        <div className={`p-4 rounded ${isConnected ? 'bg-green-800' : 'bg-red-800'}`}>
          {isConnected ? '✓ Connected to backend' : '✗ Disconnected from backend'}
        </div>

        {/* Loading Status */}
        {isLoading && (
          <div className="p-4 bg-yellow-800 rounded animate-pulse">
            Loading...
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="p-4 bg-red-900 rounded">
            Error: {error}
          </div>
        )}

        {/* Binary Selection */}
        <div className="p-4 bg-gray-800 rounded space-y-2">
          <h3 className="font-bold">1. Load Binary</h3>
          <div className="flex gap-2 items-center">
            <button
              onClick={handleSelectBinary}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded"
            >
              Select Binary
            </button>
            <button
              onClick={handleAnalyzeBinary}
              disabled={!binaryPath}
              className={`px-4 py-2 rounded ${binaryPath ? 'bg-green-600 hover:bg-green-700' : 'bg-gray-600 cursor-not-allowed'}`}
            >
              Analyze Binary
            </button>
          </div>
          {binaryPath && (
            <p className="text-sm text-gray-400">Selected: {binaryPath}</p>
          )}
        </div>

        {/* Query Buttons */}
        <div className="p-4 bg-gray-800 rounded space-y-2">
          <h3 className="font-bold">2. Query Analysis</h3>
          <div className="flex gap-2 flex-wrap">
            <button
              onClick={handleGetProgramInfo}
              className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded"
            >
              Get Program Info
            </button>
            <button
              onClick={handleGetFunctions}
              className="px-4 py-2 bg-teal-600 hover:bg-teal-700 rounded"
            >
              Get Functions
            </button>
          </div>
        </div>

        {/* Decompile Function */}
        <div className="p-4 bg-gray-800 rounded space-y-2">
          <h3 className="font-bold">3. Decompile Function</h3>
          <div className="flex gap-2 items-center">
            <input
              type="text"
              placeholder="Function address (e.g., 0x401000)"
              value={selectedFunction}
              onChange={(e) => setSelectedFunction(e.target.value)}
              className="px-3 py-2 bg-gray-700 rounded text-white flex-1"
            />
            <button
              onClick={handleDecompileFunction}
              disabled={!selectedFunction}
              className={`px-4 py-2 rounded ${selectedFunction ? 'bg-orange-600 hover:bg-orange-700' : 'bg-gray-600 cursor-not-allowed'}`}
            >
              Decompile
            </button>
          </div>
        </div>

        {/* Analysis Data Display */}
        {analysisData && (
          <div className="p-4 bg-gray-800 rounded">
            <h3 className="font-bold mb-2">Analysis Data:</h3>
            <pre className="text-sm overflow-auto max-h-96 bg-gray-900 p-2 rounded">
              {JSON.stringify(analysisData, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;