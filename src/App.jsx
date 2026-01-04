import React, { useState } from 'react';

function App() {
  const [binaryPath, setBinaryPath] = useState(null);
  const [platform, setPlatform] = useState('unknown');

  const handleSelectBinary = async () => {
    const path = await window.electron.selectBinary();
    if (path) {
      setBinaryPath(path);
      console.log('Selected binary:', path);
      
      // Start analysis
      const result = await window.electron.startAnalysis(path);
      console.log('Analysis result:', result);
    }
  };

  const checkPlatform = async () => {
    const plat = await window.electron.getPlatform();
    setPlatform(plat);
  };

  React.useEffect(() => {
    checkPlatform();
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <h1 className="text-4xl font-bold mb-4">RE Observatory</h1>
      <p className="text-gray-400 mb-4">Binary analysis workspace</p>
      
      <div className="space-y-4">
        <div className="p-4 bg-green-800 rounded">
          ✓ React is working!
        </div>
        
        <div className="p-4 bg-blue-800 rounded">
          ✓ Platform: {platform}
        </div>
        
        <button 
          onClick={handleSelectBinary}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded"
        >
          Load Binary
        </button>
        
        {binaryPath && (
          <div className="p-4 bg-gray-800 rounded">
            Selected: {binaryPath}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;