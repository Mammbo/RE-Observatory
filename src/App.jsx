import { useEffect, useState } from 'react';
import { useAnalysis } from './hooks/useAnalysis';
import SideBar from './components/Sidebar/SideBar'
import useSideBarStore from './store/sideBarStore';
import CanvasView from './components/Canvas/GraphDisplay';

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

  const {activePanel, panelWidth} = useSideBarStore();

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
    <div className="flex h-screen">
      <SideBar />
      {/* Main content area - offset by sidebar width */}
      <main 
        className="flex-1 h-screen"
        style={{ marginLeft: `${64 + (activePanel ? panelWidth : 0)}px` }}
      >
        <CanvasView />
      </main>
    </div>
  );
};

export default App;