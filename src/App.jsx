import { useEffect, useState } from 'react';
import { useAnalysis } from './hooks/useAnalysis';
import SideBar from './components/Sidebar/SideBar'
import useSideBarStore from './store/sideBarStore';
import useCFGNodeStore from './store/cfgNodeStore';
import CanvasView from './components/Canvas/GraphDisplay';
import NodePanel from './components/Canvas/nodePanels';

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
  const { activePanel: nodePanel, panelWidth: nodePanelWidth } = useCFGNodeStore();

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
  const { registerPanel } = useCFGNodeStore();

  useEffect(() => {
      // Register test data - address must match data.src in GraphDisplay.jsx
      registerPanel("0x4010000", {
          functionName: "main",
          cCode: "int main() { return 0; }"
      });
      registerPanel("0x4010014", { 
        functionName: "fgets",
        ccode: "lebron"
      })
  }, []);


  return (
    <div className="flex h-screen bg-primary">
      <SideBar />
      {/* Main content area - offset by sidebar width */}
      <main
        className="flex-1 h-screen transition-[margin] duration-300 ease-in-out"
        style={{
          marginLeft: `${64 + (activePanel ? panelWidth : 0)}px`,
          marginRight: `${nodePanel ? nodePanelWidth : 0}px`
        }}
      >
        <CanvasView />
      </main>
      <NodePanel />
    </div>
  );
};

export default App;