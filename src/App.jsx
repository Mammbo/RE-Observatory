import { useEffect, useState } from 'react';
import { useAnalysis } from './hooks/useAnalysis';
import SideBar from './components/Sidebar/SideBar'
import useSideBarStore from './store/sideBarStore';
import useCFGNodeStore from './store/cfgNodeStore';
import CanvasView from './components/Canvas/GraphDisplay';
import NodePanel from './components/Canvas/nodePanels';
import UploadBinaryPage from './components/Layout/UploadBinaryPage';
function App() {
  const {
    analysisData,
    analyzeBinary,
    messages,
    isConnected,
    isLoading,
    error
  } = useAnalysis();

  const [binaryPath, setBinaryPath] = useState(null);

  const {activePanel, panelWidth} = useSideBarStore();
  const { activePanel: nodePanel, panelWidth: nodePanelWidth } = useCFGNodeStore();

// analyze binary
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

  // auto-run analysis after a file is chosen
  useEffect(() => {
    if (binaryPath) {
      handleAnalyzeBinary();
    }
  }, [binaryPath]);


  // REGISTER NODE PANEL
  const { registerPanel } = useCFGNodeStore();

  // register panel will be for the length of the call graph.
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
      <> 
        <div className="relative flex-1 h-screen overflow-hidden">
              {/* Upload Page */}
              <div
                className={`
                  absolute inset-0 z-10 transition-all duration-500 ease-out
                  ${!binaryPath
                    ? 'opacity-100 translate-y-0 scale-100 blur-0 pointer-events-auto'
                    : 'opacity-0 -translate-y-4 scale-95 blur-sm pointer-events-none'}
                `}
              >
                <UploadBinaryPage onSelectBinary={handleSelectBinary} />
              </div>

              {/* Main App */}
              <div
                className={`
                  absolute inset-0 transition-all duration-500 ease-out
                  ${binaryPath
                    ? 'opacity-100 translate-y-0 scale-100 blur-0 z-10 pointer-events-auto'
                    : 'opacity-0 translate-y-4 sclae-95 blur-sm z-0 pointer-events-none'}
                `}
              >
                <main
                  className="flex h-screen transition-[margin] duration-300 ease-in-out"
                  style={{
                    marginLeft: `${64 + (activePanel ? panelWidth : 0)}px`,
                    marginRight: `${nodePanel ? nodePanelWidth : 0}px`,
                  }}
                >
                  <CanvasView />
                </main>

                <NodePanel />
              </div>
            </div>
          </>
    </div>
  );
};

export default App;
/*
 <div className="p-4 text-sm text-gray-200 space-y-2">
                <div>Status: {isConnected ? 'connected' : 'disconnected'} {isLoading && '(analyzing...)'}</div>
                <div>Binary: {binaryPath}</div>
                {error && <div className="text-red-400">Error: {error}</div>}
                <div className="bg-gray-900/60 rounded p-2 h-40 overflow-auto">
                  <div className="font-semibold mb-1">Backend messages (latest first)</div>
                  {[...messages].reverse().slice(0,20).map((m, i) => (
                    <div key={i} className="text-xs text-gray-300 whitespace-pre-wrap">
                      {m.type}: {JSON.stringify(m.payload).slice(0, 160)}
                    </div>
                  ))}
                </div>
              </div>
*/