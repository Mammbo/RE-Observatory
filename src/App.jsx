import { useEffect, useState } from 'react';
import { useAnalysis } from './hooks/useAnalysis';
import SideBar from './components/Sidebar/SideBar'
import useSideBarStore from './store/sideBarStore';
import useCFGNodeStore from './store/cfgNodeStore';
import useAnalysisStore from './store/analysisStore';
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

  const {activePanel, panelWidth, isResizing: isSidebarResizing} = useSideBarStore();
  const { activePanel: nodePanel, panelWidth: nodePanelWidth, isResizing } = useCFGNodeStore();
  const { setAnalysisData: setStoreAnalysisData, setIsLoading: setStoreLoading } = useAnalysisStore();

  // Sync analysis data to store for use by other components
  useEffect(() => {
    console.log('Analysis data:', analysisData);
    setStoreAnalysisData(analysisData);
  }, [analysisData, setStoreAnalysisData]);

  useEffect(() => {
    setStoreLoading(isLoading);
  }, [isLoading, setStoreLoading]);

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
                  className={`flex h-screen ${!isResizing && !isSidebarResizing ? 'transition-[margin] duration-300 ease-in-out' : ''}`}
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
