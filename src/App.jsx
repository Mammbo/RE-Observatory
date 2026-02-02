import { useEffect, useState } from 'react';
import { useAnalysis } from './hooks/useAnalysis';
import SideBar from './components/Sidebar/SideBar'
import useSideBarStore from './store/sideBarStore';
import useCFGNodeStore from './store/cfgNodeStore';
import useAnalysisStore from './store/analysisStore';
import CanvasView from './components/Canvas/GraphDisplay';
import NodePanel from './components/Canvas/nodePanels';
import UploadBinaryPage from './components/Layout/UploadBinaryPage';
import ToggleMainViews from './components/Layout/ToggleMainViews';
import TerminalComponent from './components/Layout/terminal';
import BinarySelectModal from './components/Sidebar/BinarySelectModal';
import { useToast } from './components/Layout/Toast';
import useGraphStore from './store/graphStore';
import SaveGraphButton from './components/Layout/SaveGraphButton';

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
  const [activeView, setActiveView] = useState('canvas');
  const [showBinaryModal, setShowBinaryModal] = useState(false);

  const {activePanel, panelWidth, isResizing: isSidebarResizing} = useSideBarStore();
  const { activePanel: nodePanel, panelWidth: nodePanelWidth, isResizing } = useCFGNodeStore();
  const { setAnalysisData: setStoreAnalysisData, setIsLoading: setStoreLoading, setDbReady, setBinaryId } = useAnalysisStore();
  const { showToast } = useToast();
  const { addUserNode, addUserEdge, clearUserGraph } = useGraphStore();

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
      setDbReady(false);
      setBinaryId(null);
      clearUserGraph();
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

  // auto-run analysis after a file is chosen (skip if loaded from DB)
  useEffect(() => {
    if (binaryPath && binaryPath !== 'loaded-from-db') {
      handleAnalyzeBinary();
    }
  }, [binaryPath]);

  // send query to save all data to the backend (skip if loaded from DB)
  useEffect(() => {
    if(!analysisData) return;
    if(binaryPath === 'loaded-from-db') return;
    const { functions, decompiled, cfgs, callGraph, programInfo } = analysisData;
    if (!functions || !callGraph || !programInfo) return;

    // find total length of functions
    const total = functions.length;
    const decompiledCount = decompiled ? Object.keys(decompiled).length : 0;
    const cfgCount = cfgs ? Object.keys(cfgs).length : 0;

    console.log(`Store progress: decompiled=${decompiledCount}/${total}, cfgs=${cfgCount}/${total}`);

    // check if decompiled and cfg count = funcs
    if ( decompiledCount >= total && cfgCount >= total ) {
      console.log('All data ready, sending to backend for DB save');
      window.electron.sendAsync('analysis_store_ready', analysisData);
    }
  }, [analysisData])

  // Listen for backend responses to unlock the UI and show notifications
  useEffect(() => {
    window.electron.onMessage((message) => {
      if (message.type === 'analysis_saved') {
        console.log('DB store complete, binary_id:', message.payload.binary_id);
        setBinaryId(message.payload.binary_id);
        setDbReady(true);
        showToast('Analysis saved to database', 'success');
      } else if (message.type === 'binary_loaded') {
        setBinaryPath('loaded-from-db');
        setBinaryId(message.payload.binary_id);
        setDbReady(true);
        // Clear old user nodes/edges before populating from DB
        clearUserGraph();
        // Populate graph store with saved user nodes/edges
        if (message.payload.userNodes) {
          message.payload.userNodes.forEach((n) => addUserNode(n));
        }
        if (message.payload.userEdges) {
          message.payload.userEdges.forEach((e) => addUserEdge(e));
        }
        showToast('Binary loaded from database', 'success');
      } else if (message.type === 'graph_saved') {
        showToast('Graph saved', 'success');
      } else if (message.type === 'error') {
        console.error('Backend error:', message.payload.message);
        showToast(message.payload.message, 'error');
        setDbReady(true);
      }
    });
  }, [])


  return (
    <div className="flex h-screen bg-primary">
      <SideBar onOpenBinaryModal={() => setShowBinaryModal(true)} />
      {/* Main content area - offset by sidebar width */}
      <> 
        <div className={`relative flex-1 h-screen overflow-hidden`}>
              {/* Upload Page */}
              <div
                className={`
                  absolute inset-0 z-10 transition-all duration-500 ease-out
                  ${!binaryPath
                    ? 'opacity-100 translate-y-0 scale-100 blur-0 pointer-events-auto'
                    : 'opacity-0 -translate-y-4 scale-95 blur-sm pointer-events-none'}
                `}
              >
                <UploadBinaryPage onSelectBinary={handleSelectBinary} onSelectPreviousBinary={() => setShowBinaryModal(true)} />
              </div>

              {/* Main App - Title + Toggle */}
              <div
                className={`fixed top-4 left-1/2 -translate-x-1/2 z-50 flex flex-col items-center gap-2 transition-all duration-500 ease-out
                  ${binaryPath
                    ? 'opacity-100 translate-y-0 pointer-events-auto'
                    : 'opacity-0 -translate-y-4 pointer-events-none'}`}
              >
                <h1 className="text-2xl font-bold tracking-wide text-accent drop-shadow-lg pointer-events-none">
                    Reverse Engineering Observatory
                </h1>
                <ToggleMainViews activeView={activeView} onToggle={setActiveView} />
              </div>


              {/* Canvas View */}
              <div
                className={`
                  absolute inset-0 transition-all duration-500 ease-out
                  ${binaryPath && activeView === 'canvas'
                    ? 'opacity-100 translate-y-0 scale-100 blur-0 z-10 pointer-events-auto'
                    : 'opacity-0 translate-y-4 scale-95 blur-sm z-0 pointer-events-none'}
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

                <div
                  className={`absolute inset-0 bg-primary transition-all duration-500 ease-out
                    ${activeView === 'terminal' && binaryPath
                      ? 'opacity-100 translate-y-0 scale-100 blur-0 z-10 pointer-events-auto'
                      : 'opacity-0 translate-y-4 scale-95 blur-sm z-0 pointer-events-none'}`
                    }
                  style={{ WebkitAppRegion: 'no-drag' }}
                >
                  <div
                    className={`h-full pt-24 ${!isSidebarResizing ? 'transition-[margin] duration-300 ease-in-out' : ''}`}
                    style={{
                      marginLeft: `${64 + (activePanel ? panelWidth : 0)}px`,
                    }}
                  >
                    <TerminalComponent />
                  </div>
                </div>
            </div>
          </>

      {showBinaryModal && (
        <BinarySelectModal
          onClose={() => setShowBinaryModal(false)}
          onUploadNew={handleSelectBinary}
        />
      )}
    </div>
  );
};

export default App;
