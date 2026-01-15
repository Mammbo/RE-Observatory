import { LuBinary } from "react-icons/lu";
import { RiSignalTowerFill } from "react-icons/ri";
import { TbBinaryTree } from "react-icons/tb";
import { TbAnalyze } from "react-icons/tb";
import { IoIosDownload } from "react-icons/io";
import useSideBarStore from "../../store/sideBarStore";
import ExpandedPanel from "./ExpandedPanel";
import BinaryOverview from "./panels/BinaryInfoPanel";
import SignalsOverview from "./panels/SignalsPanel"
import StatusOverviw from "./panels/AnalysisControlPanel"

const SideBar = () => { 
    // zustand store
    const {activePanel, isResizing, panelWidth, minPanelWidth, maxPanelWidth, setPanelWidth, setIsResizing, togglePanel } = useSideBarStore();
        

    //handle click to download info into json file  IMPLEMENT THIS LATER
    const handleClick = () => { 
    
    };

    return (
    <div className="fixed top-0 left-0 h-screen w-16 m-0 flex flex-col items-center py-6 gap-y-3 bg-secondary text-text-primary text-shadow-lg border-r-text-primary border-r-2">
        <SideBarButton icon={<LuBinary size="32"/>} text={"Binary Overview"} onClick={() => togglePanel('binary')} isActive={activePanel === "binary"}/>
        <SideBarButton icon={<RiSignalTowerFill size="32"/>} text={"Triage Signals"} onClick={() => togglePanel('signals')} isActive={activePanel === "signals"}/>
        <SideBarButton icon={<TbBinaryTree size="32"/>} text={"Graph Toggles"}/>

        <SideBarButton icon={<TbAnalyze size="32"/>} text={"Analysis Status"} onClick={() => togglePanel('status')}/>
        <SideBarButton icon={<IoIosDownload size="32"/>} text={"Download Binary inforamation"} onClick={handleClick}/>
        
        <ExpandedPanel activePanel={activePanel} width={panelWidth}>
            {activePanel === 'binary' && <BinaryOverview />}
            {activePanel === 'signals' && <SignalsOverview />}
            {activePanel === 'status' && <StatusOverviw />}
        </ExpandedPanel>

    </div>);
};


const SideBarButton =({ icon, text, onClick, isActive}) => (
    <button onClick={onClick} className={`sidebar-icon group ${isActive ? 'sidebar-icon-selected' : ''}`}>
        { icon }

        <span className="sidebar-tooltip group-hover:scale-100">
            {text}
        </span>


    </button>
);

export default SideBar;