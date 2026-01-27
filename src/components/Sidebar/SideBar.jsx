import { LuBinary } from "react-icons/lu";
import { RiSignalTowerFill } from "react-icons/ri";
import { MdFileDownload } from "react-icons/md";
import { MdUpload } from "react-icons/md";
import useSideBarStore from "../../store/sideBarStore";
import ExpandedPanel from "./ExpandedPanel";
import BinaryOverview from "./panels/BinaryInfoPanel";
import TriageOverview from "./panels/TriagePanel"

const SideBar = () => { 
    // zustand store
    const {activePanel, isResizing, panelWidth, minPanelWidth, maxPanelWidth, setPanelWidth, setIsResizing, togglePanel } = useSideBarStore();
        

    //handle click to download info into json file  IMPLEMENT THIS LATER basically a react hook to query to database
    const handleClick = () => { 
    
    };

    return (
    <div className="fixed top-0 left-0 h-screen w-16 m-0 flex flex-col items-center py-6 gap-y-3 bg-secondary text-text-primary text-shadow-lg border-r-2 border-r-border-default z-50">
        <SideBarButton icon={<LuBinary size="32"/>} text={"Binary Overview"} onClick={() => togglePanel('binary')} isActive={activePanel === "binary"}/>
        <SideBarButton icon={<RiSignalTowerFill size="32"/>} text={"Triage Signals"} onClick={() => togglePanel('signals')} isActive={activePanel === "signals"}/>
        <SideBarButton icon={<MdFileDownload size="32"/>} text={"Download Binary inforamation"} onClick={handleClick}/>
        <SideBarButton icon={<MdUpload size="32"/>} text={"Open/Select a Binary"} onClick={handleClick}/>
        
        <ExpandedPanel className="flex flex-col justify-items-start" activePanel={activePanel} width={panelWidth}>
            {activePanel === 'binary' && <BinaryOverview />}
            {activePanel === 'signals' && <TriageOverview />}
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